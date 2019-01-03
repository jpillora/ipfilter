package ipfilter

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	maxminddb "github.com/oschwald/maxminddb-golang"
	"github.com/tomasen/realip"
)

var (
	DBPublicURL = "http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz"
	DBTempPath  = filepath.Join(os.TempDir(), "ipfilter-GeoLite2-Country.mmdb.gz")
)

//Options for IPFilter. Allowed takes precendence over Blocked.
//IPs can be IPv4 or IPv6 and can optionally contain subnet
//masks (/24). Note however, determining if a given IP is
//included in a subnet requires a linear scan so is less performant
//than looking up single IPs.
//
//This could be improved with some algorithmic magic.
type Options struct {
	//explicity allowed IPs
	AllowedIPs []string
	//explicity blocked IPs
	BlockedIPs []string
	//explicity allowed country ISO codes
	AllowedCountries []string
	//explicity blocked country ISO codes
	BlockedCountries []string
	//in-memory GeoLite2-Country.mmdb file,
	//if not provided falls back to IPDBPath
	IPDB []byte
	//path to GeoLite2-Country.mmdb[.gz] file,
	//if not provided defaults to ipfilter.DBTempPath
	IPDBPath string
	//disable automatic fetch of GeoLite2-Country.mmdb file
	//by default, when ipfilter.IPDBPath is not found,
	//ipfilter.IPDBFetchURL will be retrieved and stored at
	//ipfilter.IPDBPath, then loaded into memory (~19MB)
	IPDBNoFetch bool
	//URL of GeoLite2-Country.mmdb[.gz] file,
	//if not provided defaults to ipfilter.DBPublicURL
	IPDBFetchURL string
	//block by default (defaults to allow)
	BlockByDefault bool
	// TrustProxy enable check request IP from proxy
	TrustProxy bool

	Logger interface {
		Printf(format string, v ...interface{})
	}
}

type IPFilter struct {
	opts Options
	//mut protects the below
	//rw since writes are rare
	mut            sync.RWMutex
	defaultAllowed bool
	db             *maxminddb.Reader
	ips            map[string]bool
	codes          map[string]bool
	subnets        []*subnet
}

type subnet struct {
	str     string
	ipnet   *net.IPNet
	allowed bool
}

//NewNoDB constructs IPFilter instance without downloading DB.
func NewNoDB(opts Options) *IPFilter {
	if opts.IPDBFetchURL == "" {
		opts.IPDBFetchURL = DBPublicURL
	}
	if opts.IPDBPath == "" {
		opts.IPDBPath = DBTempPath
	}
	if opts.Logger == nil {
		flags := log.LstdFlags
		opts.Logger = log.New(os.Stdout, "", flags)
	}
	f := &IPFilter{
		opts:           opts,
		ips:            map[string]bool{},
		codes:          map[string]bool{},
		defaultAllowed: !opts.BlockByDefault,
	}
	for _, ip := range opts.BlockedIPs {
		f.BlockIP(ip)
	}
	for _, ip := range opts.AllowedIPs {
		f.AllowIP(ip)
	}
	for _, code := range opts.BlockedCountries {
		f.BlockCountry(code)
	}
	for _, code := range opts.AllowedCountries {
		f.AllowCountry(code)
	}
	return f
}

//NewLazy performs database initialization in a goroutine.
//During this initialization, any DB (country code) lookups
//will be skipped. Errors will be logged instead of returned.
func NewLazy(opts Options) *IPFilter {
	f := NewNoDB(opts)
	go func() {
		if err := f.initDB(); err != nil {
			f.opts.Logger.Printf("[ipfilter] failed to intilise db: %s", err)
		}
	}()
	return f
}

//New blocks during database initialization and checks
//validity IP strings. returns an error on failure.
func New(opts Options) (*IPFilter, error) {
	f := NewNoDB(opts)
	if err := f.initDB(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *IPFilter) initDB() error {
	//in-memory
	if len(f.opts.IPDB) > 0 {
		return f.bytesDB(f.opts.IPDB)
	}
	//use local copy
	if fileinfo, err := os.Stat(f.opts.IPDBPath); err == nil {
		if fileinfo.Size() > 0 {
			file, err := os.Open(f.opts.IPDBPath)
			if err != nil {
				return err
			}
			defer file.Close()
			if err = f.readerDB(f.opts.IPDBFetchURL, file); err != nil {
				f.opts.Logger.Printf("[ipfilter] error reading db file %v", err)
				if errDel := os.Remove(f.opts.IPDBPath); errDel != nil {
					f.opts.Logger.Printf("[ipfilter] error removing bad file %v", f.opts.IPDBPath)
				}
			}
			return err
		}
		f.opts.Logger.Printf("[ipfilter] IP DB is 0 byte size")
	}
	//ensure fetch is allowed
	if f.opts.IPDBNoFetch {
		return errors.New("IP DB not found and fetch is disabled")
	}
	//fetch and cache missing file
	file, err := os.Create(f.opts.IPDBPath)
	if err != nil {
		return err
	}
	defer file.Close()
	f.opts.Logger.Printf("[ipfilter] downloading %s...", f.opts.IPDBFetchURL)
	resp, err := http.Get(f.opts.IPDBFetchURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	//store on disk as db loads
	r := io.TeeReader(resp.Body, file)
	err = f.readerDB(DBPublicURL, r)
	f.opts.Logger.Printf("[ipfilter] cached: %s", f.opts.IPDBPath)
	return err
}

func (f *IPFilter) readerDB(filename string, r io.Reader) error {
	if strings.HasSuffix(filename, ".gz") {
		g, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer g.Close()
		r = g
	}
	buff := bytes.Buffer{}
	if _, err := io.Copy(&buff, r); err != nil {
		return err
	}
	return f.bytesDB(buff.Bytes())
}

func (f *IPFilter) bytesDB(b []byte) error {
	db, err := maxminddb.FromBytes(b)
	if err != nil {
		return err
	}
	f.mut.Lock()
	f.db = db
	f.mut.Unlock()
	return nil
}

func (f *IPFilter) AllowIP(ip string) bool {
	return f.ToggleIP(ip, true)
}

func (f *IPFilter) BlockIP(ip string) bool {
	return f.ToggleIP(ip, false)
}

func (f *IPFilter) ToggleIP(str string, allowed bool) bool {
	//check if has subnet
	if ip, net, err := net.ParseCIDR(str); err == nil {
		// containing only one ip?
		if n, total := net.Mask.Size(); n == total {
			f.mut.Lock()
			f.ips[ip.String()] = allowed
			f.mut.Unlock()
			return true
		}
		//check for existing
		f.mut.Lock()
		found := false
		for _, subnet := range f.subnets {
			if subnet.str == str {
				found = true
				subnet.allowed = allowed
				break
			}
		}
		if !found {
			f.subnets = append(f.subnets, &subnet{
				str:     str,
				ipnet:   net,
				allowed: allowed,
			})
		}
		f.mut.Unlock()
		return true
	}
	//check if plain ip
	if ip := net.ParseIP(str); ip != nil {
		f.mut.Lock()
		f.ips[ip.String()] = allowed
		f.mut.Unlock()
		return true
	}
	return false
}

func (f *IPFilter) AllowCountry(code string) {
	f.ToggleCountry(code, true)
}

func (f *IPFilter) BlockCountry(code string) {
	f.ToggleCountry(code, false)
}

//ToggleCountry alters a specific country setting
func (f *IPFilter) ToggleCountry(code string, allowed bool) {

	f.mut.Lock()
	f.codes[code] = allowed
	f.mut.Unlock()
}

//ToggleDefault alters the default setting
func (f *IPFilter) ToggleDefault(allowed bool) {
	f.mut.Lock()
	f.defaultAllowed = allowed
	f.mut.Unlock()
}

//Allowed returns if a given IP can pass through the filter
func (f *IPFilter) Allowed(ipstr string) bool {
	return f.NetAllowed(net.ParseIP(ipstr))
}

//NetAllowed returns if a given net.IP can pass through the filter
func (f *IPFilter) NetAllowed(ip net.IP) bool {
	//invalid ip
	if ip == nil {
		return false
	}
	//read lock entire function
	//except for db access
	f.mut.RLock()
	defer f.mut.RUnlock()
	//check single ips
	allowed, ok := f.ips[ip.String()]
	if ok {
		return allowed
	}
	//scan subnets for any allow/block
	blocked := false
	for _, subnet := range f.subnets {
		if subnet.ipnet.Contains(ip) {
			if subnet.allowed {
				return true
			}
			blocked = true
		}
	}
	if blocked {
		return false
	}
	//check country codes
	f.mut.RUnlock()
	code := f.NetIPToCountry(ip)
	f.mut.RLock()
	if code != "" {
		if allowed, ok := f.codes[code]; ok {
			return allowed
		}
	}
	//use default setting
	return f.defaultAllowed
}

//Blocked returns if a given IP can NOT pass through the filter
func (f *IPFilter) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

//NetBlocked returns if a given net.IP can NOT pass through the filter
func (f *IPFilter) NetBlocked(ip net.IP) bool {
	return !f.NetAllowed(ip)
}

//Wrap the provided handler with simple IP blocking middleware
//using this IP filter and its configuration
func (f *IPFilter) Wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{IPFilter: f, next: next}
}

//IPToCountry returns the IP's ISO country code.
//Returns an empty string when cannot determine country.
func (f *IPFilter) IPToCountry(ipstr string) string {
	if ip := net.ParseIP(ipstr); ip != nil {
		return f.NetIPToCountry(ip)
	}
	return ""
}

//NetIPToCountry returns the net.IP's ISO country code.
//Returns an empty string when cannot determine country.
func (f *IPFilter) NetIPToCountry(ip net.IP) string {
	f.mut.RLock()
	db := f.db
	f.mut.RUnlock()
	return NetIPToCountry(db, ip)
}

//Wrap is equivalent to NewLazy(opts) then Wrap(next)
func Wrap(next http.Handler, opts Options) http.Handler {
	return NewLazy(opts).Wrap(next)
}

//IPToCountry is a simple IP-country code lookup.
//Returns an empty string when cannot determine country.
func IPToCountry(db *maxminddb.Reader, ipstr string) string {
	if ip := net.ParseIP(ipstr); ip != nil {
		return NetIPToCountry(db, ip)
	}
	return ""
}

//NetIPToCountry is a simple IP-country code lookup.
//Returns an empty string when cannot determine country.
func NetIPToCountry(db *maxminddb.Reader, ip net.IP) string {
	r := struct {
		//TODO(jpillora): lookup more fields and expose more options
		// IsAnonymous       bool `maxminddb:"is_anonymous"`
		// IsAnonymousVPN    bool `maxminddb:"is_anonymous_vpn"`
		// IsHostingProvider bool `maxminddb:"is_hosting_provider"`
		// IsPublicProxy     bool `maxminddb:"is_public_proxy"`
		// IsTorExitNode     bool `maxminddb:"is_tor_exit_node"`
		Country struct {
			Country string `maxminddb:"iso_code"`
			// Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
	}{}
	if db != nil {
		db.Lookup(ip, &r)
	}
	//DEBUG log.Printf("%s -> '%s'", ip, r.Country.Country)
	return r.Country.Country
}

type ipFilterMiddleware struct {
	*IPFilter
	next http.Handler
}

func (m *ipFilterMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var remoteIP string
	if m.opts.TrustProxy {
		remoteIP = realip.FromRequest(r)
	} else {
		remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	if !m.IPFilter.Allowed(remoteIP) {
		//show simple forbidden text
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}
