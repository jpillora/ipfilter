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
)

var (
	DBPublicURL = "http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz"
	DBTempPath  = filepath.Join(os.TempDir(), "ipfilter-GeoLite2-Country.mmdb.gz")
)

//Options for IPFilter.
//Allowed takes precendence over Blocked.
//IPs can be IPv4 or IPv6 and can optionally
//contain subnet masks (/24). Note however, determining if
//a given IP is included in a subnet requires a linear scan
//so is less performant than looking up single IPs.
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
	//if not provided falls back to automatically fetch
	IPDBPath string
	//disable automatic fetch of GeoLite2-Country.mmdb file
	//by default, it will be first look in os.TempDir, if missing
	//it will be fetched, cached on disk, then loaded into memory (~19MB)
	IPDBNoFetch bool
	//block by default (defaults to allow)
	BlockByDefault bool
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

//who uses the new builtin anyway?
func new(opts Options) *IPFilter {
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

//NewLazy performs database intilisation in a goroutine.
//During this intilisation, any DB (country code) lookups
//will be skipped. Errors will be logged instead of returned.
func NewLazy(opts Options) *IPFilter {
	f := new(opts)
	go func() {
		if err := f.initDB(); err != nil {
			log.Printf("[ipfilter] failed to intilise db: %s", err)
		}
	}()
	return f
}

//New blocks during database intilisation and checks
//validity IP strings. returns an error on failure.
func New(opts Options) (*IPFilter, error) {
	f := new(opts)
	if err := f.initDB(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *IPFilter) initDB() error {
	if len(f.opts.IPDB) > 0 {
		//in-memory
		return f.bytesDB(f.opts.IPDB)
	} else if f.opts.IPDBPath != "" {
		//local path
		file, err := os.Open(f.opts.IPDBPath)
		if err != nil {
			return err
		}
		defer file.Close()
		return f.readerDB(f.opts.IPDBPath, file)
	} else if !f.opts.IPDBNoFetch {
		//auto fetch
		if _, err := os.Stat(DBTempPath); os.IsNotExist(err) {
			//fetch and cache missing file
			file, err := os.Create(DBTempPath)
			if err != nil {
				return err
			}
			defer file.Close()
			log.Printf("[ipfilter] downloading %s...", DBPublicURL)
			resp, err := http.Get(DBPublicURL)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			//store on disk as db loads
			r := io.TeeReader(resp.Body, file)
			err = f.readerDB(DBPublicURL, r)
			log.Printf("[ipfilter] cached: %s", DBTempPath)
			return err
		}
		//load cached
		file, err := os.Open(DBTempPath)
		if err != nil {
			return err
		}
		defer file.Close()
		return f.readerDB(DBPublicURL, file)
	}
	//no db options remain
	return errors.New("No DB")
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

//Allowed returns if a given IP can through the filter
func (f *IPFilter) Allowed(ipstr string) bool {
	ip := net.ParseIP(ipstr)
	//invalid ip
	if ip == nil {
		return false
	}
	//read lock entire function
	//except for db access
	f.mut.RLock()
	defer f.mut.RUnlock()
	//check single ips
	allowed, ok := f.ips[ipstr]
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

//Blocked returns if a given IP can NOT through the filter
func (f *IPFilter) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

//Wrap the provided handler with simple IP blocking middleware
//using this IP filter and its configuration
func (f *IPFilter) Wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{IPFilter: f, next: next}
}

//IP string to ISO country code.
//Returns an empty string when cannot determine country.
func (f *IPFilter) IPToCountry(ipstr string) string {
	if ip := net.ParseIP(ipstr); ip != nil {
		return f.NetIPToCountry(ip)
	}
	return ""
}

//net.IP to ISO country code.
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
	//use remote addr as it cant be spoofed
	//TODO also check X-Fowarded-For and friends
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	//show simple forbidden text
	if !m.IPFilter.Allowed(ip) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}
