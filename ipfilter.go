package ipfilter

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/jpillora/ipfilter/iploc"
)

// Options for IPFilter. Allow supercedes Block for IP checks
// across all matching subnets, whereas country checks use the
// latest Allow/Block setting.
// IPs can be IPv4 or IPv6 and can optionally contain subnet
// masks (e.g. /24). Note however, determining if a given IP is
// included in a subnet requires a linear scan so is less performant
// than looking up single IPs.
//
// This could be improved with cidr range prefix tree.
type Options struct {
	//explicity allowed IPs
	AllowedIPs []string
	//explicity blocked IPs
	BlockedIPs []string
	//explicity allowed country ISO codes
	AllowedCountries []string
	//explicity blocked country ISO codes
	BlockedCountries []string
	//block by default (defaults to allow)
	BlockByDefault bool
	// TrustProxy enables forwarded-header handling for compatibility. When set
	// without TrustProxyCIDR, TrustProxyCIDR defaults to 0.0.0.0/0.
	TrustProxy bool
	// TrustProxyCIDR enables forwarded-header handling only for requests whose
	// direct peer belongs to this network. Prefer this over TrustProxy.
	TrustProxyCIDR string
	// Logger enables logging, printing using the provided interface
	Logger interface {
		Printf(format string, v ...interface{})
	}
	// These fields currently have no effect
	IPDB         []byte
	IPDBPath     string
	IPDBNoFetch  bool
	IPDBFetchURL string
}

type IPFilter struct {
	opts Options
	//mut protects the below
	//rw since writes are rare
	mut            sync.RWMutex
	defaultAllowed bool
	ips            map[string]bool
	codes          map[string]bool
	subnets        []*subnet
	trustedProxy   *net.IPNet
	trustAllProxy  bool
}

type subnet struct {
	str     string
	ipnet   *net.IPNet
	allowed bool
}

// New constructs IPFilter instance without downloading DB.
func New(opts Options) *IPFilter {
	if opts.Logger == nil {
		//disable logging by default
		opts.Logger = log.New(io.Discard, "", 0)
	}
	trustAllProxy := opts.TrustProxy && opts.TrustProxyCIDR == ""
	if trustAllProxy {
		// Preserve the original trust-all behavior for callers using the boolean
		// API. trustAllProxy also preserves trust for IPv6 peers.
		opts.TrustProxyCIDR = "0.0.0.0/0"
	}
	var trustedProxy *net.IPNet
	if opts.TrustProxyCIDR != "" {
		if _, network, err := net.ParseCIDR(opts.TrustProxyCIDR); err == nil {
			trustedProxy = network
		} else {
			panic(fmt.Sprintf("ipfilter: invalid TrustProxyCIDR %q: %v", opts.TrustProxyCIDR, err))
		}
	}
	f := &IPFilter{
		opts:           opts,
		ips:            map[string]bool{},
		codes:          map[string]bool{},
		defaultAllowed: !opts.BlockByDefault,
		trustedProxy:   trustedProxy,
		trustAllProxy:  trustAllProxy,
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

func (f *IPFilter) printf(format string, args ...interface{}) {
	if l := f.opts.Logger; l != nil {
		l.Printf("[ipfilter] "+format, args...)
	}
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
		// containing only one ip? (no bits masked)
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
	//check if plain ip (/32)
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

// ToggleCountry alters a specific country setting
func (f *IPFilter) ToggleCountry(code string, allowed bool) {

	f.mut.Lock()
	f.codes[code] = allowed
	f.mut.Unlock()
}

// ToggleDefault alters the default setting
func (f *IPFilter) ToggleDefault(allowed bool) {
	f.mut.Lock()
	f.defaultAllowed = allowed
	f.mut.Unlock()
}

// Allowed returns if a given IP can pass through the filter
func (f *IPFilter) Allowed(ipstr string) bool {
	return f.NetAllowed(net.ParseIP(ipstr))
}

// NetAllowed returns if a given net.IP can pass through the filter
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
	code := NetIPToCountry(ip)
	if code != "" {
		if allowed, ok := f.codes[code]; ok {
			return allowed
		}
	}
	//use default setting
	return f.defaultAllowed
}

// Blocked returns if a given IP can NOT pass through the filter
func (f *IPFilter) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

// NetBlocked returns if a given net.IP can NOT pass through the filter
func (f *IPFilter) NetBlocked(ip net.IP) bool {
	return !f.NetAllowed(ip)
}

// Wrap the provided handler with simple IP blocking middleware
// using this IP filter and its configuration
func (f *IPFilter) Wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{IPFilter: f, next: next}
}

// Wrap is equivalent to NewLazy(opts) then Wrap(next)
func Wrap(next http.Handler, opts Options) http.Handler {
	return New(opts).Wrap(next)
}

// IPToCountry is a simple IP-country code lookup.
// Returns an empty string when cannot determine country.
func IPToCountry(ipstr string) string {
	return NetIPToCountry(net.ParseIP(ipstr))
}

// NetIPToCountry is a simple IP-country code lookup.
// Returns an empty string when cannot determine country.
func NetIPToCountry(ip net.IP) string {
	if ip != nil {
		return iploc.Country(ip)
	}
	return ""
}

type ipFilterMiddleware struct {
	*IPFilter
	next http.Handler
}

func (m *ipFilterMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := requestPeerIP(r.RemoteAddr)
	peer := net.ParseIP(remoteIP)
	if m.trustAllProxy || (peer != nil && m.trustedProxy != nil && m.trustedProxy.Contains(peer)) {
		remoteIP = forwardedClientIP(r, m.trustedProxy, remoteIP, m.trustAllProxy)
	}
	allowed := m.IPFilter.Allowed(remoteIP)
	//special case localhost ipv4
	if !allowed && remoteIP == "::1" && m.IPFilter.Allowed("127.0.0.1") {
		allowed = true
	}
	if !allowed {
		//show simple forbidden text
		m.printf("blocked %s", remoteIP)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	//success!
	m.next.ServeHTTP(w, r)
}

// requestPeerIP extracts an IP from the address format used by net/http. The
// fallback also supports requests assembled by callers with a bare RemoteAddr.
func requestPeerIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddr)
}

// forwardedClientIP walks X-Forwarded-For from the nearest hop to the
// furthest, discarding trusted proxies. This prevents a client-supplied
// left-most value from overriding the address appended by a trusted proxy.
func forwardedClientIP(r *http.Request, trustedProxy *net.IPNet, fallback string, legacy bool) string {
	forwardedHeader := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	forwarded := strings.Split(forwardedHeader, ",")
	if legacy {
		// Match the legacy TrustProxy behavior when the compatibility CIDR is
		// active: use the first non-private forwarded address, then X-Real-IP.
		if forwardedHeader != "" {
			for _, value := range forwarded {
				candidate := net.ParseIP(strings.TrimSpace(value))
				if candidate != nil && !candidate.IsPrivate() && !candidate.IsLoopback() && !candidate.IsLinkLocalUnicast() {
					return candidate.String()
				}
			}
			return strings.TrimSpace(r.Header.Get("X-Real-IP"))
		}
		if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
			return realIP
		}
		return fallback
	}
	leftmost := ""
	if forwardedHeader != "" {
		for i := len(forwarded) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(forwarded[i]))
			if candidate == nil {
				// A malformed hop makes every value to its left untrustworthy.
				return fallback
			}
			leftmost = candidate.String()
			if !trustedProxy.Contains(candidate) {
				return leftmost
			}
		}
	}
	// If the complete chain is trusted, the left-most valid address is the best
	// available client IP.
	if leftmost != "" {
		return leftmost
	}
	if candidate := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); candidate != nil {
		return candidate.String()
	}
	return fallback
}

// NewNoDB is the same as New
func NewNoDB(opts Options) *IPFilter {
	return New(opts)
}

// NewLazy is the same as New
func NewLazy(opts Options) *IPFilter {
	return New(opts)
}

func (f *IPFilter) IPToCountry(ipstr string) string {
	return IPToCountry(ipstr)
}

func (f *IPFilter) NetIPToCountry(ip net.IP) string {
	return NetIPToCountry(ip)
}
