package ipfilter

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/phuslu/iploc"
	"github.com/tomasen/realip"
	"google.golang.org/grpc"
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
	// explicity allowed IPs
	AllowedIPs []string
	// explicity blocked IPs
	BlockedIPs []string
	// explicity allowed country ISO codes
	AllowedCountries []string
	// explicity blocked country ISO codes
	BlockedCountries []string
	// block by default (defaults to allow)
	BlockByDefault bool
	// TrustProxy enable check request IP from proxy
	TrustProxy bool
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
	// mut protects the below
	// rw since writes are rare
	mut            sync.RWMutex
	defaultAllowed bool
	ips            map[string]bool
	codes          map[string]bool
	subnets        []*subnet
}

type subnet struct {
	str     string
	ipnet   *net.IPNet
	allowed bool
}

const ipv6LoopBack = "::1" // IPV6 localhost equivalent

// New constructs IPFilter instance without downloading DB.
func New(opts Options) *IPFilter {
	if opts.Logger == nil {
		// disable logging by default
		opts.Logger = log.New(io.Discard, "", 0)
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
	// check if has subnet
	if ip, ipNet, err := net.ParseCIDR(str); err == nil {
		// containing only one ip? (no bits masked)
		if n, total := ipNet.Mask.Size(); n == total {
			f.mut.Lock()
			f.ips[ip.String()] = allowed
			f.mut.Unlock()
			return true
		}
		// check for existing
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
				ipnet:   ipNet,
				allowed: allowed,
			})
		}
		f.mut.Unlock()
		return true
	}
	// check if plain ip (/32)
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

// ToggleCountry alters a specific country setting.
func (f *IPFilter) ToggleCountry(code string, allowed bool) {
	f.mut.Lock()
	f.codes[code] = allowed
	f.mut.Unlock()
}

// ToggleDefault alters the default setting.
func (f *IPFilter) ToggleDefault(allowed bool) {
	f.mut.Lock()
	f.defaultAllowed = allowed
	f.mut.Unlock()
}

// Allowed returns if a given IP can pass through the filter.
func (f *IPFilter) Allowed(ipstr string) bool {
	return f.NetAllowed(net.ParseIP(ipstr))
}

// NetAllowed returns if a given net.IP can pass through the filter.
func (f *IPFilter) NetAllowed(ip net.IP) bool {
	// invalid ip
	if ip == nil {
		return false
	}
	// read lock entire function
	// except for db access
	f.mut.RLock()
	defer f.mut.RUnlock()
	// check single ips
	allowed, ok := f.ips[ip.String()]
	if ok {
		return allowed
	}
	// scan subnets for any allow/block
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
	// check country codes
	code := NetIPToCountry(ip)
	if code != "" {
		if allowed, ok := f.codes[code]; ok {
			return allowed
		}
	}
	// use default setting
	return f.defaultAllowed
}

// Blocked returns if a given IP can NOT pass through the filter.
func (f *IPFilter) Blocked(ip string) bool {
	return !f.Allowed(ip)
}

// NetBlocked returns if a given net.IP can NOT pass through the filter.
func (f *IPFilter) NetBlocked(ip net.IP) bool {
	return !f.NetAllowed(ip)
}

// Wrap the provided handler with simple IP blocking middleware
// using this IP filter and its configuration.
func (f *IPFilter) Wrap(next http.Handler) http.Handler {
	return &ipFilterMiddleware{IPFilter: f, next: next}
}

// Wrap is equivalent to NewLazy(opts) then Wrap(next).
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
		return string(iploc.Country(ip))
	}
	return ""
}

type ipFilterMiddleware struct {
	*IPFilter
	next http.Handler
}

// ServeHTTP intercepts the HTTP request, validates the IP and either blocks the request or serves it.
func (m *ipFilterMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var remoteIP string
	if m.opts.TrustProxy {
		remoteIP = realip.FromRequest(r)
	} else {
		remoteIP, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	allowed := m.IPFilter.Allowed(remoteIP)
	// special case localhost ipv4
	if !allowed && remoteIP == ipv6LoopBack && m.IPFilter.Allowed("127.0.0.1") {
		allowed = true
	}
	if !allowed {
		// show simple forbidden text
		m.printf("blocked %s", remoteIP)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	// success!
	m.next.ServeHTTP(w, r)
}

// IPFilterUnaryServerInterceptor intercepts a unary gRPC call and validates if the IP is allowed.
func (f *IPFilter) IPFilterUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if clientIP, err := f.getClientIP(ctx); err == nil {
			remoteIP, _, rIPErr := net.SplitHostPort(clientIP)
			if rIPErr != nil || len(remoteIP) == 0 {
				remoteIP = clientIP // Client IP mostly like doesn't have a port specified. Just use as-is
			}
			allowed := f.Allowed(remoteIP)
			// special case localhost ipv4
			if !allowed && remoteIP == ipv6LoopBack && f.Allowed("127.0.0.1") {
				allowed = true
			}
			if !allowed {
				f.printf("blocked %s", remoteIP)
				return nil, status.Errorf(codes.PermissionDenied, "not allowed to access %s", info.FullMethod)
			}
			// success!
		} else {
			f.printf("failed to detect IP address %v", err)
			return nil, status.Errorf(codes.Unauthenticated, "unable to identify client host. not allowed to access %s", info.FullMethod)
		}
		return handler(ctx, req)
	}
}

// IPFilterStreamServerInterceptor intercept a stream gRPC call and validates if the IP is allowed.
func (f *IPFilter) IPFilterStreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		stream grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := stream.Context()
		if clientIP, err := f.getClientIP(ctx); err == nil {
			remoteIP, _, rIPErr := net.SplitHostPort(clientIP)
			if rIPErr != nil || len(remoteIP) == 0 {
				remoteIP = clientIP // Client IP mostly like doesn't have a port specified. Just use as-is
			}
			allowed := f.Allowed(remoteIP)
			// special case localhost ipv4
			if !allowed && remoteIP == ipv6LoopBack && f.Allowed("127.0.0.1") {
				allowed = true
			}
			if !allowed {
				f.printf("blocked %s", remoteIP)
				return status.Errorf(codes.PermissionDenied, "not allowed to access %s", info.FullMethod)
			}
			// success!
		} else {
			f.printf("failed to detect IP address %v", err)
			return status.Errorf(codes.Unauthenticated, "unable to identify client host. not allowed to access %s", info.FullMethod)
		}
		return handler(srv, stream)
	}
}

// getClientIP inspects the context to retrieve the ip address of the client.
func (f *IPFilter) getClientIP(ctx context.Context) (string, error) {
	var clientIP string
	// Try to figure out the source IP if we trust the proxy
	if f.opts.TrustProxy {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			realIP := md["x-real-ip"]
			forwardedIP := md["x-forward-ip"]
			forwardedFor := md["x-forward-for"]
			switch {
			case len(forwardedFor) > 0:
				clientIP = strings.Trim(forwardedFor[0], " ")
			case len(forwardedIP) > 0:
				clientIP = strings.Trim(forwardedIP[0], " ")
			case len(realIP) > 0:
				clientIP = strings.Trim(realIP[0], " ")
			}
		}
	}
	// Get the client IP from the context
	if len(clientIP) == 0 {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return "", fmt.Errorf("couldn't parse client IP address")
		}
		clientIP = p.Addr.String()
	}
	return clientIP, nil
}

// NewNoDB is the same as New.
func NewNoDB(opts Options) *IPFilter {
	return New(opts)
}

// NewLazy is the same as New.
func NewLazy(opts Options) *IPFilter {
	return New(opts)
}

func (f *IPFilter) IPToCountry(ipstr string) string {
	return IPToCountry(ipstr)
}

func (f *IPFilter) NetIPToCountry(ip net.IP) string {
	return NetIPToCountry(ip)
}
