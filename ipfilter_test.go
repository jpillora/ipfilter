package ipfilter_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jpillora/ipfilter"
	"github.com/stretchr/testify/assert"
)

const (
	egUS = "52.92.180.128"
	egAU = "49.189.50.1"
	egCN = "116.31.116.51"
)

func TestSingleIP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
	assert.True(t, f.NetAllowed(net.IP{222, 25, 118, 1}), "[3] should be allowed")
	assert.True(t, f.NetBlocked(net.IP{222, 25, 118, 2}), "[4] should be blocked")
}

func TestSubnetIP(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"10.0.0.0/16"},
		BlockByDefault: true,
	})
	assert.True(t, f.Allowed("10.0.0.1"), "[1] should be allowed")
	assert.True(t, f.Allowed("10.0.42.1"), "[2] should be allowed")
	assert.True(t, f.Blocked("10.42.0.1"), "[3] should be blocked")
}

func TestManualCountryCode(t *testing.T) {
	for _, ip := range []string{egAU, egUS, egCN} {
		code := ipfilter.IPToCountry(ip)
		assert.Len(t, code, 2, "%s should resolve to a country code", ip)
		assert.Equal(t, code, ipfilter.New(ipfilter.Options{}).IPToCountry(ip))
	}
}

func TestCountryCodeWhiteList(t *testing.T) {
	code := ipfilter.IPToCountry(egAU)
	assert.Len(t, code, 2)
	f := ipfilter.New(ipfilter.Options{
		AllowedCountries: []string{code},
		BlockByDefault:   true,
	})
	assert.True(t, f.Allowed(egAU), "an IP matching the allowed country should be allowed")
	assert.True(t, f.Blocked("192.0.2.1"), "an address without a matching country should be blocked")
}

func TestCountryCodeBlackList(t *testing.T) {
	code := ipfilter.IPToCountry(egCN)
	assert.Len(t, code, 2)
	f := ipfilter.New(ipfilter.Options{
		BlockedCountries: []string{code},
	})
	assert.True(t, f.Blocked(egCN), "an IP matching the blocked country should be blocked")
	assert.True(t, f.Allowed("192.0.2.1"), "an address without a matching country should use the default")
}

// privateIPs are RFC1918/loopback/link-local/CGNAT/IPv6-ULA addresses that must
// never be associated with a country.
var privateIPs = []string{
	"10.0.0.1", "172.16.0.1", "192.168.0.1", "127.0.0.1",
	"169.254.0.1", "100.64.0.1", "::1", "fd00::1", "fe80::1",
}

// TestPrivateIPNoCountry confirms private/reserved IPs never resolve to a
// country code.
func TestPrivateIPNoCountry(t *testing.T) {
	for _, ip := range privateIPs {
		assert.Equal(t, "", ipfilter.IPToCountry(ip), "%s must have no country", ip)
	}
}

// TestPrivateIPNotAllowedByCountryWhitelist confirms a private IP cannot slip
// through a country whitelist by matching a bogus country. Previously e.g.
// 10.0.0.1 resolved to "US" and would be allowed here.
func TestPrivateIPNotAllowedByCountryWhitelist(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedCountries: []string{"US"},
		BlockByDefault:   true,
	})
	for _, ip := range privateIPs {
		assert.True(t, f.Blocked(ip), "%s should be blocked, not matched to a country", ip)
	}
}

func TestDynamicList(t *testing.T) {
	code := ipfilter.IPToCountry(egCN)
	assert.Len(t, code, 2)
	f := ipfilter.New(ipfilter.Options{})
	assert.True(t, f.Allowed(egCN), "the default should initially allow the IP")
	f.BlockCountry(code)
	assert.True(t, f.Blocked(egCN), "the dynamically blocked country should be blocked")
}

func TestTrustProxyCIDR(t *testing.T) {
	filter := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"203.0.113.10"},
		BlockByDefault: true,
		TrustProxyCIDR: "10.0.0.0/8",
	})
	handler := filter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		wantStatus int
	}{
		{
			name:       "trusted proxy and allowed client",
			remoteAddr: "10.0.0.2:1234",
			forwarded:  "203.0.113.10, 10.0.0.3",
			wantStatus: http.StatusNoContent,
		},
		{
			name:       "untrusted peer cannot spoof header",
			remoteAddr: "198.51.100.20:1234",
			forwarded:  "203.0.113.10",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "client supplied leftmost value is ignored",
			remoteAddr: "10.0.0.2:1234",
			forwarded:  "203.0.113.10, 198.51.100.20",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "malformed hop stops processing",
			remoteAddr: "10.0.0.2:1234",
			forwarded:  "203.0.113.10, malformed, 10.0.0.3",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("X-Forwarded-For", tt.forwarded)
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			assert.Equal(t, tt.wantStatus, res.Code)
		})
	}
}

func TestTrustProxyBackwardCompatibility(t *testing.T) {
	filter := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"203.0.113.10"},
		BlockByDefault: true,
		TrustProxy:     true,
	})
	handler := filter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, remoteAddr := range []string{"198.51.100.20:1234", "[2001:db8::20]:1234"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.10")
		res := httptest.NewRecorder()

		handler.ServeHTTP(res, req)

		assert.Equal(t, http.StatusNoContent, res.Code, remoteAddr)
	}
}

func TestTrustProxyCIDRMultipleForwardedHeaderLines(t *testing.T) {
	filter := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"203.0.113.10"},
		BlockByDefault: true,
		TrustProxyCIDR: "10.0.0.0/8",
	})
	handler := filter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	req.Header.Add("X-Forwarded-For", "203.0.113.10")
	req.Header.Add("X-Forwarded-For", "198.51.100.20")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	assert.Equal(t, http.StatusForbidden, res.Code)
}

func TestInvalidTrustProxyCIDRPanics(t *testing.T) {
	assert.Panics(t, func() {
		ipfilter.New(ipfilter.Options{TrustProxyCIDR: "10.0.0.0/33"})
	})
}

func TestTrustProxyCIDRWithoutLegacyFlag(t *testing.T) {
	filter := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"203.0.113.10"},
		BlockByDefault: true,
		TrustProxyCIDR: "10.0.0.0/8",
	})
	handler := filter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	req.Header.Set("X-Real-IP", "203.0.113.10")
	res := httptest.NewRecorder()

	handler.ServeHTTP(res, req)

	assert.Equal(t, http.StatusNoContent, res.Code)
}
