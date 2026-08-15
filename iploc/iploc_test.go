package iploc

import (
	"net"
	"net/netip"
	"testing"
)

func TestIPv4Country(t *testing.T) {
	tests := []string{
		"1.1.1.1",
		"8.8.8.8",
		"104.28.125.2",
		"49.189.50.1",
		"52.92.180.128",
		"116.31.116.51",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			got := Country(net.ParseIP(ip))
			if len(got) != 2 {
				t.Errorf("Country(%s) = %q, want a two-letter country code", ip, got)
			}
			viaNetip := IPCountry(netip.MustParseAddr(ip))
			if got != viaNetip {
				t.Errorf("Country(%s) = %q, IPCountry = %q", ip, got, viaNetip)
			}
		})
	}
}

func TestIPv6Country(t *testing.T) {
	tests := []string{
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
	}

	for _, ip := range tests {
		t.Run(ip, func(t *testing.T) {
			got := Country(net.ParseIP(ip))
			if len(got) != 2 {
				t.Errorf("Country(%s) = %q, want a two-letter country code", ip, got)
			}
			viaNetip := IPCountry(netip.MustParseAddr(ip))
			if got != viaNetip {
				t.Errorf("Country(%s) = %q, IPCountry = %q", ip, got, viaNetip)
			}
		})
	}
}

func TestIPv4MappedCountry(t *testing.T) {
	got := IPCountry(netip.MustParseAddr("::ffff:8.8.8.8"))
	want := IPCountry(netip.MustParseAddr("8.8.8.8"))
	if got != want {
		t.Fatalf("IPCountry(mapped IPv4) = %q, want %q", got, want)
	}
}

func TestInvalidCountry(t *testing.T) {
	if got := IPCountry(netip.Addr{}); got != "" {
		t.Fatalf("IPCountry(invalid) = %q, want empty", got)
	}
}

// TestReservedNoCountry guards against the bug where private and other
// special-use addresses fall into gaps in the MaxMind data and match the next
// allocated range, returning a bogus country. No such address may ever resolve
// to a country.
func TestReservedNoCountry(t *testing.T) {
	reserved := []string{
		// RFC 1918 private
		"10.0.0.1", "10.5.3.2", "10.255.255.254",
		"172.16.0.1", "172.31.255.254",
		"192.168.0.1", "192.168.1.1", "192.168.255.254",
		// loopback
		"127.0.0.1", "127.0.0.53",
		// link-local
		"169.254.0.1", "169.254.169.254",
		// CGNAT / shared address space
		"100.64.0.1", "100.127.255.254",
		// documentation, benchmarking, protocol assignments
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "192.0.0.1",
		// unspecified, multicast, reserved-future, broadcast
		"0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		// IPv6 loopback, unspecified, ULA private, link-local, documentation, multicast
		"::1", "::", "fd00::1", "fc00::1", "fe80::1", "2001:db8::1", "ff02::1",
	}
	for _, ip := range reserved {
		t.Run(ip, func(t *testing.T) {
			if got := Country(net.ParseIP(ip)); got != "" {
				t.Errorf("Country(%s) = %q, want %q (reserved/private addresses have no country)", ip, got, "")
			}
		})
	}
}

func BenchmarkIPv4Country(b *testing.B) {
	ip := netip.MustParseAddr("104.28.125.2")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IPCountry(ip)
	}
}

func BenchmarkIPv6Country(b *testing.B) {
	ip := netip.MustParseAddr("2606:4700:4700::1111")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IPCountry(ip)
	}
}
