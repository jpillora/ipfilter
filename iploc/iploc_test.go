package iploc

import (
	"net"
	"net/netip"
	"testing"
)

func TestIPv4Country(t *testing.T) {
	tests := []struct {
		ip      string
		country string
	}{
		{"1.1.1.1", "ZZ"},           // Cloudflare DNS (no country in MaxMind)
		{"8.8.8.8", "US"},           // Google DNS
		{"104.28.125.2", "AU"},      // Cloudflare Sydney - the IP that started this!
		{"49.189.50.1", "AU"},       // Australian IP
		{"52.92.180.128", "US"},     // US IP
		{"116.31.116.51", "CN"},     // Chinese IP
		{"127.0.0.1", "NL"},         // Localhost (MaxMind maps to NL)
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := Country(net.ParseIP(tt.ip))
			if got != tt.country {
				t.Errorf("Country(%s) = %q, want %q", tt.ip, got, tt.country)
			}
		})
	}
}

func TestIPv6Country(t *testing.T) {
	tests := []struct {
		ip      string
		country string
	}{
		{"2606:4700:4700::1111", "ZZ"}, // Cloudflare IPv6 DNS (no country in MaxMind)
		{"2001:4860:4860::8888", "US"}, // Google IPv6 DNS
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := Country(net.ParseIP(tt.ip))
			if got != tt.country {
				t.Errorf("Country(%s) = %q, want %q", tt.ip, got, tt.country)
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
