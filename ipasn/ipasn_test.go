package ipasn

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestIPv4Lookup(t *testing.T) {
	tests := []struct {
		ip      string
		number  uint32
		orgPart string // substring match, MaxMind tweaks org strings over time
	}{
		{"8.8.8.8", 15169, "Google"},
		{"1.1.1.1", 13335, "Cloudflare"},
		{"4.2.2.2", 3356, "Level 3"},
		{"208.67.222.222", 36692, "OPENDNS"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := Lookup(net.ParseIP(tt.ip))
			if got.Number != tt.number {
				t.Errorf("Lookup(%s).Number = %d, want %d", tt.ip, got.Number, tt.number)
			}
			if !strings.Contains(strings.ToUpper(got.Org), strings.ToUpper(tt.orgPart)) {
				t.Errorf("Lookup(%s).Org = %q, want substring %q", tt.ip, got.Org, tt.orgPart)
			}
		})
	}
}

func TestIPv6Lookup(t *testing.T) {
	tests := []struct {
		ip      string
		number  uint32
		orgPart string
	}{
		{"2606:4700:4700::1111", 13335, "Cloudflare"},
		{"2001:4860:4860::8888", 15169, "Google"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := Lookup(net.ParseIP(tt.ip))
			if got.Number != tt.number {
				t.Errorf("Lookup(%s).Number = %d, want %d", tt.ip, got.Number, tt.number)
			}
			if !strings.Contains(strings.ToUpper(got.Org), strings.ToUpper(tt.orgPart)) {
				t.Errorf("Lookup(%s).Org = %q, want substring %q", tt.ip, got.Org, tt.orgPart)
			}
		})
	}
}

func TestNotFound(t *testing.T) {
	// 0.0.0.0 typically has no ASN assignment.
	got := Lookup(net.ParseIP("0.0.0.0"))
	if got.Number != 0 || got.Org != "" {
		t.Errorf("Lookup(0.0.0.0) = %+v, want zero ASN", got)
	}
}

func BenchmarkIPv4Lookup(b *testing.B) {
	ip := netip.MustParseAddr("8.8.8.8")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IPLookup(ip)
	}
}

func BenchmarkIPv6Lookup(b *testing.B) {
	ip := netip.MustParseAddr("2606:4700:4700::1111")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IPLookup(ip)
	}
}
