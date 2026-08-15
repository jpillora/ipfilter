package ipasn

import (
	"math"
	"net"
	"net/netip"
	"testing"
)

func TestIPv4Lookup(t *testing.T) {
	tests := []struct {
		ip string
	}{
		{"8.8.8.8"},
		{"1.1.1.1"},
		{"4.2.2.2"},
		{"208.67.222.222"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := Lookup(net.ParseIP(tt.ip))
			if got.Number == 0 {
				t.Errorf("Lookup(%s).Number = 0, want an assigned ASN", tt.ip)
			}
			if got.Org == "" {
				t.Errorf("Lookup(%s).Org is empty", tt.ip)
			}
			viaNetip := IPLookup(netip.MustParseAddr(tt.ip))
			if got != viaNetip {
				t.Errorf("Lookup(%s) = %+v, IPLookup = %+v", tt.ip, got, viaNetip)
			}
		})
	}
}

func TestIPv6Lookup(t *testing.T) {
	tests := []struct {
		ip string
	}{
		{"2606:4700:4700::1111"},
		{"2001:4860:4860::8888"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := Lookup(net.ParseIP(tt.ip))
			if got.Number == 0 {
				t.Errorf("Lookup(%s).Number = 0, want an assigned ASN", tt.ip)
			}
			if got.Org == "" {
				t.Errorf("Lookup(%s).Org is empty", tt.ip)
			}
			viaNetip := IPLookup(netip.MustParseAddr(tt.ip))
			if got != viaNetip {
				t.Errorf("Lookup(%s) = %+v, IPLookup = %+v", tt.ip, got, viaNetip)
			}
		})
	}
}

func TestIPv4MappedLookup(t *testing.T) {
	got := IPLookup(netip.MustParseAddr("::ffff:8.8.8.8"))
	want := IPLookup(netip.MustParseAddr("8.8.8.8"))
	if got != want {
		t.Fatalf("IPLookup(mapped IPv4) = %+v, want %+v", got, want)
	}
}

func TestInvalidLookup(t *testing.T) {
	if got := IPLookup(netip.Addr{}); got != (ASN{}) {
		t.Fatalf("IPLookup(invalid) = %+v, want zero ASN", got)
	}
}

func TestOutOfRangeASNIndex(t *testing.T) {
	if got := readASN(math.MaxUint32); got != (ASN{}) {
		t.Fatalf("readASN(MaxUint32) = %+v, want zero ASN", got)
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
