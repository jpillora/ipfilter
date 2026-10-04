package ipfilter_test

import (
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/jpillora/ipfilter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubnetPrecedence(t *testing.T) {
	for _, family := range []struct {
		name, broad, narrow, host, exact string
	}{
		{"IPv4", "10.0.0.0/8", "10.1.0.0/16", "10.1.2.3", "10.1.2.3/32"},
		{"IPv6", "fd00::/8", "fd00:1::/32", "fd00:1::1234", "fd00:1::1234/128"},
	} {
		t.Run(family.name, func(t *testing.T) {
			for _, rules := range []struct{ allow, block string }{
				{family.broad, family.narrow},
				{family.narrow, family.broad},
			} {
				f := ipfilter.New(ipfilter.Options{
					AllowedIPs:     []string{rules.allow},
					BlockedIPs:     []string{rules.block},
					BlockByDefault: true,
				})
				assert.True(t, f.Allowed(family.host), "any matching allow subnet overrides block subnets")
				require.True(t, f.BlockIP(family.exact))
				assert.False(t, f.Allowed(family.host), "an exact IP overrides all subnet rules")
				require.True(t, f.AllowIP(family.host))
				assert.True(t, f.Allowed(family.host), "plain IP and full-length CIDR update the same rule")
			}

			f := ipfilter.New(ipfilter.Options{BlockedIPs: []string{family.broad}})
			assert.False(t, f.Allowed(family.host), "a matching block overrides the default allow")
			require.True(t, f.AllowIP(family.broad))
			assert.True(t, f.Allowed(family.host))
			require.True(t, f.BlockIP(family.broad))
			assert.False(t, f.Allowed(family.host), "toggling the same subnet updates its rule")
		})
	}
}

func TestSubnetEquivalentRules(t *testing.T) {
	for _, tt := range []struct {
		name, first, second, host string
	}{
		{"IPv4 host bits", "10.1.0.0/16", "10.1.2.3/16", "10.1.4.5"},
		{"IPv6 spelling", "fd00:1::/32", "fd00:0001:0000:0000:0000:0000:0000:0000/32", "fd00:1::1234"},
		{"IPv4 mapped IPv6", "192.0.2.0/24", "::ffff:192.0.2.0/120", "192.0.2.42"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := ipfilter.New(ipfilter.Options{BlockByDefault: true})
			require.True(t, f.AllowIP(tt.first))
			require.True(t, f.BlockIP(tt.second))
			assert.True(t, f.Allowed(tt.host), "equivalent CIDR strings remain independent rules")
			require.True(t, f.BlockIP(tt.first))
			assert.False(t, f.Allowed(tt.host))
			require.True(t, f.AllowIP(tt.second))
			assert.True(t, f.Allowed(tt.host))
			require.True(t, f.AllowIP(tt.first))
			require.True(t, f.AllowIP(tt.first))
			require.True(t, f.BlockIP(tt.second))
			assert.True(t, f.Allowed(tt.host), "repeated allows must not lose another allow rule")
			require.True(t, f.BlockIP(tt.first))
			assert.False(t, f.Allowed(tt.host), "repeated allows must not inflate the allow count")
		})
	}
}

func TestSubnetPrefixLengths(t *testing.T) {
	for _, addr := range []string{"198.51.100.42", "2001:db8:1234:5678:abcd:ef01:2345:6789", "::ffff:198.51.100.42"} {
		bits := 128
		if addr == "198.51.100.42" {
			bits = 32
		}
		for prefix := 0; prefix <= bits; prefix++ {
			cidr := fmt.Sprintf("%s/%d", addr, prefix)
			t.Run(cidr, func(t *testing.T) {
				_, network, err := net.ParseCIDR(cidr)
				require.NoError(t, err)
				first := network.IP
				last := append(net.IP(nil), first...)
				for i := range last {
					last[i] |= ^network.Mask[i]
				}
				outside := append(net.IP(nil), first...)
				if prefix > 0 {
					outside[(prefix-1)/8] ^= 1 << (7 - (prefix-1)%8)
				}
				f := ipfilter.New(ipfilter.Options{
					AllowedIPs:     []string{cidr},
					BlockByDefault: true,
				})
				for _, ip := range []net.IP{
					first, last, outside, net.ParseIP(addr),
					net.IP{198, 51, 100, 42}, net.ParseIP("2001:db8::1"),
				} {
					assert.Equal(t, network.Contains(ip), f.NetAllowed(ip), "%s in %s", ip, cidr)
				}
			})
		}
	}
}

func TestSubnetConcurrentUpdates(t *testing.T) {
	f := ipfilter.New(ipfilter.Options{
		AllowedIPs:     []string{"10.0.0.0/8", "fd00::/8"},
		BlockByDefault: true,
	})
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Go(func() {
			for n := 0; n < 100; n++ {
				f.ToggleIP("10.1.0.0/16", n%2 == 0)
				f.ToggleIP("fd00:1::/32", n%2 == 0)
				assert.True(t, f.Allowed("10.1.2.3"))
				assert.True(t, f.Allowed("fd00:1::1234"))
			}
		})
	}
	workers.Wait()
}

func BenchmarkSubnetIP(b *testing.B) {
	for _, family := range []string{"IPv4", "IPv6"} {
		for _, count := range []int{1, 100, 10000} {
			f := ipfilter.New(ipfilter.Options{BlockByDefault: true})
			for i := 0; i < count; i++ {
				cidr := fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
				if family == "IPv6" {
					cidr = fmt.Sprintf("fd00:%x::/48", i)
				}
				if !f.AllowIP(cidr) {
					b.Fatalf("invalid subnet %s", cidr)
				}
			}
			match := fmt.Sprintf("10.%d.%d.1", (count-1)/256, (count-1)%256)
			miss := "192.0.2.1"
			if family == "IPv6" {
				match = fmt.Sprintf("fd00:%x::1", count-1)
				miss = "fd01::1"
			}
			for _, lookup := range []struct {
				name, addr string
				allowed    bool
			}{
				{"match", match, true},
				{"miss", miss, false},
			} {
				b.Run(fmt.Sprintf("%s/%d/%s", family, count, lookup.name), func(b *testing.B) {
					ip := net.ParseIP(lookup.addr)
					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						if f.NetAllowed(ip) != lookup.allowed {
							b.Fatal("incorrect subnet decision")
						}
					}
				})
			}
		}
	}
}
