package iploc

import "net/netip"

// The country lookup performs a binary search over range *end* boundaries. The
// underlying MaxMind data only contains globally-routable ranges, so private,
// loopback and other special-use addresses are absent and leave gaps between
// ranges. A gap address matches the next allocated range and would therefore
// return a bogus country (e.g. 10.0.0.1 => "US", 127.0.0.1 => "NL"). These
// addresses are never assigned to a country, so we must reject them before the
// search runs.
//
// reservedPrefixes lists the IANA special-purpose ranges that are not globally
// reachable unicast, so must never resolve to a country. Sourced from the IANA
// IPv4/IPv6 Special-Purpose Address Registries.
var reservedPrefixes = func() []netip.Prefix {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",       // "this network" / unspecified (RFC 1122)
		"10.0.0.0/8",      // private (RFC 1918)
		"100.64.0.0/10",   // shared address space / CGNAT (RFC 6598)
		"127.0.0.0/8",     // loopback (RFC 1122)
		"169.254.0.0/16",  // link-local (RFC 3927)
		"172.16.0.0/12",   // private (RFC 1918)
		"192.0.0.0/24",    // IETF protocol assignments (RFC 6890)
		"192.0.2.0/24",    // documentation TEST-NET-1 (RFC 5737)
		"192.88.99.0/24",  // 6to4 relay anycast, deprecated (RFC 7526)
		"192.168.0.0/16",  // private (RFC 1918)
		"198.18.0.0/15",   // benchmarking (RFC 2544)
		"198.51.100.0/24", // documentation TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",  // documentation TEST-NET-3 (RFC 5737)
		"224.0.0.0/4",     // multicast (RFC 5771)
		"240.0.0.0/4",     // reserved for future use, incl. 255.255.255.255 broadcast (RFC 1112)

		// IPv6
		"::/128",         // unspecified (RFC 4291)
		"::1/128",        // loopback (RFC 4291)
		"64:ff9b:1::/48", // local-use NAT64 (RFC 8215)
		"100::/64",       // discard-only (RFC 6666)
		"2001:db8::/32",  // documentation (RFC 3849)
		"fc00::/7",       // unique local address / private (RFC 4193)
		"fe80::/10",      // link-local (RFC 4291)
		"ff00::/8",       // multicast (RFC 4291)
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		prefixes = append(prefixes, netip.MustParsePrefix(c))
	}
	return prefixes
}()

// reserved reports whether ip belongs to a special-use range that is never
// assigned to a country and so must not be matched against the country data.
func reserved(ip netip.Addr) bool {
	// Unmap IPv4-in-IPv6 so IPv4 prefixes match regardless of representation.
	ip = ip.Unmap()
	if !ip.IsValid() {
		return true
	}
	for _, p := range reservedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
