// Package ipasn provides fast IP to ASN lookup using embedded binary data
// generated from MaxMind GeoLite2-ASN.
//
// Default builds embed raw binary data. Build with -tags ipasn_gzip to embed
// gzipped data and decompress at init time.
package ipasn

import (
	"net"
	"net/netip"
	"reflect"
	"unsafe"
)

// ASN represents an autonomous-system record.
type ASN struct {
	Number uint32 // e.g. 13335
	Org    string // e.g. "Cloudflare, Inc."
}

// Package-level byte slices populated by either data_raw.go or data_gzip.go.
var (
	ipv4Bin []byte // sorted end IPs (uint32 LE x N)
	ipv4Idx []byte // parallel asn-table indices (uint32 LE x N)
	ipv6Bin []byte // sorted end IPs (uint64 LE pair x N)
	ipv6Idx []byte // parallel asn-table indices (uint32 LE x N)
	asnBin  []byte // ASN records (12 bytes each)
	orgsTxt []byte // concatenated org-name bytes
)

// Lookup returns the ASN for the given net.IP. Zero value if not found.
func Lookup(ip net.IP) ASN {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return IPLookup(addr)
	}
	return ASN{}
}

// IPLookup returns the ASN for the given netip.Addr. Zero value if not found.
func IPLookup(ip netip.Addr) ASN {
	if ip.Is4() {
		return ipv4Lookup(ip)
	}
	return ipv6Lookup(ip)
}

func ipv4Lookup(ip netip.Addr) ASN {
	if len(ipv4Bin) == 0 {
		return ASN{}
	}

	b := ip.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])

	i, j := 0, len(ipv4Bin)/4
	for i < j {
		h := (i + j) >> 1
		end := *(*uint32)(unsafe.Add(unsafe.Pointer(&ipv4Bin[0]), uintptr(h*4)))
		if end < n {
			i = h + 1
		} else {
			j = h
		}
	}

	if i >= len(ipv4Idx)/4 {
		return ASN{}
	}
	asnIdx := *(*uint32)(unsafe.Add(unsafe.Pointer(&ipv4Idx[0]), uintptr(i*4)))
	return readASN(asnIdx)
}

func ipv6Lookup(ip netip.Addr) ASN {
	if len(ipv6Bin) == 0 {
		return ASN{}
	}

	b := ip.As16()
	high := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	low := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])

	i, j := 0, len(ipv6Bin)/16
	for i < j {
		h := (i + j) >> 1
		endHigh := *(*uint64)(unsafe.Add(unsafe.Pointer(&ipv6Bin[0]), uintptr(h*16)))
		endLow := *(*uint64)(unsafe.Add(unsafe.Pointer(&ipv6Bin[0]), uintptr(h*16+8)))
		if endHigh < high || (endHigh == high && endLow < low) {
			i = h + 1
		} else {
			j = h
		}
	}

	if i >= len(ipv6Idx)/4 {
		return ASN{}
	}
	asnIdx := *(*uint32)(unsafe.Add(unsafe.Pointer(&ipv6Idx[0]), uintptr(i*4)))
	return readASN(asnIdx)
}

// readASN reads ASN record at index from asn.bin and returns ASN with org
// constructed as a zero-copy string view into orgs.txt.
func readASN(idx uint32) ASN {
	base := uintptr(idx) * 12
	if int(base)+12 > len(asnBin) {
		return ASN{}
	}
	num := *(*uint32)(unsafe.Add(unsafe.Pointer(&asnBin[0]), base))
	off := *(*uint32)(unsafe.Add(unsafe.Pointer(&asnBin[0]), base+4))
	ln := *(*uint16)(unsafe.Add(unsafe.Pointer(&asnBin[0]), base+8))

	var org string
	if ln > 0 && int(off)+int(ln) <= len(orgsTxt) {
		sh := (*reflect.StringHeader)(unsafe.Pointer(&org))
		sh.Data = uintptr(unsafe.Add(unsafe.Pointer(&orgsTxt[0]), uintptr(off)))
		sh.Len = int(ln)
	}
	return ASN{Number: num, Org: org}
}
