// Package iploc provides fast IP to country lookup using embedded binary data
// generated from MaxMind GeoLite2-Country database.
//
// The binary format is optimized for fast lookups using binary search with
// direct memory access via unsafe pointers.
package iploc

import (
	_ "embed"
	"net"
	"net/netip"
	"reflect"
	"unsafe"
)

//go:embed ipv4.bin
var ipv4Bin []byte

//go:embed ipv4.txt
var ipv4Txt []byte

//go:embed ipv6.bin
var ipv6Bin []byte

//go:embed ipv6.txt
var ipv6Txt []byte

// Country returns the ISO 3166-1 alpha-2 country code for the given net.IP.
// Returns an empty string if the country cannot be determined.
func Country(ip net.IP) string {
	// net.ParseIP returns 16-byte IPv4-mapped IPv6 for IPv4 addresses.
	// Convert to 4-byte form if possible.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return IPCountry(addr)
	}
	return ""
}

// IPCountry returns the ISO 3166-1 alpha-2 country code for the given netip.Addr.
// Returns an empty string if the country cannot be determined.
func IPCountry(ip netip.Addr) (country string) {
	if ip.Is4() {
		return ipv4Country(ip)
	}
	return ipv6Country(ip)
}

func ipv4Country(ip netip.Addr) (country string) {
	if len(ipv4Bin) == 0 {
		return ""
	}

	b := ip.As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])

	// Binary search for the range containing this IP
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

	if i >= len(ipv4Txt)/2 {
		return ""
	}

	// Return country code via unsafe string construction (zero-copy)
	sh := (*reflect.StringHeader)(unsafe.Pointer(&country))
	sh.Data = uintptr(unsafe.Add(unsafe.Pointer(&ipv4Txt[0]), uintptr(i*2)))
	sh.Len = 2
	return
}

func ipv6Country(ip netip.Addr) (country string) {
	if len(ipv6Bin) == 0 {
		return ""
	}

	b := ip.As16()
	high := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	low := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])

	// Binary search for the range containing this IP
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

	if i >= len(ipv6Txt)/2 {
		return ""
	}

	// Return country code via unsafe string construction (zero-copy)
	sh := (*reflect.StringHeader)(unsafe.Pointer(&country))
	sh.Data = uintptr(unsafe.Add(unsafe.Pointer(&ipv6Txt[0]), uintptr(i*2)))
	sh.Len = 2
	return
}
