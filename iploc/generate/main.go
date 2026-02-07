// Command generate converts MaxMind GeoLite2-Country.mmdb to iploc binary format.
//
// Usage: go run ./iploc/generate -mmdb path/to/GeoLite2-Country.mmdb -out ./iploc
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/oschwald/maxminddb-golang/v2"
)

type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type ipRange struct {
	end     netip.Addr
	country string
}

func main() {
	mmdbPath := flag.String("mmdb", "", "path to GeoLite2-Country.mmdb")
	outDir := flag.String("out", ".", "output directory")
	flag.Parse()

	if *mmdbPath == "" {
		fmt.Fprintln(os.Stderr, "usage: generate -mmdb path/to/GeoLite2-Country.mmdb")
		os.Exit(1)
	}

	db, err := maxminddb.Open(*mmdbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open mmdb: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	var ipv4Ranges, ipv6Ranges []ipRange

	// Iterate all networks in the database
	for result := range db.Networks() {
		if result.Err() != nil {
			fmt.Fprintf(os.Stderr, "network iteration error: %v\n", result.Err())
			continue
		}

		var record countryRecord
		if err := result.Decode(&record); err != nil {
			continue
		}

		country := record.Country.ISOCode
		if country == "" {
			country = "ZZ" // Unknown
		}

		// Get the last IP in the range
		prefix := result.Prefix()
		lastIP := lastAddr(prefix)

		r := ipRange{end: lastIP, country: country}
		if prefix.Addr().Is4() {
			ipv4Ranges = append(ipv4Ranges, r)
		} else {
			ipv6Ranges = append(ipv6Ranges, r)
		}
	}

	// Sort by end IP
	sort.Slice(ipv4Ranges, func(i, j int) bool {
		return ipv4Ranges[i].end.Compare(ipv4Ranges[j].end) < 0
	})
	sort.Slice(ipv6Ranges, func(i, j int) bool {
		return ipv6Ranges[i].end.Compare(ipv6Ranges[j].end) < 0
	})

	// Write IPv4 binary (little-endian uint32 array)
	ipv4Bin := make([]byte, len(ipv4Ranges)*4)
	ipv4Txt := make([]byte, len(ipv4Ranges)*2)
	for i, r := range ipv4Ranges {
		b := r.end.As4()
		n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		binary.LittleEndian.PutUint32(ipv4Bin[i*4:], n)
		copy(ipv4Txt[i*2:], r.country)
	}

	// Write IPv6 binary (little-endian uint64 pairs, gzipped)
	ipv6Bin := make([]byte, len(ipv6Ranges)*16)
	ipv6Txt := make([]byte, len(ipv6Ranges)*2)
	for i, r := range ipv6Ranges {
		b := r.end.As16()
		high := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
		low := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
			uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
		binary.LittleEndian.PutUint64(ipv6Bin[i*16:], high)
		binary.LittleEndian.PutUint64(ipv6Bin[i*16+8:], low)
		copy(ipv6Txt[i*2:], r.country)
	}

	// Write files
	write := func(name string, data []byte) {
		path := filepath.Join(*outDir, name)
		if err := os.WriteFile(path, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d bytes)\n", path, len(data))
	}

	write("ipv4.bin", ipv4Bin)
	write("ipv4.txt", ipv4Txt)
	write("ipv6.bin", ipv6Bin)
	write("ipv6.txt", ipv6Txt)

	fmt.Printf("\nTotal: %d IPv4 ranges, %d IPv6 ranges\n", len(ipv4Ranges), len(ipv6Ranges))
}

// lastAddr returns the last address in a prefix
func lastAddr(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	bits := p.Bits()

	if addr.Is4() {
		b := addr.As4()
		n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		mask := uint32(0xFFFFFFFF) >> bits
		n |= mask
		return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}

	b := addr.As16()
	high := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	low := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
		uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])

	if bits <= 64 {
		mask := uint64(0xFFFFFFFFFFFFFFFF) >> bits
		high |= mask
		low = 0xFFFFFFFFFFFFFFFF
	} else {
		mask := uint64(0xFFFFFFFFFFFFFFFF) >> (bits - 64)
		low |= mask
	}

	var out [16]byte
	out[0], out[1], out[2], out[3] = byte(high>>56), byte(high>>48), byte(high>>40), byte(high>>32)
	out[4], out[5], out[6], out[7] = byte(high>>24), byte(high>>16), byte(high>>8), byte(high)
	out[8], out[9], out[10], out[11] = byte(low>>56), byte(low>>48), byte(low>>40), byte(low>>32)
	out[12], out[13], out[14], out[15] = byte(low>>24), byte(low>>16), byte(low>>8), byte(low)
	return netip.AddrFrom16(out)
}
