// Command generate converts MaxMind GeoLite2-ASN.mmdb to ipasn binary format.
//
// Usage: go run ./ipasn/generate -mmdb path/to/GeoLite2-ASN.mmdb -out ./ipasn
//
// Output files (raw + .gz):
//
//	ipv4.bin  sorted end-IPs (uint32 LE x N)
//	ipv4.idx  parallel array of asn-table indices (uint32 LE x N)
//	ipv6.bin  sorted end-IPs (uint64 LE pair x N)
//	ipv6.idx  parallel array of asn-table indices (uint32 LE x N)
//	asn.bin   deduped ASN records: {asn:u32, org_off:u32, org_len:u16, _pad:u16}
//	orgs.txt  concatenated org-name bytes
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/oschwald/maxminddb-golang/v2"
)

type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

type ipRange struct {
	start  netip.Addr
	end    netip.Addr
	asnIdx uint32
}

func main() {
	mmdbPath := flag.String("mmdb", "", "path to GeoLite2-ASN.mmdb")
	outDir := flag.String("out", ".", "output directory")
	flag.Parse()

	if *mmdbPath == "" {
		fmt.Fprintln(os.Stderr, "usage: generate -mmdb path/to/GeoLite2-ASN.mmdb")
		os.Exit(1)
	}

	db, err := maxminddb.Open(*mmdbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open mmdb: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Dedup table: (asn, org) -> index
	type asnKey struct {
		num uint32
		org string
	}
	asnTable := make(map[asnKey]uint32)
	var asnOrder []asnKey

	intern := func(num uint32, org string) uint32 {
		k := asnKey{num: num, org: org}
		if idx, ok := asnTable[k]; ok {
			return idx
		}
		idx := uint32(len(asnOrder))
		asnTable[k] = idx
		asnOrder = append(asnOrder, k)
		return idx
	}

	// Sentinel (no-ASN) entry interned at index 0 so it can fill gaps between
	// MaxMind ranges. GeoLite2-ASN does not cover unassigned IP space.
	sentinelIdx := intern(0, "")

	var ipv4Ranges, ipv6Ranges []ipRange

	for result := range db.Networks() {
		if result.Err() != nil {
			fmt.Fprintf(os.Stderr, "network iteration error: %v\n", result.Err())
			continue
		}
		var rec asnRecord
		if err := result.Decode(&rec); err != nil {
			continue
		}

		idx := intern(rec.Number, rec.Org)
		prefix := result.Prefix()
		r := ipRange{start: prefix.Addr(), end: lastAddr(prefix), asnIdx: idx}
		if prefix.Addr().Is4() {
			ipv4Ranges = append(ipv4Ranges, r)
		} else {
			ipv6Ranges = append(ipv6Ranges, r)
		}
	}

	sort.Slice(ipv4Ranges, func(i, j int) bool {
		return ipv4Ranges[i].start.Compare(ipv4Ranges[j].start) < 0
	})
	sort.Slice(ipv6Ranges, func(i, j int) bool {
		return ipv6Ranges[i].start.Compare(ipv6Ranges[j].start) < 0
	})

	ipv4Ranges = fillGaps(ipv4Ranges, netip.AddrFrom4([4]byte{0, 0, 0, 0}),
		netip.AddrFrom4([4]byte{255, 255, 255, 255}), sentinelIdx)
	ipv6Ranges = fillGaps(ipv6Ranges, netip.IPv6Unspecified(),
		netip.AddrFrom16([16]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		}), sentinelIdx)

	// IPv4 outputs
	ipv4Bin := make([]byte, len(ipv4Ranges)*4)
	ipv4Idx := make([]byte, len(ipv4Ranges)*4)
	for i, r := range ipv4Ranges {
		b := r.end.As4()
		n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		binary.LittleEndian.PutUint32(ipv4Bin[i*4:], n)
		binary.LittleEndian.PutUint32(ipv4Idx[i*4:], r.asnIdx)
	}

	// IPv6 outputs
	ipv6Bin := make([]byte, len(ipv6Ranges)*16)
	ipv6Idx := make([]byte, len(ipv6Ranges)*4)
	for i, r := range ipv6Ranges {
		b := r.end.As16()
		high := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
			uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
		low := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 |
			uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
		binary.LittleEndian.PutUint64(ipv6Bin[i*16:], high)
		binary.LittleEndian.PutUint64(ipv6Bin[i*16+8:], low)
		binary.LittleEndian.PutUint32(ipv6Idx[i*4:], r.asnIdx)
	}

	// ASN table + org strings. asn.bin layout per entry (12 bytes):
	//   asn:u32 LE | org_off:u32 LE | org_len:u16 LE | pad:u16
	var orgsTxt bytes.Buffer
	asnBin := make([]byte, len(asnOrder)*12)
	for i, k := range asnOrder {
		off := uint32(orgsTxt.Len())
		ln := uint16(len(k.org))
		orgsTxt.WriteString(k.org)
		base := i * 12
		binary.LittleEndian.PutUint32(asnBin[base:], k.num)
		binary.LittleEndian.PutUint32(asnBin[base+4:], off)
		binary.LittleEndian.PutUint16(asnBin[base+8:], ln)
		// bytes 10-11: padding (zero)
	}

	writePair := func(name string, data []byte) {
		path := filepath.Join(*outDir, name)
		if err := os.WriteFile(path, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", path, err)
			os.Exit(1)
		}
		gzPath := path + ".gz"
		var gzBuf bytes.Buffer
		gzw, _ := gzip.NewWriterLevel(&gzBuf, gzip.BestCompression)
		gzw.Write(data)
		gzw.Close()
		if err := os.WriteFile(gzPath, gzBuf.Bytes(), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write %s: %v\n", gzPath, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d bytes, gz %d bytes)\n", path, len(data), gzBuf.Len())
	}

	writePair("ipv4.bin", ipv4Bin)
	writePair("ipv4.idx", ipv4Idx)
	writePair("ipv6.bin", ipv6Bin)
	writePair("ipv6.idx", ipv6Idx)
	writePair("asn.bin", asnBin)
	writePair("orgs.txt", orgsTxt.Bytes())

	fmt.Printf("\nTotal: %d IPv4 ranges, %d IPv6 ranges, %d unique ASN entries\n",
		len(ipv4Ranges), len(ipv6Ranges), len(asnOrder))
}

// fillGaps walks a start-sorted, non-overlapping list of ranges and inserts
// sentinel entries for any gaps between them, including before the first and
// after the last. Result is still sorted by start (== sorted by end since
// non-overlapping).
func fillGaps(ranges []ipRange, min, max netip.Addr, sentinelIdx uint32) []ipRange {
	out := make([]ipRange, 0, len(ranges)*2+1)
	cursor := min
	for _, r := range ranges {
		if r.start.Compare(cursor) > 0 {
			out = append(out, ipRange{
				start:  cursor,
				end:    r.start.Prev(),
				asnIdx: sentinelIdx,
			})
		}
		out = append(out, r)
		cursor = r.end.Next()
		if !cursor.IsValid() {
			// Wrapped past max — no more space.
			return out
		}
	}
	if cursor.Compare(max) <= 0 {
		out = append(out, ipRange{
			start:  cursor,
			end:    max,
			asnIdx: sentinelIdx,
		})
	}
	return out
}

// lastAddr returns the last address in a prefix.
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
