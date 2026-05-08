//go:build ipasn_gzip

package ipasn

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
)

//go:embed ipv4.bin.gz
var gzIPv4Bin []byte

//go:embed ipv4.idx.gz
var gzIPv4Idx []byte

//go:embed ipv6.bin.gz
var gzIPv6Bin []byte

//go:embed ipv6.idx.gz
var gzIPv6Idx []byte

//go:embed asn.bin.gz
var gzASNBin []byte

//go:embed orgs.txt.gz
var gzOrgsTxt []byte

func init() {
	ipv4Bin = gunzip(gzIPv4Bin)
	ipv4Idx = gunzip(gzIPv4Idx)
	ipv6Bin = gunzip(gzIPv6Bin)
	ipv6Idx = gunzip(gzIPv6Idx)
	asnBin = gunzip(gzASNBin)
	orgsTxt = gunzip(gzOrgsTxt)
}

func gunzip(b []byte) []byte {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		panic("ipasn: gzip reader: " + err.Error())
	}
	out, err := io.ReadAll(r)
	if err != nil {
		panic("ipasn: gzip read: " + err.Error())
	}
	return out
}
