//go:build !ipasn_gzip

package ipasn

import _ "embed"

//go:embed ipv4.bin
var rawIPv4Bin []byte

//go:embed ipv4.idx
var rawIPv4Idx []byte

//go:embed ipv6.bin
var rawIPv6Bin []byte

//go:embed ipv6.idx
var rawIPv6Idx []byte

//go:embed asn.bin
var rawASNBin []byte

//go:embed orgs.txt
var rawOrgsTxt []byte

func init() {
	ipv4Bin = rawIPv4Bin
	ipv4Idx = rawIPv4Idx
	ipv6Bin = rawIPv6Bin
	ipv6Idx = rawIPv6Idx
	asnBin = rawASNBin
	orgsTxt = rawOrgsTxt
}
