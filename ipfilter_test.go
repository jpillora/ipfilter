package ipfilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSingleIP(t *testing.T) {
	f, err := New(Options{
		AllowedIPs:     []string{"222.25.118.1"},
		BlockByDefault: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("222.25.118.1"), "[1] should be allowed")
	assert.True(t, f.Blocked("222.25.118.2"), "[2] should be blocked")
}

func TestSubnetIP(t *testing.T) {
	f, err := New(Options{
		AllowedIPs:     []string{"10.0.0.0/16"},
		BlockByDefault: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("10.0.0.1"), "[1] should be allowed")
	assert.True(t, f.Allowed("10.0.42.1"), "[2] should be allowed")
	assert.True(t, f.Blocked("10.42.0.1"), "[3] should be blocked")
}

func TestManualCountryCode(t *testing.T) {
	f, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, f.IPToISOCode("203.25.111.68"), "AU")
	assert.Equal(t, f.IPToISOCode("216.58.199.67"), "US")
}

func TestCountryCodeWhiteList(t *testing.T) {
	f, err := New(Options{
		AllowedISOCodes: []string{"AU"},
		BlockByDefault:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("203.25.111.68"), "[1] should be allowed")
	assert.True(t, f.Blocked("216.58.199.67"), "[2] should be blocked")
}

func TestCountryCodeBlackList(t *testing.T) {
	f, err := New(Options{
		BlockedISOCodes: []string{"RU", "CN"},
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("203.25.111.68"), "[1] AU should be allowed")
	assert.True(t, f.Allowed("216.58.199.67"), "[2] US should be allowed")
	assert.True(t, f.Blocked("116.31.116.51"), "[3] CN should be blocked")
}

func TestDynamicList(t *testing.T) {
	f, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, f.Allowed("116.31.116.51"), "[1] CN should be allowed")
	f.BlockISOCode("CN")
	assert.True(t, f.Blocked("116.31.116.51"), "[1] CN should be blocked")
}
