package main

import (
	"net/netip"
	"testing"
)

func TestFillGaps(t *testing.T) {
	addr := func(last byte) netip.Addr {
		return netip.AddrFrom4([4]byte{0, 0, 0, last})
	}
	ranges := []ipRange{
		{start: addr(10), end: addr(19), country: "US"},
		{start: addr(30), end: addr(39), country: "AU"},
	}

	got := fillGaps(ranges, addr(0), addr(49))
	want := []ipRange{
		{start: addr(0), end: addr(9), country: unknownCountry},
		{start: addr(10), end: addr(19), country: "US"},
		{start: addr(20), end: addr(29), country: unknownCountry},
		{start: addr(30), end: addr(39), country: "AU"},
		{start: addr(40), end: addr(49), country: unknownCountry},
	}

	if len(got) != len(want) {
		t.Fatalf("fillGaps() returned %d ranges, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fillGaps()[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestFillGapsEmpty(t *testing.T) {
	min := netip.MustParseAddr("::")
	max := netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	got := fillGaps(nil, min, max)
	if len(got) != 1 || got[0] != (ipRange{start: min, end: max, country: unknownCountry}) {
		t.Fatalf("fillGaps(nil) = %#v, want one unknown range", got)
	}
}

func TestCoalesceRanges(t *testing.T) {
	addr := func(last byte) netip.Addr {
		return netip.AddrFrom4([4]byte{0, 0, 0, last})
	}
	ranges := []ipRange{
		{start: addr(0), end: addr(9), country: "US"},
		{start: addr(10), end: addr(19), country: "US"},
		{start: addr(20), end: addr(29), country: "AU"},
		{start: addr(30), end: addr(39), country: "AU"},
		{start: addr(41), end: addr(49), country: "AU"},
	}

	got := coalesceRanges(ranges)
	want := []ipRange{
		{start: addr(0), end: addr(19), country: "US"},
		{start: addr(20), end: addr(39), country: "AU"},
		{start: addr(41), end: addr(49), country: "AU"},
	}
	if len(got) != len(want) {
		t.Fatalf("coalesceRanges() returned %d ranges, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("coalesceRanges()[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestCoalesceRangesEmpty(t *testing.T) {
	if got := coalesceRanges(nil); got != nil {
		t.Fatalf("coalesceRanges(nil) = %#v, want nil", got)
	}
}
