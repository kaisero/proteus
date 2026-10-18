package index

import (
	"net/netip"
	"testing"
)

func TestPrefixesOfSingleAddress(t *testing.T) {
	t.Parallel()
	got := prefixesOf("10.124.0.1")
	if len(got) != 1 || got[0].String() != "10.124.0.1/32" {
		t.Errorf("got %v, want [10.124.0.1/32]", got)
	}
}

func TestPrefixesOfNetmask(t *testing.T) {
	t.Parallel()
	got := prefixesOf("10.124.0.0/16")
	if len(got) != 1 || got[0].String() != "10.124.0.0/16" {
		t.Errorf("got %v, want [10.124.0.0/16]", got)
	}
}

// An ip-range must be covered exactly, with no address outside it.
func TestPrefixesOfRange(t *testing.T) {
	t.Parallel()
	got := prefixesOf("10.1.9.10-10.1.9.20")
	if len(got) == 0 {
		t.Fatal("a range must yield prefixes")
	}
	lo := netip.MustParseAddr("10.1.9.10")
	hi := netip.MustParseAddr("10.1.9.20")
	for _, p := range got {
		if p.Addr().Less(lo) {
			t.Errorf("%v starts below the range", p)
		}
		if hi.Less(lastAddr(p)) {
			t.Errorf("%v ends above the range", p)
		}
	}
	// Every address in the range is covered, and nothing outside it.
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"10.1.9.9", false},
		{"10.1.9.10", true},
		{"10.1.9.15", true},
		{"10.1.9.20", true},
		{"10.1.9.21", false},
	} {
		a := netip.MustParseAddr(tc.addr)
		covered := false
		for _, p := range got {
			if p.Contains(a) {
				covered = true
			}
		}
		if covered != tc.want {
			t.Errorf("%s covered = %v, want %v (prefixes %v)", tc.addr, covered, tc.want, got)
		}
	}
}

// An fqdn has no addresses in the configuration; the firewall resolves it.
func TestPrefixesOfFQDNIsEmpty(t *testing.T) {
	t.Parallel()
	if got := prefixesOf("updates.vendor.example"); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestPrefixesOfIPv6(t *testing.T) {
	t.Parallel()
	got := prefixesOf("2001:db8::/32")
	if len(got) != 1 || got[0].String() != "2001:db8::/32" {
		t.Errorf("got %v, want [2001:db8::/32]", got)
	}
}
