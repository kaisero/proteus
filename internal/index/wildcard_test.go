package index

import (
	"net/netip"
	"testing"

	"github.com/okaiser/proteus/internal/resolve"
)

// As observed on fw02, PAN-OS 12.2.3 (L2): 10.88.2.1/0.0.255.0 matches
// 10.88.7.1 and 10.88.200.1, and not 10.88.7.2 or 10.89.7.1. The rule naming the
// object, directly or through a group, is a candidate for exactly the first two.
func TestWildcardMatchesByMask(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-wildcard.xml", "vsys1")
	rules := idx.Rules()
	for _, tc := range []struct {
		addr string
		hit  bool
	}{
		{"10.88.7.1", true},
		{"10.88.200.1", true},
		{"10.88.7.2", false},
		{"10.89.7.1", false},
	} {
		a := netip.MustParseAddr(tc.addr)
		for _, side := range []struct {
			f    Field
			rule string
		}{{Source, "from-wc"}, {Destination, "to-g-wc"}} {
			got := false
			for it := idx.CandidatesFor(side.f, a).Iterator(); it.HasNext(); {
				if rules[it.Next()].Name == side.rule {
					got = true
				}
			}
			if got != tc.hit {
				t.Errorf("%s %s: %s is a candidate: %v, want %v", side.f, tc.addr, side.rule, got, tc.hit)
			}
		}
		_, rep := idx.Candidates(Source, tc.addr)
		if len(rep.Unresolved) != 0 {
			t.Errorf("%s: unresolved %v; one address decides a wildcard", tc.addr, rep.Unresolved)
		}
	}
}

// A prefix query cannot decide a wildcard object, so it lists the object as
// unresolved, and only where the object may hold an address of the prefix
// (decision C1).
func TestWildcardIsUnresolvedForAPrefix(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-wildcard.xml", "vsys1")
	for _, tc := range []struct {
		prefix string
		want   bool
	}{
		{"10.88.0.0/16", true},
		{"10.88.7.0/24", true},
		{"10.88.7.0/31", true},  // holds 10.88.7.1
		{"10.88.7.2/31", false}, // 10.88.7.2 and .3
		{"10.89.0.0/16", false},
		{"0.0.0.0/0", true},
		{"2001:db8::/32", false},
	} {
		_, rep := idx.Candidates(Source, tc.prefix)
		got := false
		for _, u := range rep.Unresolved {
			if u.Code == "gap.address-wildcard" && u.Value == "wc" && u.Kind == "address" {
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("%s: wildcard unresolved %v, want %v (%v)", tc.prefix, got, tc.want, rep.Unresolved)
		}
		for _, h := range rep.Hits {
			if h.Name == "wc" {
				t.Errorf("%s: wildcard listed as a hit", tc.prefix)
			}
		}
	}
}

// Only an IPv4 wildcard is read. Any other value stays where it was, in the FQDN
// table, with its code; asking by the wildcard's own value finds the object.
func TestWildcardReadsIPv4Only(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-wildcard.xml", "vsys1")
	ws := idx.Wildcards()
	if len(ws) != 1 || ws[0].Name != "wc" || ws[0].Value != "10.88.2.1/0.0.255.0" {
		t.Fatalf("Wildcards() = %+v", ws)
	}
	ws[0].Name = "changed"
	if idx.Wildcards()[0].Name != "wc" {
		t.Error("Wildcards returned the index's own slice")
	}
	hits, un, ok := idx.addrRes.resolve("2001:db8::1/::ff00", Providers{})
	if !ok || len(hits) != 1 || hits[0].Name != "wc-v6" || len(un) != 1 || un[0].Code != "gap.fqdn-no-address" {
		t.Errorf("IPv6 wildcard: %v %v %v", hits, un, ok)
	}
	hits, un, ok = idx.addrRes.resolve("10.88.2.1/0.0.255.0", Providers{})
	if !ok || len(hits) != 1 || hits[0].Name != "wc" || len(un) != 0 {
		t.Errorf("by value: %v %v %v", hits, un, ok)
	}
	if got := idx.SearchValues("0.0.255"); len(got) != 1 || got[0].Name != "wc" {
		t.Errorf("SearchValues = %v", got)
	}
	for _, v := range []string{"10.88.2.1", "10.88.2.1/x", "x/0.0.255.0", "10.88.2.1/::ff"} {
		if _, ok := parseWildcard(resolve.Object{Name: "x", Value: v, Wildcard: true}); ok {
			t.Errorf("%s read as a wildcard", v)
		}
	}
}
