package index

import (
	"net/netip"
	"testing"

	"github.com/okaiser/proteus/internal/resolve"
)

// As observed on fw02, PAN-OS 12.2.3 (L2): 10.88.2.1/0.0.255.0 matches
// 10.88.7.1 and 10.88.200.1, and not 10.88.7.2 or 10.89.7.1. The rule naming the
// object, directly or through a group, is a candidate for exactly the first two.
// A /32 is one address and decides the object as the address does.
func TestWildcardMatchesByMask(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-wildcard.xml", "vsys1")
	rules := idx.Rules()
	for _, tc := range []struct {
		addr string
		hit  bool
	}{
		{"10.88.7.1", true},
		{"10.88.7.1/32", true},
		{"10.88.200.1", true},
		{"10.88.7.2", false},
		{"10.88.7.2/32", false},
		{"10.89.7.1", false},
	} {
		for _, side := range []struct {
			f    Field
			rule string
		}{{Source, "from-wc"}, {Destination, "to-g-wc"}} {
			got := false
			for it := candidates(idx, side.f, tc.addr).Iterator(); it.HasNext(); {
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

// MatchWildcards holds decision C1 for every caller. One address decides an
// object. A prefix, several prefixes, or one address that the caller does not
// let decide, list the object as unresolved where it may hold an address of the
// term, and the reason names the prefix it may hold addresses of.
func TestMatchWildcards(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-wildcard.xml", "vsys1")
	ps := func(s ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, p := range s {
			out = append(out, netip.MustParsePrefix(p))
		}
		return out
	}
	for _, tc := range []struct {
		prefixes   []netip.Prefix
		single     bool
		hit        bool
		unresolved string // the prefix the reason names; empty for none
	}{
		{ps("10.88.7.1/32"), true, true, ""},
		{ps("10.88.7.2/32"), true, false, ""},
		{ps("10.88.7.1/32"), false, false, "10.88.7.1/32"},
		{ps("10.88.7.1/16"), false, false, "10.88.0.0/16"},
		{ps("10.87.0.0/16", "10.88.7.0/31"), false, false, "10.88.7.0/31"},
		{ps("10.88.7.0/31", "10.88.7.2/32"), true, false, "10.88.7.0/31"},
		{ps("10.89.0.0/16"), false, false, ""},
	} {
		hits, un := idx.MatchWildcards(tc.prefixes, tc.single)
		if got := len(hits) == 1 && hits[0].Name == "wc" && hits[0].Via == "10.88.2.1/0.0.255.0"; got != tc.hit || len(hits) > 1 {
			t.Errorf("%v %v: hits %v, want a hit %v", tc.prefixes, tc.single, hits, tc.hit)
		}
		want := "wildcard object wc (10.88.2.1/0.0.255.0) matches by mask; a prefix query cannot decide it for " + tc.unresolved
		if tc.unresolved == "" && len(un) != 0 ||
			tc.unresolved != "" && (len(un) != 1 || un[0].Value != "wc" || un[0].Code != "gap.address-wildcard" || un[0].Reason != want) {
			t.Errorf("%v %v: unresolved %v, want %q", tc.prefixes, tc.single, un, tc.unresolved)
		}
	}
}

// Only an IPv4 wildcard is read. Any other value stays where it was, in the FQDN
// table, with its code; asking by the wildcard's own value finds the object.
func TestWildcardReadsIPv4Only(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-wildcard.xml", "vsys1")
	ws := idx.addrRes.wildcards
	if len(ws) != 1 || ws[0].Name != "wc" || ws[0].Value != "10.88.2.1/0.0.255.0" {
		t.Fatalf("wildcards = %+v", ws)
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
