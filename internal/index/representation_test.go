package index

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// R11. Rule sets and group closures are Roaring bitmaps, never []uint32.
//
// The rule sets are checked through the API, which hands them out as bitmaps.
// No accessor hands out a closure, so the closure's sets are checked by their
// declared types: the typed helpers below stop compiling if one becomes a
// slice. Each set is also checked for what it holds, so a bitmap left empty
// beside a slice that does the work fails too.
func TestClosureRepresentation(t *testing.T) {
	t.Parallel()
	idx := nestedIndex(t)
	outer, ok := idx.Interner().Lookup("g-outer")
	if !ok {
		t.Fatal("g-outer is not interned")
	}
	allowOuter := roaring.BitmapOf(0)

	cand, _ := idx.Candidates(Source, "10.1.1.1")
	sets := map[string]*roaring.Bitmap{
		"Candidates":               cand,
		"Candidates of an address": candidates(idx, Source, "10.1.1.2"),
		"Candidates of a name":     candidates(idx, Source, "h-1"),
		"RulesWith":                idx.RulesWith(Source, outer),
		"RulesReaching":            idx.RulesReaching(Source, "h-2"),
		"RulesWithAny":             idx.RulesWithAny(Destination),
	}
	for name, b := range sets {
		if b == nil || !b.Equals(allowOuter) {
			t.Errorf("%s = %v, want the rule allow-outer as {0}", name, b)
		}
	}
	// No rule is disabled, and none names an address literally.
	empty := map[string]*roaring.Bitmap{
		"Disabled":        idx.Disabled(),
		"RulesWithAddr":   idx.RulesWithAddr(Source, netip.MustParseAddr("10.1.1.1")),
		"RulesWithPrefix": idx.RulesWithPrefix(Source, netip.MustParsePrefix("10.1.1.0/24")),
	}
	for name, b := range empty {
		if b == nil || !b.IsEmpty() {
			t.Errorf("%s = %v, want an empty bitmap", name, b)
		}
	}

	h1, _ := idx.Interner().Lookup("h-1")
	checked := false
	for _, fam := range idx.families {
		direct := bitmapSets(fam.closure.direct)
		forward := bitmapSets(fam.closure.forward)
		ancestors := bitmapSet(fam.closure.ancestors(h1))
		reverse := bitmapSets(fam.closure.reverse)
		if fam.kind != addressGroups {
			continue
		}
		checked = true
		if got := idx.names(direct[outer]); !slices.Equal(got, []string{"g-middle"}) {
			t.Errorf("direct members of g-outer = %v", got)
		}
		if got := idx.names(forward[outer]); !slices.Equal(slices.Sorted(slices.Values(got)),
			[]string{"g-inner", "g-middle", "h-1", "h-2"}) {
			t.Errorf("forward closure of g-outer = %v", got)
		}
		if got := idx.names(ancestors); !slices.Equal(slices.Sorted(slices.Values(got)),
			[]string{"g-inner", "g-middle", "g-outer"}) {
			t.Errorf("ancestors of h-1 = %v", got)
		}
		if reverse[h1] == nil {
			t.Error("the reverse closure of h-1 is not memoised as a bitmap")
		}
	}
	if !checked {
		t.Error("the index has no address-group closure")
	}
}

// bitmapSet and bitmapSets take only bitmaps, so passing a closure's set
// through one checks its type when the test compiles.
func bitmapSet(b *roaring.Bitmap) *roaring.Bitmap { return b }

func bitmapSets(m map[uint32]*roaring.Bitmap) map[uint32]*roaring.Bitmap { return m }

// R5. No lookup resolves a name globally. The one shared dynamic group
// corp-location selects by tag, and each vsys tags its own objects, so it holds
// the Vienna network in vsys1, the Graz network in vsys2, and nothing in vsys3,
// which tags nothing, nor in shared. A rule naming it matches by the members its
// own vsys sees. First observed on a lab device (AGENTS.md R10).
func TestScopedResolution(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	vienna, graz := netip.MustParseAddr("10.124.0.9"), netip.MustParseAddr("10.125.0.9")
	for _, tc := range []struct {
		scope   config.Scope
		members []string
		holds   netip.Addr // an address the group covers here
		misses  netip.Addr // the sibling's address, which it does not
	}{
		{config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, []string{"corp-location-vienna"}, vienna, graz},
		{config.Scope{Sort: config.ScopeVsys, Name: "vsys2"}, []string{"corp-location-graz"}, graz, vienna},
		{config.Scope{Sort: config.ScopeVsys, Name: "vsys3"}, nil, netip.Addr{}, vienna},
		{config.Scope{Sort: config.ScopeShared}, nil, netip.Addr{}, graz},
	} {
		idx, err := New(cfg, tc.scope, resolve.Security)
		if err != nil {
			t.Fatalf("%s: %v", tc.scope, err)
		}
		if got := membersOf(idx, "corp-location"); !slices.Equal(got, tc.members) {
			t.Errorf("%s: corp-location holds %v, want %v", tc.scope, got, tc.members)
		}
		if tc.holds.IsValid() && !groupCovers(idx, tc.holds, "corp-location") {
			t.Errorf("%s: corp-location must cover %s", tc.scope, tc.holds)
		}
		if groupCovers(idx, tc.misses, "corp-location") {
			t.Errorf("%s: corp-location covers %s, which only a sibling scope tags", tc.scope, tc.misses)
		}
	}

	// The rule in vsys1 names the group: it is a candidate for the Vienna
	// network and not for the Graz one.
	idx, err := New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	if !ruleNames(idx, candidates(idx, Source, vienna.String()))["Corp DC Access"] {
		t.Error("vsys1: Corp DC Access must be a candidate for the Vienna network")
	}
	if ruleNames(idx, candidates(idx, Source, graz.String()))["Corp DC Access"] {
		t.Error("vsys1: Corp DC Access must not match the Graz network, which vsys2 tags")
	}
}

// groupCovers reports whether a group holds an object that contains addr.
func groupCovers(idx *Index, addr netip.Addr, group string) bool {
	for _, m := range idx.Containing(addr) {
		if slices.Contains(groupsOf(idx, m.Name), group) {
			return true
		}
	}
	return false
}
