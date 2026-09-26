package index

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/go-panos-schema/config"
)

func labIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../testdata/config/panorama-lab.xml", "host_1_directory")
}

func TestIndexIsCachedPerScope(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeDeviceGroup, Name: "host_1_directory"}
	a, err := For(cfg, sc)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	b, _ := For(cfg, sc)
	if a != b {
		t.Error("the same scope must return the same cached index")
	}
	other, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: "corp-graz"})
	if err != nil {
		t.Fatalf("For sibling: %v", err)
	}
	if other == a {
		t.Error("a different scope must get its own index")
	}
	if other.Scope().String() != "dg:corp-graz" {
		t.Errorf("scope = %q, want dg:corp-graz", other.Scope().String())
	}
}

func TestContainingFindsEveryCoveringObject(t *testing.T) {
	idx := labIndex(t)
	names := map[string]bool{}
	for _, m := range idx.Containing(netip.MustParseAddr("10.124.0.1")) {
		names[m.Name] = true
	}
	if !names["corp-dc-vienna"] {
		t.Errorf("the /32 host object is missing: %v", names)
	}
	if !names["corp-location-vienna"] {
		t.Errorf("the covering /16 is missing: %v", names)
	}
}

// The sibling device group's objects must not appear, whatever the address.
func TestContainingIsScopeBound(t *testing.T) {
	idx := labIndex(t)
	for _, m := range idx.Containing(netip.MustParseAddr("10.125.0.1")) {
		t.Errorf("a Graz object leaked into the Vienna index: %s", m.Name)
	}
	graz := indexOf(t, "../testdata/config/panorama-lab.xml", "corp-graz")
	found := false
	for _, m := range graz.Containing(netip.MustParseAddr("10.125.0.1")) {
		if m.Name == "corp-dc-graz" {
			found = true
		}
	}
	if !found {
		t.Error("the Graz index must find its own object")
	}
}

func TestOverlappingMatchesABroaderPrefix(t *testing.T) {
	idx := labIndex(t)
	if got := idx.Overlapping(netip.MustParsePrefix("10.124.0.0/8")); len(got) == 0 {
		t.Error("a /8 overlaps the Vienna /16 and its host, so both must match")
	}
}

func TestRefsFindTheRuleThatUsesAGroup(t *testing.T) {
	idx := labIndex(t)
	got := idx.Refs("corp-location")
	if len(got) == 0 {
		t.Fatal("no edge points at corp-location, but a rule names it as its source")
	}
	var found bool
	for _, r := range got {
		if r.Field == "source" && strings.Contains(r.From, "Corp DC Access") {
			found = true
			if len(r.Candidates) < 2 {
				t.Errorf("source must carry several candidate kinds, got %v", r.Candidates)
			}
			if r.Scope.String() != "dg:host_1_directory" {
				t.Errorf("edge scope = %q, want dg:host_1_directory", r.Scope.String())
			}
		}
	}
	if !found {
		t.Errorf("the rule edge is missing from %+v", got)
	}
}

// The whole point: source and destination intersect, and the lowest bit is the
// first matching rule.
func TestFirstMatchIsTheLowestBit(t *testing.T) {
	idx := labIndex(t)
	in := idx.Interner()
	src := idx.RulesWith(Source, in.ID("corp-location"))
	dst := idx.RulesWith(Destination, in.ID("corp-dc"))
	cand := roaring.And(src, dst)
	if cand.IsEmpty() {
		t.Fatal("the lab rule names both, so the intersection cannot be empty")
	}
	rules := idx.Rules()
	first := rules[cand.Minimum()]
	if first.Name != "Corp DC Access" {
		t.Errorf("first match = %q, want Corp DC Access", first.Name)
	}
}

// A rule reached through a nested group is still found, which is what the closure
// is for.
func TestFirstMatchThroughNestedGroups(t *testing.T) {
	idx := nestedIndex(t)
	in := idx.Interner()

	// h-1 is three groups deep. Expand it, then ask which rules name any of them.
	ids := []uint32{in.ID("h-1")}
	for _, g := range idx.GroupsOf("h-1") {
		ids = append(ids, in.ID(g))
	}
	cand := idx.RulesWith(Source, ids...)
	if cand.IsEmpty() {
		t.Fatal("allow-outer names g-outer, which holds h-1 three levels down")
	}
	if got := idx.Rules()[cand.Minimum()].Name; got != "allow-outer" {
		t.Errorf("first match = %q, want allow-outer", got)
	}
}

func TestDisabledRulesAreMasked(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/panorama-merge.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: "leaf"})
	if err != nil {
		t.Fatal(err)
	}
	mask := idx.Disabled()
	if mask.IsEmpty() {
		t.Fatal("leaf-pre-2 is disabled in the fixture")
	}
	rules := idx.Rules()
	for it := mask.Iterator(); it.HasNext(); {
		if got := rules[it.Next()].Name; got != "leaf-pre-2" {
			t.Errorf("disabled rule = %q, want leaf-pre-2", got)
		}
	}
}

func TestForRejectsAnUnknownDeviceGroup(t *testing.T) {
	cfg, _, _ := config.Load("../testdata/config/panorama-lab.xml")
	if _, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: "nope"}); err == nil {
		t.Error("an unknown device group must be an error")
	}
}
