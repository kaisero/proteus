package index

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/panos-analyst/config"
)

func labIndex(t *testing.T) *Index {
	t.Helper()
	return indexOfVsys(t, "../testdata/config/firewall-multivsys.xml", "vsys1")
}

func TestIndexIsCachedPerScope(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	a, err := For(cfg, sc)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	b, _ := For(cfg, sc)
	if a != b {
		t.Error("the same scope must return the same cached index")
	}
	other, err := For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys2"})
	if err != nil {
		t.Fatalf("For sibling: %v", err)
	}
	if other == a {
		t.Error("a different scope must get its own index")
	}
	if other.Scope().String() != "vsys:vsys2" {
		t.Errorf("scope = %q, want vsys:vsys2", other.Scope().String())
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

// The sibling vsys's objects must not appear, whatever the address.
func TestContainingIsScopeBound(t *testing.T) {
	idx := labIndex(t)
	for _, m := range idx.Containing(netip.MustParseAddr("10.125.0.1")) {
		t.Errorf("a Graz object leaked into the Vienna index: %s", m.Name)
	}
	graz := indexOfVsys(t, "../testdata/config/firewall-multivsys.xml", "vsys2")
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
			if r.Scope.String() != "vsys:vsys1" {
				t.Errorf("edge scope = %q, want vsys:vsys1", r.Scope.String())
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
	idx := indexOfVsys(t, "../testdata/config/firewall-lab.xml", "vsys1")
	mask := idx.Disabled()
	if mask.IsEmpty() {
		t.Fatal("tagged-out is disabled in the fixture")
	}
	rules := idx.Rules()
	for it := mask.Iterator(); it.HasNext(); {
		if got := rules[it.Next()].Name; got != "tagged-out" {
			t.Errorf("disabled rule = %q, want tagged-out", got)
		}
	}
}

func TestForRejectsAnUnknownDeviceGroup(t *testing.T) {
	cfg, _, _ := config.Load("../testdata/config/panorama-lab.xml")
	if _, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: "nope"}); err == nil {
		t.Error("an unknown device group must be an error")
	}
}

// A firewall's vsys is a policy scope like a device group, and its own rulebase is
// part of the effective policy.
func TestIndexForAFirewallVsys(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	rules := idx.Rules()
	if len(rules) == 0 {
		t.Fatal("a firewall vsys has its own rules")
	}

	// The whole chain on a firewall: an address, the object covering it, the group
	// holding that object, the rule naming the group.
	ms := idx.Containing(netip.MustParseAddr("198.18.10.100"))
	if len(ms) == 0 {
		t.Fatal("dc01 covers 198.18.10.100")
	}
	in := idx.Interner()
	ids := []uint32{}
	for _, m := range ms {
		ids = append(ids, in.ID(m.Name))
		for _, g := range idx.GroupsOf(m.Name) {
			ids = append(ids, in.ID(g))
		}
	}
	b := idx.RulesWith(Source, ids...)
	if b.IsEmpty() {
		t.Fatal("dc01 is in g-servers, which dc-to-home names as its source")
	}
	found := map[string]bool{}
	for it := b.Iterator(); it.HasNext(); {
		found[rules[it.Next()].Name] = true
	}
	if !found["dc-to-home"] {
		t.Errorf("got %v, want dc-to-home", found)
	}
	// The dynamic group matches the same object by tag.
	if !found["tagged-out"] {
		t.Errorf("got %v, want tagged-out through the tag filter", found)
	}
}

func TestIndexRejectsAnUnknownVsys(t *testing.T) {
	cfg, _, _ := config.Load("../testdata/config/firewall-lab.xml")
	if _, err := For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys9"}); err == nil {
		t.Error("an unknown vsys must be an error")
	}
}
