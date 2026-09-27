package index

import (
	"testing"

	"github.com/okaiser/panos-analyst/config"
)

// indexOf builds an index for one vsys of a configuration file.
func indexOf(t *testing.T, path, vsys string) *Index {
	t.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load %s: %v", path, err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeVsys, Name: vsys})
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	return idx
}

func nestedIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../testdata/config/firewall-nested-groups.xml", "vsys1")
}

func TestGroupsOfIsTransitive(t *testing.T) {
	idx := nestedIndex(t)
	got := map[string]bool{}
	for _, g := range idx.GroupsOf("h-1") {
		got[g] = true
	}
	for _, want := range []string{"g-inner", "g-middle", "g-outer"} {
		if !got[want] {
			t.Errorf("%s missing from %v", want, got)
		}
	}
}

func TestMembersOfIsTransitive(t *testing.T) {
	idx := nestedIndex(t)
	got := map[string]bool{}
	for _, m := range idx.MembersOf("g-outer") {
		got[m] = true
	}
	for _, want := range []string{"g-middle", "g-inner", "h-1", "h-2"} {
		if !got[want] {
			t.Errorf("%s missing from MembersOf(g-outer) = %v", want, got)
		}
	}
}

// A cycle must not hang or overflow. The membership is still reported.
func TestClosureSurvivesACycle(t *testing.T) {
	idx := indexOf(t, "../testdata/config/firewall-cyclic-groups.xml", "vsys1")
	if got := idx.GroupsOf("h-1"); len(got) == 0 {
		t.Error("a cyclic group definition still has members")
	}
}

// A dynamic group must extend the chain like a static one: an address finds the
// object, the object finds the dynamic group holding it by tag, and the group
// finds the rule.
func TestDynamicGroupExtendsTheChain(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
	if err != nil {
		t.Fatal(err)
	}
	got := idx.GroupsOf("corp-location-vienna")
	var found bool
	for _, g := range got {
		if g == "corp-location" {
			found = true
		}
	}
	if !found {
		t.Errorf("corp-location-vienna carries the tag, so it is in corp-location; got %v", got)
	}
	if members := idx.MembersOf("corp-location"); len(members) != 1 ||
		members[0] != "corp-location-vienna" {
		t.Errorf("MembersOf(corp-location) = %v, want [corp-location-vienna]", members)
	}
}

// And the same dynamic group resolves differently in a sibling vsys, so the
// closure is scope-bound like everything else.
func TestDynamicClosureIsScopeBound(t *testing.T) {
	graz := indexOf(t, "../testdata/config/firewall-multivsys.xml", "vsys2")
	if got := graz.MembersOf("corp-location"); len(got) != 1 || got[0] != "corp-location-graz" {
		t.Errorf("in vsys2 the group holds %v, want [corp-location-graz]", got)
	}
	if got := graz.GroupsOf("corp-location-vienna"); len(got) != 0 {
		t.Errorf("the Vienna object is invisible here, got groups %v", got)
	}
}

// A dynamic group whose filter cannot be read has no members in the index, and the
// index says which group that is rather than leaving the caller to notice.
func TestUnparsedFiltersAreReported(t *testing.T) {
	idx := indexOf(t, "../testdata/config/firewall-badfilter.xml", "vsys1")
	got := idx.UnparsedFilters()
	if len(got) != 1 || got[0].Group != "g-bad" {
		t.Fatalf("UnparsedFilters = %+v, want just g-bad", got)
	}
	if got[0].Filter != "'a' xor 'b'" || got[0].Reason == "" {
		t.Errorf("the report must carry the filter and a reason, got %+v", got[0])
	}
	got[0].Group = "mutated"
	if idx.UnparsedFilters()[0].Group != "g-bad" {
		t.Error("UnparsedFilters returned the index's own slice; it must return a copy")
	}
}
