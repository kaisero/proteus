package index

import (
	"testing"

	"github.com/okaiser/go-panos-schema/config"
)

func indexOf(t *testing.T, path, dg string) *Index {
	t.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load %s: %v", path, err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: dg})
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	return idx
}

func nestedIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../testdata/config/panorama-nested-groups.xml", "dg1")
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
	idx := indexOf(t, "../testdata/config/panorama-cyclic-groups.xml", "dg1")
	if got := idx.GroupsOf("h-1"); len(got) == 0 {
		t.Error("a cyclic group definition still has members")
	}
}

// A dynamic group must extend the chain like a static one: an address finds the
// object, the object finds the dynamic group holding it by tag, and the group
// finds the rule.
func TestDynamicGroupExtendsTheChain(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: "host_1_directory"})
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

// And the same dynamic group resolves differently in a sibling, so the closure is
// scope-bound like everything else.
func TestDynamicClosureIsScopeBound(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	graz, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: "corp-graz"})
	if err != nil {
		t.Fatal(err)
	}
	if got := graz.MembersOf("corp-location"); len(got) != 1 || got[0] != "corp-location-graz" {
		t.Errorf("in corp-graz the group holds %v, want [corp-location-graz]", got)
	}
	if got := graz.GroupsOf("corp-location-vienna"); len(got) != 0 {
		t.Errorf("the Vienna object is invisible here, got groups %v", got)
	}
}
