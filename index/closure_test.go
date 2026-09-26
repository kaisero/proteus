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

// A dynamic group has no static membership, so it contributes no closure edges.
func TestDynamicGroupsAreNotInTheClosure(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: "host_1_directory"})
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.MembersOf("corp-location"); len(got) != 0 {
		t.Errorf("a dynamic group has no static members, got %v", got)
	}
}
