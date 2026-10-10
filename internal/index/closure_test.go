package index

import (
	"slices"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// indexOf builds an index for one vsys of a configuration file.
func indexOf(t *testing.T, path, vsys string) *Index {
	t.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load %s: %v", path, err)
	}
	idx, err := New(cfg, config.Scope{Sort: config.ScopeVsys, Name: vsys}, resolve.Security)
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	return idx
}

func nestedIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-nested-groups.xml", "vsys1")
}

func TestGroupsOfIsTransitive(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// A cycle must not hang or overflow, and the answer must not depend on the group
// the build starts from: g-inner holds h-1 and g-outer, g-outer holds g-middle,
// g-middle holds g-inner. Every group of the cycle holds h-1, so the rule on
// g-outer is a candidate for 10.1.1.1 on every build. Map order picks the start;
// run with -count to try many.
func TestClosureSurvivesACycle(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-cyclic-groups.xml", "vsys1")
	if got := slices.Sorted(slices.Values(idx.GroupsOf("h-1"))); !slices.Equal(got, []string{"g-inner", "g-middle", "g-outer"}) {
		t.Errorf("GroupsOf(h-1) = %v, want the three groups of the cycle", got)
	}
	for _, g := range []string{"g-inner", "g-middle", "g-outer"} {
		members := idx.MembersOf(g)
		if !slices.Contains(members, "h-1") || slices.Contains(members, g) {
			t.Errorf("MembersOf(%s) = %v: want h-1, and not the group itself", g, members)
		}
	}
	b, _ := idx.Candidates(Source, "10.1.1.1")
	if !ruleNames(idx, b)["allow-outer"] {
		t.Error("allow-outer is missing for 10.1.1.1")
	}
}

// A dynamic group must extend the chain like a static one: an address finds the
// object, the object finds the dynamic group holding it by tag, and the group
// finds the rule.
func TestDynamicGroupExtendsTheChain(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
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
	t.Parallel()
	graz := indexOf(t, "../../testdata/config/firewall-multivsys.xml", "vsys2")
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
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-badfilter.xml", "vsys1")
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

// Direct groups answer "which group do I edit": only the one naming the member.
func TestDirectGroupsOf(t *testing.T) {
	t.Parallel()
	idx := nestedIndex(t)
	if got := idx.DirectGroupsOf("h-1"); len(got) != 1 || got[0] != "g-inner" {
		t.Errorf("DirectGroupsOf(h-1) = %v, want [g-inner]", got)
	}
	if got := idx.DirectGroupsOf("g-inner"); len(got) != 1 || got[0] != "g-middle" {
		t.Errorf("DirectGroupsOf(g-inner) = %v, want [g-middle]", got)
	}
	if got := idx.DirectGroupsOf("unknown"); got != nil {
		t.Errorf("an unknown name has no groups, got %v", got)
	}
}

func TestPrefixesOfIsExported(t *testing.T) {
	t.Parallel()
	if got := PrefixesOf("10.0.0.0/8"); len(got) != 1 {
		t.Errorf("PrefixesOf = %v", got)
	}
}

// A name the index never saw, and a name that is not a group, have no members.
func TestMembersOfANonGroupIsEmpty(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-nested-groups.xml", "vsys1")
	for _, name := range []string{"no-such-group", "h-1"} {
		if got := idx.MembersOf(name); got != nil {
			t.Errorf("MembersOf(%q) = %v, want nil", name, got)
		}
	}
}

// An address group and a service group named webgrp are two groups: each holds
// its own members, and a field reaches only the groups it can name.
func TestEachGroupKindHasItsOwnClosure(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-shared-names.xml", "vsys1")
	for _, tc := range []struct {
		kind, name string
		direct     bool
		want       []Group
	}{
		{"service", "svc-web", false, []Group{{"service-group", "webgrp"}}},
		{"service", "svc-web", true, []Group{{"service-group", "webgrp"}}},
		{"address", "h-api", false, []Group{{"address-group", "webgrp"}}},
		{"address", "h-web", true, []Group{{"address-group", "web"}}},
		{"tag", "web", false, nil},
		{"address", "nothing", false, nil},
	} {
		if got := idx.GroupsHolding(tc.kind, tc.name, tc.direct); !slices.Equal(got, tc.want) {
			t.Errorf("GroupsHolding(%s, %s, %v) = %v, want %v", tc.kind, tc.name, tc.direct, got, tc.want)
		}
	}
	for _, tc := range []struct {
		f     Field
		value string
		rule  string
		want  bool
	}{
		{Service, "tcp/8443", "svc-webgrp", true},
		{Source, "10.88.4.20", "src-webgrp", true},
		{Source, "svc-web", "src-webgrp", false},
		{Service, "h-api", "svc-webgrp", false},
		{Destination, "h-web", "to-web", true},
	} {
		b, _ := idx.Candidates(tc.f, tc.value)
		if got := ruleNames(idx, b)[tc.rule]; got != tc.want {
			t.Errorf("Candidates(%s, %s) has %s: %v, want %v", tc.f, tc.value, tc.rule, got, tc.want)
		}
	}
	if got := slices.Sorted(slices.Values(idx.MembersOf("webgrp"))); !slices.Equal(got, []string{"h-api", "svc-web"}) {
		t.Errorf("MembersOf(webgrp) = %v, want both kinds' members", got)
	}
	if got := idx.DirectGroupsOf("svc-web"); !slices.Equal(got, []string{"webgrp"}) {
		t.Errorf("DirectGroupsOf(svc-web) = %v", got)
	}
	if got := idx.MembersOf("svc-web"); got != nil {
		t.Errorf("MembersOf(svc-web) = %v, want none", got)
	}
}

// The member kinds of each group kind come from the schema: the group's field
// that can name the group kind itself.
func TestGroupMemberKindsComeFromTheSchema(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-shared-names.xml")
	if err != nil {
		t.Fatal(err)
	}
	for group, want := range map[string][]string{
		"address-group":     {"address", "address-group"},
		"service-group":     {"service", "service-group"},
		"application-group": {"application", "application-container", "application-filter", "application-group"},
		"no-such-group":     nil,
	} {
		if got := memberKinds(cfg, group); !slices.Equal(got, want) {
			t.Errorf("memberKinds(%s) = %v, want %v", group, got, want)
		}
	}
}
