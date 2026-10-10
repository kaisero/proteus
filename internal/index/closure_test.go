package index

import (
	"fmt"
	"slices"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

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

// groupsOf names the groups holding an address object, at any depth.
func groupsOf(idx *Index, name string) []string {
	var out []string
	for _, g := range idx.GroupsHolding("address", name, false) {
		out = append(out, g.Name)
	}
	return out
}

// membersOf is a group's transitive members, read from the forward closure of
// every group kind that has a group of that name.
func membersOf(idx *Index, group string) []string {
	id, known := idx.in.Lookup(group)
	if !known {
		return nil
	}
	b := roaring.New()
	found := false
	for _, fam := range idx.families {
		if m, ok := fam.closure.forward[id]; ok {
			b.Or(m)
			found = true
		}
	}
	if !found {
		return nil
	}
	return idx.names(b)
}

func TestGroupsHoldingIsTransitive(t *testing.T) {
	t.Parallel()
	idx := nestedIndex(t)
	got := map[string]bool{}
	for _, g := range groupsOf(idx, "h-1") {
		got[g] = true
	}
	for _, want := range []string{"g-inner", "g-middle", "g-outer"} {
		if !got[want] {
			t.Errorf("%s missing from %v", want, got)
		}
	}
}

func TestForwardClosureIsTransitive(t *testing.T) {
	t.Parallel()
	idx := nestedIndex(t)
	got := map[string]bool{}
	for _, m := range membersOf(idx, "g-outer") {
		got[m] = true
	}
	for _, want := range []string{"g-middle", "g-inner", "h-1", "h-2"} {
		if !got[want] {
			t.Errorf("%s missing from the members of g-outer: %v", want, got)
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
	if got := groupsOf(idx, "h-1"); !slices.Equal(got, []string{"g-inner", "g-middle", "g-outer"}) {
		t.Errorf("groups of h-1 = %v, want the three groups of the cycle", got)
	}
	for _, g := range []string{"g-inner", "g-middle", "g-outer"} {
		members := membersOf(idx, g)
		if !slices.Contains(members, "h-1") || slices.Contains(members, g) {
			t.Errorf("members of %s = %v: want h-1, and not the group itself", g, members)
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
	got := groupsOf(idx, "corp-location-vienna")
	var found bool
	for _, g := range got {
		if g == "corp-location" {
			found = true
		}
	}
	if !found {
		t.Errorf("corp-location-vienna carries the tag, so it is in corp-location; got %v", got)
	}
	if members := membersOf(idx, "corp-location"); len(members) != 1 ||
		members[0] != "corp-location-vienna" {
		t.Errorf("members of corp-location = %v, want [corp-location-vienna]", members)
	}
}

// And the same dynamic group resolves differently in a sibling vsys, so the
// closure is scope-bound like everything else.
func TestDynamicClosureIsScopeBound(t *testing.T) {
	t.Parallel()
	graz := indexOf(t, "../../testdata/config/firewall-multivsys.xml", "vsys2")
	if got := membersOf(graz, "corp-location"); len(got) != 1 || got[0] != "corp-location-graz" {
		t.Errorf("in vsys2 the group holds %v, want [corp-location-graz]", got)
	}
	if got := groupsOf(graz, "corp-location-vienna"); len(got) != 0 {
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
func TestGroupsHoldingDirect(t *testing.T) {
	t.Parallel()
	idx := nestedIndex(t)
	if got := idx.GroupsHolding("address", "h-1", true); !slices.Equal(got, []Group{{"address-group", "g-inner"}}) {
		t.Errorf("direct groups of h-1 = %v, want [g-inner]", got)
	}
	if got := idx.GroupsHolding("address-group", "g-inner", true); !slices.Equal(got, []Group{{"address-group", "g-middle"}}) {
		t.Errorf("direct groups of g-inner = %v, want [g-middle]", got)
	}
	if got := idx.GroupsHolding("address", "unknown", true); got != nil {
		t.Errorf("an unknown name has no groups, got %v", got)
	}
}

func TestPrefixesOfIsExported(t *testing.T) {
	t.Parallel()
	if got := PrefixesOf("10.0.0.0/8"); len(got) != 1 {
		t.Errorf("PrefixesOf = %v", got)
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
	if got := slices.Sorted(slices.Values(membersOf(idx, "webgrp"))); !slices.Equal(got, []string{"h-api", "svc-web"}) {
		t.Errorf("members of webgrp = %v, want both kinds' members", got)
	}
	// holders unions the families it is given: dual is an address, a service
	// and an application member.
	holders := func(name string) []string {
		id, _ := idx.in.Lookup(name)
		return idx.holders(idx.families, id)
	}
	if got := slices.Sorted(slices.Values(holders("dual"))); !slices.Equal(got, []string{"g-dual-addr", "g-dual-app", "g-dual-svc"}) {
		t.Errorf("holders of dual = %v", got)
	}
	if got := holders("webgrp"); got == nil || len(got) != 0 {
		t.Errorf("holders of webgrp = %#v, want empty", got)
	}
	if got := membersOf(idx, "svc-web"); got != nil {
		t.Errorf("members of svc-web = %v, want none", got)
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

// A group kind whose member kinds the schema does not give is asked for every
// kind, so a group is never missed: here every family has lost its member
// kinds, and the address dual is held by all three groups named for it.
func TestAGroupKindWithoutMemberKindsHoldsEveryKind(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-shared-names.xml", "vsys1")
	for _, fam := range idx.families {
		fam.members = nil
	}
	want := []Group{{"address-group", "g-dual-addr"}, {"application-group", "g-dual-app"}, {"service-group", "g-dual-svc"}}
	if got := idx.GroupsHolding("address", "dual", true); !slices.Equal(got, want) {
		t.Errorf("GroupsHolding(address, dual) = %v, want %v", got, want)
	}
}

// A vsys with no tagged objects of its own resolves the shared dynamic group to
// nothing, which is the honest answer rather than the sibling's members.
func TestDynamicGroupIsEmptyWhereNothingIsTagged(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-multivsys.xml", "vsys3")
	if got := membersOf(idx, "corp-location"); len(got) != 0 {
		t.Errorf("vsys3 resolved corp-location to %v, want nothing", got)
	}
}

// A boolean filter selects by every tag it names, and a filter this build cannot
// read selects nothing rather than a guess.
func TestBooleanFilterSelectsItsMembers(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-badfilter.xml", "vsys1")
	for group, want := range map[string][]string{
		"g-and": {"h-both"},
		"g-not": {"h-a"},
		"g-bad": nil,
	} {
		if got := membersOf(idx, group); !slices.Equal(got, want) {
			t.Errorf("members of %s = %v, want %v", group, got, want)
		}
	}
}

// A dynamic group whose filter starts with a parenthesis selects its tagged
// addresses (L1).
func TestParenthesisedFilterSelectsItsMembers(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-dynamic-filter.xml", "vsys1")
	if got := slices.Sorted(slices.Values(membersOf(idx, "dag-paren"))); !slices.Equal(got, []string{"h-a", "h-b"}) {
		t.Errorf("members of dag-paren = %v, want [h-a h-b]", got)
	}
}

// Groups that hold each other share their members, each without itself, and a
// group holding a cycle holds all of it. A long cycle builds in one pass and
// costs no call depth.
func TestClosureOfComponents(t *testing.T) {
	t.Parallel()
	static := func(name, members string) resolve.Object {
		return resolve.Object{Name: name, Kind: addressGroups, Value: members}
	}
	in := NewInterner()
	c := newClosureIndex(in, []resolve.Object{
		static("a", "b"), static("b", "c, h-1"), static("c", "a, d"), static("d", "h-2"),
		static("e", "a"), static("s", "s, h-3"), static("empty", ""),
	}, nil)
	names := func(g string) []string {
		b := c.forward[in.ID(g)]
		var out []string
		for it := b.Iterator(); it.HasNext(); {
			out = append(out, in.Name(it.Next()))
		}
		slices.Sort(out)
		return out
	}
	for g, want := range map[string][]string{
		"a": {"b", "c", "d", "h-1", "h-2"},
		"b": {"a", "c", "d", "h-1", "h-2"},
		"c": {"a", "b", "d", "h-1", "h-2"},
		"d": {"h-2"},
		"e": {"a", "b", "c", "d", "h-1", "h-2"},
		"s": {"h-3"},
	} {
		if got := names(g); !slices.Equal(got, want) {
			t.Errorf("members of %s = %v, want %v", g, got, want)
		}
	}

	const n = 5000
	groups := make([]resolve.Object, n)
	for i := range n {
		groups[i] = static(fmt.Sprintf("c-%d", i), fmt.Sprintf("c-%d, h-%d", (i+1)%n, i))
	}
	long := newClosureIndex(NewInterner(), groups, nil)
	for g, b := range long.forward {
		if got := b.GetCardinality(); got != 2*n-1 || b.Contains(g) {
			t.Fatalf("a group of the long cycle holds %d members, want %d without itself", got, 2*n-1)
		}
	}
}
