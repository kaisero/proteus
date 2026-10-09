package index

import (
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

func labIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-multivsys.xml", "vsys1")
}

// The package keeps nothing: each call builds a new index, and the caller owns it.
func TestNewBuildsEachTime(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	a, err := New(cfg, sc, resolve.Security)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	b, _ := New(cfg, sc, resolve.Security)
	if a == b {
		t.Error("New must not return an index kept from an earlier call")
	}
	if len(a.Rules()) != len(b.Rules()) {
		t.Errorf("two builds differ: %d and %d rules", len(a.Rules()), len(b.Rules()))
	}
}

// A set builds each (scope, rulebase) index once and keeps it for its owner.
func TestSetBuildsEachIndexOnce(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet(cfg)
	if s.Config() != cfg {
		t.Error("Config must return the set's configuration")
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	a, err := s.Index(sc, resolve.Security)
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if b, _ := s.Provider(sc)(resolve.Security); a != b {
		t.Error("the same scope and rulebase must return the same index")
	}
	if nat, _ := s.Index(sc, resolve.NAT); nat == a {
		t.Error("another rulebase must get its own index")
	}
	other, err := s.Index(config.Scope{Sort: config.ScopeVsys, Name: "vsys2"}, resolve.Security)
	if err != nil {
		t.Fatalf("Index sibling: %v", err)
	}
	if other == a {
		t.Error("a different scope must get its own index")
	}
	if other.Scope().String() != "vsys:vsys2" {
		t.Errorf("scope = %q, want vsys:vsys2", other.Scope().String())
	}
	if other.refs.all == nil || &other.refs.all[0] != &a.refs.all[0] {
		t.Error("the indexes of one set must share one edge list")
	}
}

// Concurrent first calls share one build.
func TestSetIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet(cfg)
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	got := make([]*Index, 16)
	var wg sync.WaitGroup
	for i := range got {
		wg.Go(func() {
			idx, err := s.Index(sc, resolve.Security)
			if err != nil {
				t.Error(err)
			}
			got[i] = idx
		})
	}
	wg.Wait()
	for _, idx := range got {
		if idx != got[0] {
			t.Fatal("concurrent calls built more than one index")
		}
	}
}

// A failed build is not kept: the set tries again on the next call.
func TestSetDoesNotKeepAFailure(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet(cfg)
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys9"}
	if _, err := s.Index(sc, resolve.Security); err == nil {
		t.Fatal("an unknown vsys must fail")
	}
	if len(s.built) != 0 {
		t.Errorf("the set kept %d failed builds", len(s.built))
	}
	if _, err := s.Index(sc, resolve.Security); err == nil {
		t.Fatal("the second call must fail again, not return a kept result")
	}
}

// Edges read from one configuration cannot build another's index: the positions
// the index keeps would point into the wrong file.
func TestBuildRefusesEdgesOfAnotherConfiguration(t *testing.T) {
	t.Parallel()
	load := func(name string) *config.Config {
		cfg, _, err := config.Load("../../testdata/config/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg, other := load("firewall-multivsys.xml"), load("firewall-multivsys.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	edges, err := ReadEdges(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(cfg, edges, sc, resolve.Security); err == nil {
		t.Error("Build accepted edges read from another configuration")
	}
	if _, err := Build(cfg, nil, sc, resolve.Security); err == nil {
		t.Error("Build accepted no edges")
	}
	own, err := ReadEdges(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build(cfg, own, sc, resolve.Security); err != nil {
		t.Errorf("Build with its own edges: %v", err)
	}
}

func TestContainingFindsEveryCoveringObject(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	idx := labIndex(t)
	for _, m := range idx.Containing(netip.MustParseAddr("10.125.0.1")) {
		t.Errorf("a Graz object leaked into the Vienna index: %s", m.Name)
	}
	graz := indexOf(t, "../../testdata/config/firewall-multivsys.xml", "vsys2")
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
	t.Parallel()
	idx := labIndex(t)
	if got := idx.Overlapping(netip.MustParsePrefix("10.124.0.0/8")); len(got) == 0 {
		t.Error("a /8 overlaps the Vienna /16 and its host, so both must match")
	}
}

func TestRefsFindTheRuleThatUsesAGroup(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-lab.xml", "vsys1")
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

// A firewall's vsys is a policy scope like a device group, and its own rulebase is
// part of the effective policy.
func TestIndexForAFirewallVsys(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
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
	t.Parallel()
	cfg, _, _ := config.Load("../../testdata/config/firewall-lab.xml")
	if _, err := New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys9"}, resolve.Security); err == nil {
		t.Error("an unknown vsys must be an error")
	}
}

// A NAT or PBF index answers with the same matching as the security index: a
// member of a nested group reaches the rule naming the outer group.
func TestAnIndexPerRulebase(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-routing.xml")
	if err != nil {
		t.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	nat, err := New(cfg, sc, resolve.NAT)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := nat.Candidates(Source, "10.23.1.1") // net-salzburg, in west-branches, in branch-networks
	if !b.Contains(0) || b.Contains(2) {
		t.Errorf("NAT source candidates = %v", b.ToArray())
	}
	pbf, err := New(cfg, sc, resolve.PBF)
	if err != nil || pbf == nat {
		t.Fatalf("pbf index: %v", err)
	}
	if b, _ := pbf.Candidates(Destination, "10.1.10.100"); !b.Contains(1) {
		t.Errorf("PBF destination candidates = %v", b.ToArray())
	}
	sec, _ := New(cfg, sc, resolve.Security)
	if len(sec.Rules()) != 2 || len(nat.Rules()) != 4 {
		t.Errorf("rules: security %d, nat %d", len(sec.Rules()), len(nat.Rules()))
	}
}
