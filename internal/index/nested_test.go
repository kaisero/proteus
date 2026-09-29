package index

import (
	"net/netip"
	"testing"
)

// The full chain: a raw IP value, to the object whose value covers it, to the
// group holding that object, to the group holding that group, to the rule that
// names the outermost group.
//
// This is the lookup a policy question actually needs, and every step of it has to
// compose. The fixture nests three levels deep on purpose.
func TestNestedChainFromValueToRule(t *testing.T) {
	t.Parallel()
	idx := nestedIndex(t)
	in := idx.Interner()

	// 1. a raw IP value
	addr := netip.MustParseAddr("10.1.1.1")

	// 2. which objects cover it
	var objs []string
	for _, m := range idx.Containing(addr) {
		objs = append(objs, m.Name)
	}
	t.Logf("1. %s is covered by %v", addr, objs)
	if len(objs) == 0 {
		t.Fatal("no object covers the address")
	}

	// 3. which groups hold those objects, transitively
	ids := []uint32{}
	var groups []string
	for _, o := range objs {
		ids = append(ids, in.ID(o))
		for _, g := range idx.GroupsOf(o) {
			groups = append(groups, g)
			ids = append(ids, in.ID(g))
		}
	}
	t.Logf("2. those objects sit in groups %v", groups)
	if len(groups) < 3 {
		t.Fatalf("expected three levels of nesting, got %v", groups)
	}

	// 4. which rules name the object or any of its groups
	cand := idx.RulesWith(Source, ids...)
	if cand.IsEmpty() {
		t.Fatal("no rule reached through the nesting")
	}
	rules := idx.Rules()
	t.Logf("3. first matching rule: %s", rules[cand.Minimum()].Name)
	if got := rules[cand.Minimum()].Name; got != "allow-outer" {
		t.Errorf("first match = %q, want allow-outer", got)
	}

	// 5. and the reverse: what points at the outermost group
	for _, r := range idx.Refs("g-outer") {
		t.Logf("4. %s/%s points at g-outer", r.Scope, r.Field)
	}
}
