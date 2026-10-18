package card

import (
	"fmt"
	"testing"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/testconfig"
)

// benchCard measures lookup's card of one element of vsys1 of a generated
// configuration. The index is built once, outside the loop: the card is what is
// measured.
func benchCard(b *testing.B, g testconfig.Groups, name, kind string) {
	b.Helper()
	cfg, _, err := config.Load(testconfig.Write(b, g))
	if err != nil {
		b.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		cs, err := Find(cfg, idx, nil, name, kind)
		if err != nil || len(cs) != 1 {
			b.Fatalf("Find: %d cards, %v", len(cs), err)
		}
	}
}

// BenchmarkRuleCardNestedGroups builds the lookup card of a rule whose source is
// a group tree of 364 groups, out of 2,000, among 20,000 addresses and 5,000
// rules. R7: the lookup figure comes from this benchmark.
func BenchmarkRuleCardNestedGroups(b *testing.B) {
	benchCard(b, testconfig.Groups{Addrs: 20000, Rules: 5000}, testconfig.TopRule, KindRule)
}

// BenchmarkObjectCardDenseGroups builds the card of d-0 in the same
// configuration with groups beside the tree that each hold three others of
// them: every group is reached by many paths. R7: the lookup figure for shared
// sub-groups comes from this benchmark.
func BenchmarkObjectCardDenseGroups(b *testing.B) {
	for _, n := range []int{30, 5000} {
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			benchCard(b, testconfig.Groups{Addrs: 20000, Rules: 5000, Dense: n}, "d-0", "address-group")
		})
	}
}

// BenchmarkRuleCardGroupRing builds the card of the rule naming c-0, the first
// group of a cycle of 5,000 beside the tree: one chain as deep as the cycle is
// long.
func BenchmarkRuleCardGroupRing(b *testing.B) {
	benchCard(b, testconfig.Groups{Addrs: 20000, Rules: 5000, Ring: 5000}, "r-ring", KindRule)
}
