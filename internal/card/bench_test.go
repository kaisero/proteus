package card

import (
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/testconfig"
)

// BenchmarkRuleCardNestedGroups builds the lookup card of a rule whose source is
// a group tree of 364 groups, out of 2,000, among 20,000 addresses and 5,000
// rules. R7: the lookup figure comes from this benchmark.
func BenchmarkRuleCardNestedGroups(b *testing.B) {
	cfg, _, err := config.Load(testconfig.Write(b, testconfig.Groups{Addrs: 20000, Rules: 5000}))
	if err != nil {
		b.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		cs, err := Find(cfg, idx, testconfig.TopRule, KindRule)
		if err != nil || len(cs) != 1 {
			b.Fatalf("Find: %d cards, %v", len(cs), err)
		}
	}
}
