package index

import (
	"fmt"
	"testing"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/testconfig"
)

// benchBuild measures the index build of vsys1 of a generated configuration. The
// edges are read once, outside the loop: the build is what is measured.
func benchBuild(b *testing.B, g testconfig.Groups) {
	b.Helper()
	cfg, _, err := config.Load(testconfig.Write(b, g))
	if err != nil {
		b.Fatal(err)
	}
	edges, err := ReadEdges(cfg)
	if err != nil {
		b.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Build(cfg, edges, sc, resolve.Security); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIndexBuildNestedGroups builds the index of 20,000 addresses, 2,000
// nested address groups and 5,000 rules naming them.
func BenchmarkIndexBuildNestedGroups(b *testing.B) {
	benchBuild(b, testconfig.Groups{Addrs: 20000, Rules: 5000})
}

// BenchmarkIndexBuildGroupCycle builds the same index with one long cycle of
// groups beside the tree.
func BenchmarkIndexBuildGroupCycle(b *testing.B) {
	for _, n := range []int{2000, 5000} {
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			benchBuild(b, testconfig.Groups{Addrs: 20000, Rules: 5000, Ring: n})
		})
	}
}

// BenchmarkIndexBuildDenseGroups builds the same index with groups beside the
// tree that each hold three others of them, and a rule naming each: one
// component of many cycles.
func BenchmarkIndexBuildDenseGroups(b *testing.B) {
	for _, n := range []int{20, 30, 40} {
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			benchBuild(b, testconfig.Groups{Addrs: 20000, Rules: 5000, Dense: n})
		})
	}
}
