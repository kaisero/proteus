package mcp

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/store"
)

// retained loads a snapshot through a new cache, builds the three rulebase
// indexes of each vsys, and returns the bytes that stay live while the cache
// holds them. The schema digest is loaded once per process before, so it is
// not counted here: the cache sizes it apart, as digestBytes.
func retained(b *testing.B, sn store.Snapshot) uint64 {
	b.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	c := newCache(1<<40, 1, 1, true)
	ld, err := c.bind(context.Background()).Config(sn)
	if err != nil {
		b.Fatal(err)
	}
	for _, v := range resolve.Vsyses(ld.Config) {
		for _, rb := range []resolve.Rulebase{resolve.Security, resolve.NAT, resolve.PBF} {
			if _, err := ld.Indexes.Index(config.Scope{Sort: config.ScopeVsys, Name: v}, rb); err != nil {
				b.Fatal(err)
			}
		}
	}

	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(c)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

// R7. The cache sizes a snapshot's configuration at configFactor times its
// file's bytes, and docs/guides/mcp.md gives that figure for max_cache. This
// measures it on the multi-vsys fixture: the configuration, its edges and the
// security, NAT and PBF index of every vsys, live after a garbage collection,
// per byte of the file. It reports the factor as retained-B/file-B.
func BenchmarkCacheRetention(b *testing.B) {
	const path = "../../testdata/config/firewall-multivsys.xml"
	doc, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	st, err := store.Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	sn, err := st.Write(store.Meta{Device: "fw01", Host: "fw01.example.test", Serial: "000000000001"},
		map[string][]byte{store.ConfigDoc: doc}, 1)
	if err != nil {
		b.Fatal(err)
	}
	retained(b, sn) // warm the process-wide digest and schema tables

	var total uint64
	n := 0
	for b.Loop() {
		total += retained(b, sn)
		n++
	}
	b.ReportMetric(float64(total)/float64(n)/float64(len(doc)), "retained-B/file-B")
}
