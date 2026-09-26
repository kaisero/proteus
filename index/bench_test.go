package index

import (
	"net/netip"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/go-panos-schema/config"
)

func benchIndex(b *testing.B) *Index {
	b.Helper()
	cfg, _, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		b.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: "host_1_directory"})
	if err != nil {
		b.Fatal(err)
	}
	return idx
}

func BenchmarkContaining(b *testing.B) {
	idx := benchIndex(b)
	addr := netip.MustParseAddr("10.124.0.1")
	for b.Loop() {
		_ = idx.Containing(addr)
	}
}

func BenchmarkGroupsOf(b *testing.B) {
	idx := indexOfB(b, "../testdata/config/panorama-nested-groups.xml", "dg1")
	for b.Loop() {
		_ = idx.GroupsOf("h-1")
	}
}

func BenchmarkRefs(b *testing.B) {
	idx := benchIndex(b)
	for b.Loop() {
		_ = idx.Refs("corp-location")
	}
}

func BenchmarkFirstMatch(b *testing.B) {
	idx := benchIndex(b)
	in := idx.Interner()
	src, dst := in.ID("corp-location"), in.ID("corp-dc")
	for b.Loop() {
		cand := roaring.And(idx.RulesWith(Source, src), idx.RulesWith(Destination, dst))
		if !cand.IsEmpty() {
			_ = cand.Minimum()
		}
	}
}

func BenchmarkIndexBuild(b *testing.B) {
	cfg, _, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		b.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeDeviceGroup, Name: "host_1_directory"}
	for b.Loop() {
		clearCache()
		if _, err := For(cfg, sc); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrefixesOfRange(b *testing.B) {
	for b.Loop() {
		_ = prefixesOf("10.1.9.10-10.1.9.20")
	}
}

func indexOfB(b *testing.B, path, dg string) *Index {
	b.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		b.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: dg})
	if err != nil {
		b.Fatal(err)
	}
	return idx
}
