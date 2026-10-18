package index

import (
	"net/netip"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/resolve"
)

func benchIndex(b *testing.B) *Index {
	b.Helper()
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		b.Fatal(err)
	}
	idx, err := New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
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

func BenchmarkGroupsHolding(b *testing.B) {
	idx := indexOfB(b, "../../testdata/config/firewall-nested-groups.xml", "vsys1")
	for b.Loop() {
		_ = idx.GroupsHolding("address", "h-1", false)
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
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		b.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	for b.Loop() {
		if _, err := New(cfg, sc, resolve.Security); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrefixesOfRange(b *testing.B) {
	for b.Loop() {
		_ = prefixesOf("10.1.9.10-10.1.9.20")
	}
}

func indexOfB(b *testing.B, path, vsys string) *Index {
	b.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		b.Fatal(err)
	}
	idx, err := New(cfg, config.Scope{Sort: config.ScopeVsys, Name: vsys}, resolve.Security)
	if err != nil {
		b.Fatal(err)
	}
	return idx
}
