package search

import (
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
)

// BenchmarkRun is one search on a loaded, indexed configuration: what every vsys
// of every device pays per question.
func BenchmarkRun(b *testing.B) {
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		b.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Run(cfg, idx, Query{Term: "10.124.0.0/24"}); err != nil {
			b.Fatal(err)
		}
	}
}
