//go:build live

// This file runs only with -tags live. It reads a configuration exported from a
// real device and is never part of CI.
//
// It is an external test package, so it can import index, which imports resolve.
package resolve_test

import (
	"os"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
)

// TestLiveConfigLoads checks the whole path against a configuration exported from
// a real device.
//
//	PROTEUS_LIVE_CONFIG=/path/to/export.xml go test -tags live ./resolve/
func TestLiveConfigLoads(t *testing.T) {
	path := os.Getenv("PROTEUS_LIVE_CONFIG")
	if path == "" {
		t.Skip("set PROTEUS_LIVE_CONFIG to a configuration exported from a device")
	}
	cfg, rep, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Logf("PAN-OS %s (%s)", cfg.Version(), cfg.DetailVersion())
	if rep.HasUnknown() {
		t.Logf("untyped: %s", rep)
	} else {
		t.Log("untyped: none")
	}

	tgs, err := resolve.Targets(cfg)
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	if len(tgs) == 0 {
		t.Log("the configuration defines no vsys")
	}
	for _, tg := range tgs {
		rules, err := tg.Rules(resolve.Security)
		if err != nil {
			t.Fatalf("Rules for %s/%s: %v", tg.Serial(), tg.Vsys(), err)
		}
		objs, err := tg.Objects("address")
		if err != nil {
			t.Fatalf("Objects for %s/%s: %v", tg.Serial(), tg.Vsys(), err)
		}
		t.Logf("%s/%s: %d rules, %d visible addresses",
			tg.Serial(), tg.Vsys(), len(rules), len(objs))
		for _, r := range rules {
			t.Logf("    %2d. [%-11s %-18s] %-22s src=%v dst=%v",
				r.Position, r.Layer, r.Scope, r.Name, r.Fields["source"], r.Fields["destination"])
		}

		idx, err := index.For(cfg, tg.Scope())
		if err != nil {
			t.Fatalf("index.For %s: %v", tg.Scope(), err)
		}
		for _, o := range objs {
			refs := idx.Refs(o.Name)
			groups := idx.GroupsOf(o.Name)
			if len(refs) == 0 && len(groups) == 0 {
				continue
			}
			t.Logf("    %-24s referenced %d time(s), in groups %v", o.Name, len(refs), groups)
		}
	}
}
