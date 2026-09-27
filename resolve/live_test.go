//go:build live

// This file runs only with -tags live. It reads a configuration exported from a
// real device and is never part of CI.
//
// It is an external test package, so it can import index, which imports resolve.
package resolve_test

import (
	"os"
	"testing"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/resolve"
)

// TestLiveConfigLoads checks the whole path against a configuration exported from
// a real device.
//
//	PANOS_LIVE_CONFIG=/path/to/export.xml go test -tags live ./resolve/
func TestLiveConfigLoads(t *testing.T) {
	path := os.Getenv("PANOS_LIVE_CONFIG")
	if path == "" {
		t.Skip("set PANOS_LIVE_CONFIG to a configuration exported from a device")
	}
	cfg, rep, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	t.Logf("PAN-OS %s (%s), %s", cfg.Version(), cfg.DetailVersion(), cfg.Platform())
	if rep.HasUnknown() {
		t.Logf("untyped: %s", rep)
	} else {
		t.Log("untyped: none")
	}

	h, err := resolve.NewHierarchy(cfg)
	if err != nil {
		t.Fatalf("NewHierarchy: %v", err)
	}
	for _, root := range h.Roots() {
		logTree(t, h, root, 1)
	}

	// Every device group has an effective policy, whether or not a firewall is
	// assigned to it. A sibling root's rules must never appear in another's.
	for _, dg := range allDeviceGroups(h) {
		rules, err := resolve.RulesForDeviceGroup(cfg, dg, resolve.Security)
		if err != nil {
			t.Fatalf("RulesForDeviceGroup %s: %v", dg, err)
		}
		names := make([]string, len(rules))
		for i, r := range rules {
			names[i] = r.Name + " (" + r.Layer.String() + ")"
		}
		t.Logf("dg %-12s effective policy: %v", dg, names)
	}

	tgs, err := resolve.Targets(cfg)
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	if len(tgs) == 0 {
		t.Log("no firewall is assigned to a device group")
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
		t.Logf("%s/%s -> dg %s (stack %s): %d effective rules, %d visible addresses",
			tg.Serial(), tg.Vsys(), tg.DeviceGroup(), tg.TemplateStack(), len(rules), len(objs))
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

// allDeviceGroups returns every device group in the tree, roots first.
func allDeviceGroups(h *resolve.Hierarchy) []string {
	var out []string
	var walk func(string)
	walk = func(dg string) {
		out = append(out, dg)
		for _, c := range h.Children(dg) {
			walk(c)
		}
	}
	for _, r := range h.Roots() {
		walk(r)
	}
	return out
}

func logTree(t *testing.T, h *resolve.Hierarchy, dg string, depth int) {
	t.Helper()
	indent := ""
	for range depth {
		indent += "  "
	}
	t.Logf("%s%s", indent, dg)
	for _, c := range h.Children(dg) {
		logTree(t, h, c, depth+1)
	}
}
