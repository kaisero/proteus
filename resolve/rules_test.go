package resolve

import (
	"testing"

	"github.com/okaiser/go-panos-schema/config"
)

func mergeLab(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../testdata/config/panorama-merge.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// Pre-rules run root to leaf, post-rules leaf to root. The two directions are
// opposite, which is the detail most easily got wrong.
//
// Source: PAN-OS documentation, "Device Group Policies": a firewall inheriting
// from several levels "evaluates pre-rules in the order of highest to lowest
// level" and post-rules "in the order of lowest to highest level".
func TestMergedRuleOrder(t *testing.T) {
	tg, err := TargetFor(mergeLab(t), "001122334455", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	rules, err := tg.Rules(Security)
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}

	want := []string{
		"shared-pre-1",
		"top-pre",
		"middle-pre",
		"leaf-pre-1",
		"leaf-pre-2",
		"leaf-post",
		"middle-post",
		"top-post",
		"shared-post-1",
	}
	got := make([]string, len(rules))
	for i, r := range rules {
		got[i] = r.Name
	}
	if len(got) != len(want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q", i+1, got[i], want[i])
		}
	}
}

func TestMergedRulesCarryOriginAndPosition(t *testing.T) {
	tg, _ := TargetFor(mergeLab(t), "001122334455", "vsys1")
	rules, _ := tg.Rules(Security)

	for i, r := range rules {
		if r.Position != i+1 {
			t.Errorf("%s has position %d, want %d", r.Name, r.Position, i+1)
		}
	}
	byName := map[string]Rule{}
	for _, r := range rules {
		byName[r.Name] = r
	}
	if got := byName["leaf-pre-1"].Scope.String(); got != "dg:leaf" {
		t.Errorf("leaf-pre-1 scope = %q, want dg:leaf", got)
	}
	if byName["shared-pre-1"].Layer != LayerSharedPre {
		t.Errorf("shared-pre-1 layer = %v, want shared-pre", byName["shared-pre-1"].Layer)
	}
	if byName["top-post"].Layer != LayerDeviceGroupPost {
		t.Errorf("top-post layer = %v, want dg-post", byName["top-post"].Layer)
	}
	if !byName["leaf-pre-2"].Disabled {
		t.Error("leaf-pre-2 is disabled in the fixture")
	}
	if byName["shared-post-1"].Action != "deny" {
		t.Errorf("shared-post-1 action = %q, want deny", byName["shared-post-1"].Action)
	}
}

// A Panorama configuration holds no local firewall rules, so the local layer is
// empty and the caller is told so rather than left to assume.
func TestLocalLayerIsAbsentFromPanorama(t *testing.T) {
	tg, _ := TargetFor(mergeLab(t), "001122334455", "vsys1")
	rules, _ := tg.Rules(Security)
	for _, r := range rules {
		if r.Layer == LayerLocal {
			t.Errorf("%s claims the local layer, which a Panorama config cannot hold", r.Name)
		}
	}
}

// A sibling's rules must never appear.
func TestMergedRulesExcludeSiblings(t *testing.T) {
	tg, _ := TargetFor(lab(t), "007900000000003", "vsys1")
	rules, err := tg.Rules(Security)
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "Corp DC Access" {
		names := make([]string, len(rules))
		for i, r := range rules {
			names[i] = r.Name
		}
		t.Errorf("got %v, want just [Corp DC Access]", names)
	}
	if got := rules[0].Fields["source"]; len(got) != 1 || got[0] != "corp-location" {
		t.Errorf("source = %v, want [corp-location]", got)
	}
}
