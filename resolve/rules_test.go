package resolve

import (
	"testing"

	"github.com/okaiser/panos-analyst/config"
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

// A sibling vsys's rules must never appear.
func TestRulesExcludeASiblingVsys(t *testing.T) {
	tg, _ := TargetFor(vsysLab(t), "localhost.localdomain", "vsys1")
	rules, err := tg.Rules(Security)
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "Corp DC Access" {
		names := make([]string, len(rules))
		for i, r := range rules {
			names[i] = r.Name
		}
		t.Fatalf("got %v, want just [Corp DC Access]", names)
	}
	if got := rules[0].Fields["source"]; len(got) != 1 || got[0] != "corp-location" {
		t.Errorf("source = %v, want [corp-location]", got)
	}
	sibling, _ := TargetFor(vsysLab(t), "localhost.localdomain", "vsys2")
	if got, _ := sibling.Rules(Security); len(got) != 0 {
		t.Errorf("vsys2 has no rules of its own, got %d", len(got))
	}
}

// Every rule carries the scope it was read from and its place in the order.
func TestFirewallRulesCarryScopeAndPosition(t *testing.T) {
	tg, err := TargetFor(fwLab(t), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	rules, err := tg.Rules(Security)
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	byName := map[string]Rule{}
	for i, r := range rules {
		if r.Position != i+1 {
			t.Errorf("%s has position %d, want %d", r.Name, r.Position, i+1)
		}
		byName[r.Name] = r
	}
	if got := byName["pushed-pre"].Scope.String(); got != "shared" {
		t.Errorf("pushed-pre scope = %q, want shared", got)
	}
	if got := byName["dc-to-home"].Scope.String(); got != "vsys:vsys1" {
		t.Errorf("dc-to-home scope = %q, want vsys:vsys1", got)
	}
	if !byName["tagged-out"].Disabled {
		t.Error("tagged-out is disabled in the fixture")
	}
	if byName["pushed-post"].Action != "deny" {
		t.Errorf("pushed-post action = %q, want deny", byName["pushed-post"].Action)
	}
}

// A device group with no firewall assigned still has an effective policy: the
// device group determines it, not the firewall.
func TestRulesForDeviceGroupWithoutAFirewall(t *testing.T) {
	cfg := mergeLab(t)
	// middle has no devices in the fixture.
	got, err := RulesForDeviceGroup(cfg, "middle", Security)
	if err != nil {
		t.Fatalf("RulesForDeviceGroup: %v", err)
	}
	want := []string{
		"shared-pre-1", "top-pre", "middle-pre",
		"middle-post", "top-post", "shared-post-1",
	}
	names := make([]string, len(got))
	for i, r := range got {
		names[i] = r.Name
	}
	if len(names) != len(want) {
		t.Fatalf("got %v\nwant %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("position %d: got %q, want %q", i+1, names[i], want[i])
		}
	}
	// The leaf's rules must not appear: a parent does not inherit from a child.
	for _, n := range names {
		if n == "leaf-pre-1" || n == "leaf-post" {
			t.Errorf("%s is a descendant's rule and must not appear", n)
		}
	}
}

func TestRulesForDeviceGroupRejectsACycle(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/panorama-cycle.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RulesForDeviceGroup(cfg, "a", Security); err == nil {
		t.Error("a cyclic hierarchy must be an error")
	}
}

// The NAT rulebase reads through the same path.
func TestNatRulebaseIsEmptyInTheFixture(t *testing.T) {
	tg, _ := TargetFor(fwLab(t), "localhost.localdomain", "vsys1")
	got, err := tg.Rules(NAT)
	if err != nil {
		t.Fatalf("Rules(NAT): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("the fixture has no NAT rules, got %d", len(got))
	}
}
