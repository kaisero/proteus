package resolve

import (
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

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

// A firewall evaluates three layers: pushed shared pre-rules, its own vsys rules,
// then pushed shared post-rules. The device-group layers do not exist here.
//
// Source: PAN-OS documentation, "Device Group Policies". Not yet observed on a
// Panorama-managed firewall; see docs/specs/2026-09-27-panos-analyst-scope.md §5.3.
func TestLayersAreSharedPreLocalSharedPost(t *testing.T) {
	got := []string{LayerSharedPre.String(), LayerLocal.String(), LayerSharedPost.String()}
	if strings.Join(got, ",") != "shared-pre,local,shared-post" {
		t.Errorf("layers = %v", got)
	}
	if LayerSharedPre >= LayerLocal || LayerLocal >= LayerSharedPost {
		t.Error("layers must order shared-pre, local, shared-post")
	}
}

func TestRulesReadNegation(t *testing.T) {
	tg, err := TargetFor(loadT(t, "../../testdata/config/firewall-simulate.xml"), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := tg.Rules(Security)
	if !rules[0].NegateSource || rules[0].NegateDestination || rules[1].NegateSource {
		t.Errorf("negation = %v %v %v", rules[0].NegateSource, rules[0].NegateDestination, rules[1].NegateSource)
	}
}

func TestRulesReadWhatTheEditorShows(t *testing.T) {
	tg, err := TargetFor(loadT(t, "../../testdata/config/firewall-lookup.xml"), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := tg.Rules(Security)
	big := rules[1]
	if big.UUID != "0b3f5e2a-9d41-4c1e-8f7a-2b6c9d1ec21e" || big.Description == "" || big.LogStart != "yes" ||
		big.LogEnd != "yes" || big.LogSetting != "log-to-panorama" || big.Schedule != "business-hours" {
		t.Errorf("rule = %+v", big)
	}
	if small := rules[0]; small.Description != "" || small.LogSetting != "" || small.LogStart != "no" {
		t.Errorf("absent elements read empty: %+v", small)
	}
	objs, _ := ObjectsInScope(loadT(t, "../../testdata/config/firewall-lookup.xml"), config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, "address")
	for _, o := range objs {
		if o.Name == "net-vienna" && o.Description != "Vienna office" {
			t.Errorf("description = %q", o.Description)
		}
	}
}
