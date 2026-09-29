package resolve

import (
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

func fwLab(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// vsysLab is one firewall with three vsys. vsys1 and vsys2 each tag their own
// objects for the shared dynamic group corp-location; vsys3 tags nothing.
func vsysLab(t *testing.T) *config.Config {
	t.Helper()
	return loadT(t, "../../testdata/config/firewall-multivsys.xml")
}

func TestVsysesFromAFirewall(t *testing.T) {
	got, err := Vsyses(fwLab(t))
	if err != nil {
		t.Fatalf("Vsyses: %v", err)
	}
	if len(got) != 2 || got[0] != "vsys1" || got[1] != "vsys2" {
		t.Errorf("got %v, want [vsys1 vsys2]", got)
	}
}

// A firewall's own rules sit in the plain rulebase, not pre or post, and they
// evaluate after any pushed pre-rules and before any pushed post-rules.
func TestFirewallRuleOrderIncludesTheLocalLayer(t *testing.T) {
	tgs, err := Targets(fwLab(t))
	if err != nil {
		t.Fatalf("Targets: %v", err)
	}
	if len(tgs) != 2 {
		t.Fatalf("got %d targets, want one per vsys", len(tgs))
	}

	var vsys1 *Target
	for _, tg := range tgs {
		if tg.Vsys() == "vsys1" {
			vsys1 = tg
		}
	}
	if vsys1 == nil {
		t.Fatal("vsys1 not found")
	}
	if got := vsys1.Scope().String(); got != "vsys:vsys1" {
		t.Errorf("scope = %q, want vsys:vsys1", got)
	}

	rules, err := vsys1.Rules(Security)
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	want := []struct {
		name  string
		layer Layer
	}{
		{"pushed-pre", LayerSharedPre},
		{"identity-redistribution", LayerLocal},
		{"dc-to-home", LayerLocal},
		{"tagged-out", LayerLocal},
		{"pushed-post", LayerSharedPost},
	}
	if len(rules) != len(want) {
		names := make([]string, len(rules))
		for i, r := range rules {
			names[i] = r.Name + "/" + r.Layer.String()
		}
		t.Fatalf("got %v, want %d rules", names, len(want))
	}
	for i, w := range want {
		if rules[i].Name != w.name {
			t.Errorf("position %d: got %q, want %q", i+1, rules[i].Name, w.name)
		}
		if rules[i].Layer != w.layer {
			t.Errorf("%s layer = %v, want %v", rules[i].Name, rules[i].Layer, w.layer)
		}
	}
}

// One vsys must not see another's rules or objects.
func TestVsysesAreIsolated(t *testing.T) {
	tgs, _ := Targets(fwLab(t))
	for _, tg := range tgs {
		rules, err := tg.Rules(Security)
		if err != nil {
			t.Fatal(err)
		}
		objs, err := tg.Objects("address")
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, r := range rules {
			names[r.Name] = true
		}
		objNames := map[string]bool{}
		for _, o := range objs {
			objNames[o.Name] = true
		}
		switch tg.Vsys() {
		case "vsys1":
			if names["dmz-out"] {
				t.Error("vsys1 must not see vsys2's rule")
			}
			if objNames["net-dmz"] {
				t.Error("vsys1 must not see vsys2's object")
			}
			if !objNames["shared-dns"] {
				t.Error("vsys1 must inherit the shared object")
			}
		case "vsys2":
			if names["dc-to-home"] {
				t.Error("vsys2 must not see vsys1's rule")
			}
			if !objNames["net-dmz"] {
				t.Error("vsys2 must see its own object")
			}
		}
	}
}
