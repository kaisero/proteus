package resolve

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

// A sibling vsys's rules must never appear.
func TestRulesExcludeASiblingVsys(t *testing.T) {
	t.Parallel()
	tg, _ := TargetFor(vsysLab(t), "localhost.localdomain", "vsys1")
	rules := tg.Rules(Security)
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
	if got := sibling.Rules(Security); len(got) != 0 {
		t.Errorf("vsys2 has no rules of its own, got %d", len(got))
	}
}

// Every rule carries the scope it was read from and its place in the order.
func TestFirewallRulesCarryScopeAndPosition(t *testing.T) {
	t.Parallel()
	tg, err := TargetFor(fwLab(t), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	rules := tg.Rules(Security)
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
	t.Parallel()
	tg, _ := TargetFor(fwLab(t), "localhost.localdomain", "vsys1")
	got := tg.Rules(NAT)
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
	t.Parallel()
	got := []string{LayerSharedPre.String(), LayerLocal.String(), LayerSharedPost.String()}
	if strings.Join(got, ",") != "shared-pre,local,shared-post" {
		t.Errorf("layers = %v", got)
	}
	if LayerSharedPre >= LayerLocal || LayerLocal >= LayerSharedPost {
		t.Error("layers must order shared-pre, local, shared-post")
	}
}

func TestRulesReadNegation(t *testing.T) {
	t.Parallel()
	tg, err := TargetFor(loadT(t, "../../testdata/config/firewall-simulate.xml"), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	rules := tg.Rules(Security)
	if !rules[0].NegateSource || rules[0].NegateDestination || rules[1].NegateSource {
		t.Errorf("negation = %v %v %v", rules[0].NegateSource, rules[0].NegateDestination, rules[1].NegateSource)
	}
}

func TestRulesReadWhatTheEditorShows(t *testing.T) {
	t.Parallel()
	tg, err := TargetFor(loadT(t, "../../testdata/config/firewall-lookup.xml"), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	rules := tg.Rules(Security)
	big := rules[1]
	if big.UUID != "0b3f5e2a-9d41-4c1e-8f7a-2b6c9d1ec21e" || big.Description == "" || big.LogStart != "yes" ||
		big.LogEnd != "yes" || big.LogSetting != "log-to-panorama" || big.Schedule != "business-hours" {
		t.Errorf("rule = %+v", big)
	}
	if small := rules[0]; small.Description != "" || small.LogSetting != "" || small.LogStart != "no" {
		t.Errorf("absent elements read empty: %+v", small)
	}
	objs := ObjectsInScope(loadT(t, "../../testdata/config/firewall-lookup.xml"), config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, "address")
	for _, o := range objs {
		if o.Name == "net-vienna" && o.Description != "Vienna office" {
			t.Errorf("description = %q", o.Description)
		}
	}
}

// defaultsConfig writes a configuration with the given local and pushed default
// rule entries and security rules, and returns vsys1's target.
func defaultsConfig(t *testing.T, local, pushed, rules string) *Target {
	t.Helper()
	doc := `<config version="11.2.0" detail-version="11.2.5"><shared>` +
		`<post-rulebase><default-security-rules><rules>` + pushed + `</rules></default-security-rules></post-rulebase>` +
		`</shared><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase>` +
		`<security><rules>` + rules + `</rules></security>` +
		`<default-security-rules><rules>` + local + `</rules></default-security-rules>` +
		`</rulebase></entry></vsys></entry></devices></config>`
	path := filepath.Join(t.TempDir(), "defaults.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	tg, err := TargetFor(loadT(t, path), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// The shapes measured on the lab (2026-10-08): fw01 (PAN-OS 11.2.5) stores both
// default rules with action, log settings and a uuid; fw02 (PAN-OS 12.2.3) stores
// only interzone-default.
func TestDefaultRules(t *testing.T) {
	t.Parallel()
	const (
		intra = `<entry name="intrazone-default" uuid="11111111-2222-3333-4444-555555555555">` +
			`<action>allow</action><log-start>no</log-start><log-end>yes</log-end></entry>`
		inter = `<entry name="interzone-default" uuid="66666666-7777-8888-9999-000000000000">` +
			`<action>deny</action><log-start>no</log-start><log-end>yes</log-end></entry>`
		bare = `<entry name="interzone-default"><log-end>yes</log-end></entry>`
	)
	for _, c := range []struct {
		name          string
		local, pushed string
		want          []DefaultRule
	}{
		{"none", "", "", nil},
		{"fw01 shape", intra + inter, "", []DefaultRule{
			{"intrazone-default", "allow", "local"}, {"interzone-default", "deny", "local"},
		}},
		{"fw02 shape", inter, "", []DefaultRule{{"interzone-default", "deny", "local"}}},
		{"pushed only", "", inter, []DefaultRule{{"interzone-default", "deny", "pushed"}}},
		{"local and pushed", intra, intra + inter, []DefaultRule{
			{"intrazone-default", "allow", "local"},
			{"intrazone-default", "allow", "pushed"},
			{"interzone-default", "deny", "pushed"},
		}},
		{"absent action stays empty", bare, "", []DefaultRule{{"interzone-default", "", "local"}}},
	} {
		got := defaultsConfig(t, c.local, c.pushed, "").DefaultRules()
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// A security rule reads its rule-type; an absent one is universal, the schema's
// default.
func TestRuleType(t *testing.T) {
	t.Parallel()
	rule := func(name, typ string) string {
		s := `<entry name="` + name + `"><action>allow</action>`
		if typ != "" {
			s += `<rule-type>` + typ + `</rule-type>`
		}
		return s + `</entry>`
	}
	tg := defaultsConfig(t, "", "", rule("absent", "")+rule("u", "universal")+rule("intra", "intrazone")+rule("inter", "interzone"))
	got := map[string]string{}
	for _, r := range tg.Rules(Security) {
		got[r.Name] = r.RuleType
	}
	want := map[string]string{"absent": "universal", "u": "universal", "intra": "intrazone", "inter": "interzone"}
	if !maps.Equal(got, want) {
		t.Errorf("rule types = %v, want %v", got, want)
	}
	n := tg.cfg.Digest()
	for _, seg := range []string{"devices", "entry", "vsys", "entry", "rulebase", "security", "rules", "entry", "rule-type"} {
		n = n.Child(seg)
	}
	if n == nil || n.Default != "universal" {
		t.Errorf("the schema's rule-type default is not universal: %+v", n)
	}
	nat := Targets(loadT(t, "../../testdata/config/firewall-nat.xml"))[0].Rules(NAT)
	if len(nat) == 0 {
		t.Fatal("the NAT fixture has no rules")
	}
	for _, r := range nat {
		if r.RuleType != "" {
			t.Errorf("a NAT rule has no rule-type, got %q", r.RuleType)
		}
	}
}

// A sibling vsys's default rules never appear (R5).
func TestDefaultRulesExcludeASiblingVsys(t *testing.T) {
	t.Parallel()
	vsys := func(name, rules string) string {
		return `<entry name="` + name + `"><rulebase><default-security-rules><rules>` + rules +
			`</rules></default-security-rules></rulebase></entry>`
	}
	doc := `<config version="11.2.0"><devices><entry name="localhost.localdomain"><vsys>` +
		vsys("vsys1", "") + vsys("vsys2", `<entry name="interzone-default"><action>allow</action></entry>`) +
		`</vsys></entry></devices></config>`
	path := filepath.Join(t.TempDir(), "siblings.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadT(t, path)
	for vsys, want := range map[string]int{"vsys1": 0, "vsys2": 1} {
		tg, err := TargetFor(cfg, "localhost.localdomain", vsys)
		if err != nil {
			t.Fatal(err)
		}
		if got := tg.DefaultRules(); len(got) != want {
			t.Errorf("%s: default rules %+v, want %d", vsys, got, want)
		}
	}
}
