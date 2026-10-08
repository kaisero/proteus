package securitypolicy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/simulate"
)

// env loads one fixture's vsys1, with the fw01 forwarding table when zones is set.
func env(t *testing.T, fixture string, zones bool) *simulate.Env {
	t.Helper()
	return envPath(t, "../../../testdata/config/"+fixture, zones)
}

// envPath is env for a configuration at any path.
func envPath(t *testing.T, path string, zones bool) *simulate.Env {
	t.Helper()
	return &simulate.Env{Load: func(_, vsys string) (simulate.Target, error) {
		cfg, rep, err := config.Load(path)
		if err != nil {
			return simulate.Target{}, err
		}
		idx, err := index.For(cfg, config.Scope{Sort: config.ScopeVsys, Name: vsys})
		if err != nil {
			return simulate.Target{}, err
		}
		var p index.Providers
		if zones {
			i, _ := os.Open("../../../testdata/opdata/fw01-interface-all.xml")
			f, _ := os.Open("../../../testdata/opdata/fw01-advanced-routing-fib.xml")
			defer i.Close()
			defer f.Close()
			z, err := index.NewZoneSnapshot(time.Now(), "fw01", i, f)
			if err != nil {
				t.Fatal(err)
			}
			p.Zones = z
		}
		var notes []string
		if rep.VersionGap != "" {
			notes = append(notes, rep.VersionGap)
		}
		return simulate.Target{Config: cfg, Index: idx, Providers: p, Notes: notes}, nil
	}}
}

func ep(s string) simulate.Endpoint { return simulate.Addr(netip.MustParseAddr(s)) }

func run(t *testing.T, e *simulate.Env, f simulate.Flow) (simulate.Run, Verdict) {
	t.Helper()
	if f.Protocol == "" {
		f.Protocol = "tcp"
	}
	r, err := Simulation{}.Run(context.Background(), e, simulate.Input{Flow: f, Device: "fw01", Vsys: "vsys1"})
	if err != nil {
		t.Fatal(err)
	}
	return r, r.Output.(Verdict)
}

func first(v Verdict) string {
	if v.Rule == nil {
		return "none"
	}
	return v.Rule.Name
}

func stage(r simulate.Run, slug string) simulate.Stage {
	for _, s := range r.Stages {
		if s.Slug == slug {
			return s
		}
	}
	return simulate.Stage{}
}

func TestGivenZones(t *testing.T) {
	t.Parallel()
	r, v := run(t, env(t, "firewall-zones.xml", false), simulate.Flow{
		Source: ep("10.1.0.5"), Destination: ep("10.2.0.5"), FromZone: "inside", ToZone: "dmz",
	})
	if first(v) != "from-inside" {
		t.Errorf("first match = %s", first(v))
	}
	if stage(r, "derive-zones").Fidelity.Level() != "exact" || v.Zones.Source != "given" {
		t.Errorf("given zones are exact: %s %s", stage(r, "derive-zones").Fidelity, v.Zones.Source)
	}
	if got := r.Fidelity.String(); got != "overmatch; not evaluated: service, application" {
		t.Errorf("overall = %s", got)
	}
	var prev uint64 = 1 << 62
	for _, s := range r.Stages {
		if s.State.Candidates > prev {
			t.Errorf("%s grew the candidate set", s.Slug)
		}
		prev = s.State.Candidates
	}
}

func TestZonesFromTheConfiguration(t *testing.T) {
	t.Parallel()
	r, v := run(t, env(t, "firewall-zones.xml", false), simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.2.0.5")})
	if v.Zones.Source != "configuration" || stage(r, "derive-zones").Fidelity.Level() != "inferred" {
		t.Errorf("zones %+v, fidelity %s", v.Zones, stage(r, "derive-zones").Fidelity)
	}
	if len(v.Zones.From) == 0 || v.Zones.From[0] != "inside" {
		t.Errorf("from = %v", v.Zones.From)
	}
}

// Zones derived from the stored forwarding table; the disabled rule never wins.
func TestZonesFromTheForwardingTable(t *testing.T) {
	t.Parallel()
	r, v := run(t, env(t, "firewall-fw01-zones.xml", true), simulate.Flow{Source: ep("198.18.11.5"), Destination: ep("198.18.10.5")})
	if first(v) != "client-to-server" {
		t.Errorf("first match = %s; stages %+v", first(v), r.Stages)
	}
	if v.Zones.Source != "forwarding table" || strings.Join(v.Zones.From, ",") != "client" || strings.Join(v.Zones.To, ",") != "server" {
		t.Errorf("zones = %+v", v.Zones)
	}
	if !v.Relevance.Known || !v.Relevance.Relevant {
		t.Errorf("relevance = %+v", v.Relevance)
	}
	if r.Fidelity.Level() != "inferred" {
		t.Errorf("overall = %s", r.Fidelity)
	}
}

func TestRelevance(t *testing.T) {
	t.Parallel()
	_, v := run(t, env(t, "firewall-fw01-zones.xml", true), simulate.Flow{Source: ep("8.8.8.8"), Destination: ep("1.1.1.1")})
	if !v.Relevance.Known || v.Relevance.Relevant {
		t.Errorf("only default routes: %+v", v.Relevance)
	}
	_, v = run(t, env(t, "firewall-zones.xml", false), simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.2.0.5")})
	if v.Relevance.Known {
		t.Errorf("no forwarding table, no relevance: %+v", v.Relevance)
	}
}

func TestNegatedSource(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-simulate.xml", false)
	if _, v := run(t, e, simulate.Flow{Source: ep("10.0.0.2"), Destination: ep("10.9.9.9")}); first(v) != "deny-untrusted" {
		t.Errorf("an address outside the negated list matches: %s", first(v))
	}
	if _, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.9.9.9")}); first(v) != "anything" {
		t.Errorf("the listed address does not match the negated rule: %s", first(v))
	}
}

func TestFQDN(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-simulate.xml", false)
	resolved := simulate.Endpoint{Name: "www.example.com", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.10")}, Resolved: true}
	r, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: resolved})
	names := ruleNames(v)
	if !strings.Contains(names, "to-web-by-name") || !strings.Contains(names, "to-web-by-address") {
		t.Errorf("a resolved FQDN matches by name and by address: %s", names)
	}
	if stage(r, "resolve-destination").Fidelity.Level() != "inferred" {
		t.Errorf("DNS from this machine is inferred: %s", stage(r, "resolve-destination").Fidelity)
	}
	r, v = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: simulate.Endpoint{Name: "www.example.com"}})
	if names := ruleNames(v); !strings.Contains(names, "to-web-by-name") || strings.Contains(names, "to-web-by-address") {
		t.Errorf("an unresolved FQDN matches FQDN objects only: %s", names)
	}
	if r.Fidelity.Level() != "undermatch" {
		t.Errorf("overall = %s", r.Fidelity)
	}
	if !strings.Contains(r.Fidelity.String(), "resolved to no address") || stage(r, "derive-zones").Fidelity.Level() != "overmatch" {
		t.Errorf("fidelity = %s; zones %s", r.Fidelity, stage(r, "derive-zones").Fidelity)
	}
}

func TestServicesByPort(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-simulate.xml", false)
	r, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.5.0.1"), DestPort: 8443})
	names := ruleNames(v)
	for _, want := range []string{"custom-port", "app-default", "predefined-https"} {
		if !strings.Contains(names, want) {
			t.Errorf("%s missing from %s", want, names)
		}
	}
	svc := stage(r, "match-service").Fidelity
	if svc.Level() != "overmatch" || !strings.Contains(svc.String(), "app-default, predefined-https") {
		t.Errorf("match-service = %s", svc)
	}
	_, v = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.5.0.1"), DestPort: 9999})
	if strings.Contains(ruleNames(v), "custom-port") || first(v) != "app-default" {
		t.Errorf("a port no service holds drops custom-port: %s", ruleNames(v))
	}
	r, _ = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.5.0.1"), Protocol: "icmp", DestPort: 8})
	if !strings.Contains(stage(r, "match-service").Fidelity.String(), "not evaluated: service") {
		t.Errorf("icmp has no service port: %s", stage(r, "match-service").Fidelity)
	}
}

func TestURLCategories(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-simulate.xml", false)
	r, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.6.0.1"), URL: "shop.example.com/cart"})
	if first(v) != "shop" || !strings.Contains(ruleNames(v), "social") {
		t.Errorf("custom category matches, PAN-DB category kept: %s", ruleNames(v))
	}
	if f := stage(r, "match-url").Fidelity; f.Level() != "overmatch" || !strings.Contains(f.String(), "social") {
		t.Errorf("match-url = %s", f)
	}
	_, v = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.6.0.1"), URL: "other.example.org"})
	if strings.Contains(ruleNames(v), "shop") || first(v) != "social" {
		t.Errorf("another URL drops shop: %s", ruleNames(v))
	}
	r, _ = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.6.0.1")})
	if !strings.Contains(stage(r, "match-url").Fidelity.String(), "not evaluated: url category") {
		t.Errorf("without a URL, category is not evaluated: %s", stage(r, "match-url").Fidelity)
	}
	r, _ = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.9.9.8")})
	if stage(r, "match-url").Fidelity.Level() != "exact" {
		t.Errorf("no candidate names a category: %s", stage(r, "match-url").Fidelity)
	}
}

func TestAnUnrecognisedValueIsUnderMatch(t *testing.T) {
	t.Parallel()
	r, v := run(t, env(t, "firewall-version-12.2.xml", false), simulate.Flow{Source: ep("198.18.10.100"), Destination: ep("198.18.1.5")})
	if r.Fidelity.Level() != "undermatch" || !strings.Contains(r.Fidelity.String(), "12.2.0") {
		t.Errorf("a version gap is undermatch: %s", r.Fidelity)
	}
	if first(v) != "dc-to-home" {
		t.Errorf("first match = %s", first(v))
	}
}

func TestNoMatch(t *testing.T) {
	t.Parallel()
	r, v := run(t, env(t, "firewall-zones.xml", false), simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.2.0.5"), FromZone: "dmz", ToZone: "inside"})
	if v.Rule != nil || v.Default != "interzone-default" || v.DefaultAction != "deny" || v.DefaultSource != "built-in" ||
		stage(r, "first-match").Detail != "no enabled rule matches; default rule interzone-default (deny), built-in" {
		t.Errorf("got %s, default %s: %s", first(v), v.Default, stage(r, "first-match").Detail)
	}
	_, v = run(t, env(t, "firewall-zones.xml", false), simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.2.0.5"), User: "alice"})
	_ = v
}

func TestDescribeAndStages(t *testing.T) {
	t.Parallel()
	s := Simulation{}
	if s.Kind() != "policy" || s.Describe() == "" {
		t.Error("kind and description")
	}
	if got := strings.Join(s.Stages(), ","); got != "resolve-source,resolve-destination,derive-zones,match-service,match-url,drop-disabled,order,first-match" {
		t.Errorf("stages = %s", got)
	}
}

func TestALoadFailureNamesTheDevice(t *testing.T) {
	t.Parallel()
	e := &simulate.Env{Load: func(string, string) (simulate.Target, error) { return simulate.Target{}, errors.New("no snapshot") }}
	_, err := Simulation{}.Run(context.Background(), e, simulate.Input{Device: "fw09", Vsys: "vsys1"})
	if err == nil || !strings.Contains(err.Error(), "fw09/vsys1") {
		t.Errorf("err = %v", err)
	}
}

func ruleNames(v Verdict) string {
	var out []string
	for _, r := range v.Candidates {
		out = append(out, r.Name)
	}
	return strings.Join(out, ",")
}

// A rule without a category matches every URL; a rule without a service cannot be
// judged on a port, so it stays and the stage says so.
func TestAbsentFields(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-simulate.xml", false)
	_, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.7.0.1"), URL: "shop.example.com"})
	if first(v) != "anything" {
		t.Errorf("a rule without a category matches a URL: %s", ruleNames(v))
	}
	r, v := run(t, env(t, "firewall-lab.xml", false), simulate.Flow{Source: ep("198.18.10.100"), Destination: ep("198.18.1.5"), DestPort: 443})
	if first(v) != "dc-to-home" || !strings.Contains(stage(r, "match-service").Fidelity.String(), "absent") {
		t.Errorf("a rule without a service stays: %s; %s", ruleNames(v), stage(r, "match-service").Fidelity)
	}
}

// A source placed only by a default route leaves the source zone open: a default
// route does not say where a packet arrives.
func TestADefaultRouteDoesNotPlaceTheSource(t *testing.T) {
	t.Parallel()
	r, v := run(t, env(t, "firewall-fw01-zones.xml", true), simulate.Flow{Source: ep("8.8.8.8"), Destination: ep("198.18.10.5")})
	if len(v.Zones.From) != 0 || strings.Join(v.Zones.To, ",") != "server" {
		t.Errorf("zones = %+v", v.Zones)
	}
	f := stage(r, "derive-zones").Fidelity
	if !strings.Contains(f.String(), "not evaluated: source zone") {
		t.Errorf("derive-zones = %s", f)
	}
	if first(v) != "client-to-server" {
		t.Errorf("with the source zone open, client-to-server stays a candidate: %s", ruleNames(v))
	}
	if !viaDefault("ethernet1/1 via default 0.0.0.0/0") || viaDefault("ethernet1/3 via default 198.18.11.0/24") || viaDefault("") {
		t.Error("viaDefault")
	}
}

// rule-type with single and known zones: each type with equal and with different
// zones.
func TestRuleTypeWithGivenZones(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-ruletype.xml", false)
	for _, c := range []struct {
		from, to string
		want     string // the candidates, in order
	}{
		{"inside", "inside", "intra-inside"}, // intrazone, equal: to is not read
		{"inside", "dmz", "inter-inside"},    // intrazone, different: no; interzone, different: yes
		{"dmz", "dmz", ""},                   // intrazone needs from in rule.from
		{"out", "out", "universal-out"},      // universal, equal
		{"out", "dmz", "universal-out"},      // universal, different
		{"dmz", "inside", ""},                // nothing names dmz as from
	} {
		r, v := run(t, e, simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.2.0.5"), FromZone: c.from, ToZone: c.to})
		if got := ruleNames(v); got != c.want {
			t.Errorf("%s -> %s: candidates %q, want %q", c.from, c.to, got, c.want)
		}
		if lvl := stage(r, "derive-zones").Fidelity.Level(); lvl != "exact" {
			t.Errorf("%s -> %s: derive-zones = %s", c.from, c.to, lvl)
		}
	}
}

// Without single and known zones a rule of another type stays a candidate, and the
// zone stage says so.
func TestRuleTypeWithoutKnownZones(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-ruletype.xml", false)
	for _, c := range []struct {
		name   string
		flow   simulate.Flow
		want   string
		reason string
	}{
		{
			"derived inside to out",
			simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.3.0.5")},
			"intra-inside,inter-inside", "the zones are derived",
		},
		{
			"derived inside to inside",
			simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.1.0.6")},
			"intra-inside,inter-inside", "the zones are derived",
		},
		{
			"given but undefined",
			simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.2.0.5"), FromZone: "nowhere", ToZone: "dmz"},
			"intra-inside,inter-inside", "a given zone is not defined",
		},
	} {
		r, v := run(t, e, c.flow)
		if got := ruleNames(v); got != c.want {
			t.Errorf("%s: candidates %q, want %q", c.name, got, c.want)
		}
		f := stage(r, "derive-zones").Fidelity
		// Derived zones are inferred, which is weaker than overmatch; the reason stays.
		if f.Level() == "exact" || !strings.Contains(f.String(), c.reason) || !strings.Contains(f.String(), "intra-inside, inter-inside") {
			t.Errorf("%s: derive-zones = %s", c.name, f)
		}
	}
}

// ruleTypeWith is the rule-type fixture with default rule entries added, local
// under the vsys rulebase and pushed under the shared post-rulebase.
func ruleTypeWith(t *testing.T, local, pushed string) *simulate.Env {
	t.Helper()
	src, err := os.ReadFile("../../../testdata/config/firewall-ruletype.xml")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(src), "<shared/>",
		"<shared><post-rulebase><default-security-rules><rules>"+pushed+"</rules></default-security-rules></post-rulebase></shared>", 1)
	doc = strings.Replace(doc, "</security>",
		"</security><default-security-rules><rules>"+local+"</rules></default-security-rules>", 1)
	path := filepath.Join(t.TempDir(), "defaults.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return envPath(t, path, false)
}

func entry(name, action string) string {
	if action == "" {
		return `<entry name="` + name + `"><log-end>yes</log-end></entry>`
	}
	return `<entry name="` + name + `"><action>` + action + `</action></entry>`
}

// With no candidate and single, known zones, the default rule for the zone pair
// decides, with the action its sources give.
func TestDefaultRuleDecides(t *testing.T) {
	t.Parallel()
	const intra, inter = "intrazone-default", "interzone-default"
	for _, c := range []struct {
		name          string
		local, pushed string
		to            string // from is dmz
		want          string // default (action), source; or the undermatch reason
	}{
		{"built-in intrazone", "", "", "dmz", "intrazone-default (allow), built-in"},
		{"built-in interzone; vsys2's entry does not count", "", "", "inside", "interzone-default (deny), built-in"},
		{"the other rule's entry does not count", entry(intra, "deny"), "", "inside", "interzone-default (deny), built-in"},
		{"local overrides", entry(inter, "allow"), "", "inside", "interzone-default (allow), local"},
		{"local without action keeps the built-in", entry(inter, ""), "", "inside", "interzone-default (deny), local"},
		{"pushed overrides", "", entry(intra, "reset-both"), "dmz", "intrazone-default (reset-both), pushed"},
		{"local and pushed agree", entry(intra, "drop"), entry(intra, "drop"), "dmz", "intrazone-default (drop), local"},
		{"local and pushed disagree", entry(intra, "drop"), entry(intra, "allow"), "dmz", "local and pushed default rules disagree; precedence not verified"},
		{"not an action", entry(inter, "maybe"), "", "inside", `interzone-default has the action "maybe", which is not a security rule action`},
	} {
		r, v := run(t, ruleTypeWith(t, c.local, c.pushed), simulate.Flow{
			Source: ep("10.2.0.5"), Destination: ep("10.1.0.5"), FromZone: "dmz", ToZone: c.to,
		})
		fm := stage(r, "first-match")
		got := fmt.Sprintf("%s (%s), %s", v.Default, v.DefaultAction, v.DefaultSource)
		if v.Default == "" {
			if fm.Fidelity.Level() != "undermatch" {
				t.Errorf("%s: an undecided default is undermatch, got %s", c.name, fm.Fidelity)
			}
			got = strings.TrimPrefix(fm.Detail, "no enabled rule matches; ")
		}
		if got != c.want || v.Rule != nil {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// Without single, known zones no default rule decides.
func TestDefaultRuleNeedsKnownZones(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-zones.xml", false)
	for _, f := range []simulate.Flow{
		{Source: ep("10.2.0.5"), Destination: ep("10.1.0.5")},                                        // derived
		{Source: ep("10.2.0.5"), Destination: ep("10.1.0.5"), FromZone: "nowhere", ToZone: "inside"}, // undefined
	} {
		r, v := run(t, e, f)
		fm := stage(r, "first-match").Fidelity
		if v.Default != "" || fm.Level() != "undermatch" || !strings.Contains(fm.String(), "the default rule depends on the zones") {
			t.Errorf("%+v: default %q, first-match %s", f, v.Default, fm)
		}
	}
}
