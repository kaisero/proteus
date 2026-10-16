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
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
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
		cfg, _, err := config.Load(path)
		if err != nil {
			return simulate.Target{}, err
		}
		set := index.NewSet(cfg)
		sc := config.Scope{Sort: config.ScopeVsys, Name: vsys}
		if _, err := set.Index(sc, resolve.Security); err != nil {
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
		return simulate.Target{Config: cfg, Indexes: set.Provider(sc), Providers: p}, nil
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
	if got := r.Fidelity.String(); got != "overmatch; not evaluated: service" {
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
	if strings.Contains(ruleNames(v), "custom-port") || head(v) != "app-default" {
		t.Errorf("a port no service holds drops custom-port: %s", ruleNames(v))
	}
	r, _ = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.5.0.1"), Protocol: "icmp", DestPort: 8})
	if !strings.Contains(stage(r, "match-service").Fidelity.String(), "not evaluated: service") {
		t.Errorf("icmp has no service port: %s", stage(r, "match-service").Fidelity)
	}
}

// A protocol given by number decides as its name does: 6 is tcp in the service
// stage and in the service doubts, so custom-port decides.
func TestAProtocolNumberDecidesTheService(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-simulate.xml", false)
	answer := func(proto string) string {
		_, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.5.0.9"), Protocol: proto, DestPort: 8443})
		o, why := v.Decision()
		var doubts []string
		for _, d := range v.Doubts {
			doubts = append(doubts, d.Rule+" "+string(d.Reasons[0].Code))
		}
		return fmt.Sprintf("%s: %s; doubts %v", o, why.Text(), doubts)
	}
	tcp := answer("tcp")
	if !strings.HasPrefix(tcp, "pass: rule custom-port (allow)") {
		t.Errorf("tcp: %s", tcp)
	}
	for _, proto := range []string{"6", "TCP"} {
		if got := answer(proto); got != tcp {
			t.Errorf("%s: %s, want %s", proto, got, tcp)
		}
	}
}

func TestURLCategories(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-simulate.xml", false)
	r, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.6.0.1"), URL: "shop.example.com/cart"})
	if head(v) != "shop" || !strings.Contains(ruleNames(v), "social") {
		t.Errorf("custom category matches, PAN-DB category kept: %s", ruleNames(v))
	}
	if f := stage(r, "match-url").Fidelity; f.Level() != "overmatch" || !strings.Contains(f.String(), "social") {
		t.Errorf("match-url = %s", f)
	}
	_, v = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.6.0.1"), URL: "other.example.org"})
	if strings.Contains(ruleNames(v), "shop") || head(v) != "social" {
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

// A configuration of another PAN-OS version reads with the one schema: the
// address stages stay exact and the run has no note.
func TestAnotherVersionIsExact(t *testing.T) {
	t.Parallel()
	r, v := run(t, env(t, "firewall-version-12.2.xml", false), simulate.Flow{Source: ep("198.18.10.100"), Destination: ep("198.18.1.5"), DestPort: 443})
	for _, slug := range []string{"resolve-source", "resolve-destination"} {
		if st := stage(r, slug); st.Fidelity.Level() != "exact" || len(st.Unresolved) != 0 {
			t.Errorf("%s: %s, unresolved %v", slug, st.Fidelity, st.Unresolved)
		}
	}
	if len(r.Notes) != 0 {
		t.Errorf("notes = %v", r.Notes)
	}
	if head(v) != "dc-to-home" {
		t.Errorf("candidates = %s", ruleNames(v))
	}
	r, _ = run(t, env(t, "firewall-version-12.2.xml", false), simulate.Flow{Source: ep("198.18.10.100"), Destination: ep("198.18.1.5"), URL: "shop.example.com"})
	if st := stage(r, "match-url"); st.Fidelity.Level() != "exact" || len(st.Unresolved) != 0 {
		t.Errorf("match-url: %s, unresolved %v", st.Fidelity, st.Unresolved)
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
	if got := strings.Join(s.Stages(), ","); got != "resolve-source,resolve-destination,derive-zones,match-application,match-service,match-url,drop-disabled,order,first-match" {
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

// The security index comes from the target's provider. A target without one fails
// the run like a failed load: the check never builds an index itself.
func TestATargetWithoutAnIndexProviderFailsLikeALoad(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-zones.xml")
	if err != nil {
		t.Fatal(err)
	}
	e := &simulate.Env{Load: func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg}, nil }}
	_, err = Simulation{}.Run(context.Background(), e, simulate.Input{Device: "fw09", Vsys: "vsys1"})
	if err == nil || err.Error() != "policy: fw09/vsys1: no index provider" {
		t.Errorf("err = %v", err)
	}
}

// head is the first candidate, whether or not it decides.
func head(v Verdict) string {
	if len(v.Candidates) == 0 {
		return "none"
	}
	return v.Candidates[0].Name
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
	if head(v) != "dc-to-home" || !strings.Contains(stage(r, "match-service").Fidelity.String(), "absent") {
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

// Without a forwarding table the configuration places the source, and a
// default static route places nothing either: 198.51.100.7 reaches outside only
// through the route internet, so the source zone stays open and the default
// rule is not decided on it.
func TestADefaultStaticRouteDoesNotPlaceTheSource(t *testing.T) {
	t.Parallel()
	r, v := run(t, env(t, "firewall-default-route.xml", false), simulate.Flow{Source: ep("198.51.100.7"), Destination: ep("10.1.0.5")})
	if len(v.Zones.From) != 0 || strings.Join(v.Zones.To, ",") != "inside" ||
		!strings.Contains(v.Zones.Detail, "198.51.100.7: outside via ethernet1/3 static route internet 0.0.0.0/0 ignored") {
		t.Errorf("zones = %+v", v.Zones)
	}
	if o, why := v.Decision(); o != Undecided || why[0].Code != "default.zones-unknown" || v.Default != "" {
		t.Errorf("%s %v, default %s", o, why, v.Default)
	}
	if f := stage(r, "derive-zones").Fidelity; !strings.Contains(f.String(), "not evaluated: source zone") {
		t.Errorf("derive-zones = %s", f)
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

// rule-type with zones that are not given: one derived zone on each side
// decides as given zones do, with the zones inferred (C5, lab L5). Several
// derived zones on a side leave an intrazone or interzone rule a candidate with
// a zone.derived doubt, and the first match decides whether it matters (E20). A
// given zone the vsys does not define is refused (C15). Each case asserts the
// decision, not only the candidates.
func TestRuleTypeWithoutKnownZones(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-ruletype.xml", false)
	two := simulate.Endpoint{Addrs: []netip.Addr{netip.MustParseAddr("10.1.0.5"), netip.MustParseAddr("10.3.0.5")}}
	for _, c := range []struct {
		name     string
		flow     simulate.Flow
		want     string // the candidates, in order
		doubts   string // each doubt's rule and code
		decision string // the outcome and its reasons
		reason   string // in the zone stage's fidelity; "" for none about rule-type
	}{
		{
			// intra-inside: from differs from to; inter-inside does not name out.
			// The derived pair chooses the default rule (C16).
			"derived inside to out",
			simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.3.0.5")},
			"", "", "stop: default rule interzone-default (deny), built-in", "",
		},
		{
			// intra-inside: from equals to; inter-inside: an interzone rule within one zone.
			"derived inside to inside",
			simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.1.0.6")},
			"intra-inside", "", "pass: rule intra-inside (allow)", "",
		},
		{
			// inter-inside: inside to dmz, which it names.
			"derived inside to dmz",
			simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.2.0.5")},
			"inter-inside", "", "stop: rule inter-inside (deny)", "",
		},
		{
			// No rule names dmz as its from zone, whatever its type.
			"derived dmz to inside",
			simulate.Flow{Source: ep("10.2.0.5"), Destination: ep("10.1.0.5")},
			"", "", "stop: default rule interzone-default (deny), built-in", "",
		},
		{
			// From inside or out, to dmz: intra-inside and inter-inside are in
			// doubt above universal-out, and inter-inside denies.
			"two derived from zones",
			simulate.Flow{Source: two, Destination: ep("10.2.0.5")},
			"intra-inside,inter-inside,universal-out",
			"intra-inside zone.derived; inter-inside zone.derived",
			"undecided: inter-inside (deny) at position 2 may match first: rule-type interzone not compared: the derived zones are not one on each side",
			"the zones are derived, so rule-type could not compare from and to for: intra-inside, inter-inside",
		},
	} {
		r, v := run(t, e, c.flow)
		if got := ruleNames(v); got != c.want {
			t.Errorf("%s: candidates %q, want %q", c.name, got, c.want)
		}
		var doubts []string
		for _, d := range v.Doubts {
			doubts = append(doubts, d.Rule+" "+string(d.Reasons[0].Code))
		}
		if got := strings.Join(doubts, "; "); got != c.doubts {
			t.Errorf("%s: doubts %q, want %q", c.name, got, c.doubts)
		}
		o, why := v.Decision()
		if got := fmt.Sprintf("%s: %s", o, why.Text()); got != c.decision {
			t.Errorf("%s: decision %q, want %q", c.name, got, c.decision)
		}
		f := stage(r, "derive-zones").Fidelity
		if c.reason != "" && !strings.Contains(f.String(), c.reason) || c.reason == "" && strings.Contains(f.String(), "rule-type") {
			t.Errorf("%s: derive-zones = %s", c.name, f)
		}
		if f.Level() == "exact" {
			t.Errorf("%s: derived zones are inferred: %s", c.name, f)
		}
	}
	for _, z := range [][2]string{{"nowhere", "dmz"}, {"inside", "nowhere"}} {
		_, err := Simulation{}.Run(context.Background(), e, simulate.Input{
			Flow:   simulate.Flow{Source: ep("10.1.0.5"), Destination: ep("10.2.0.5"), FromZone: z[0], ToZone: z[1]},
			Device: "fw01", Vsys: "vsys1",
		})
		if _, ok := errors.AsType[*simulate.ChoiceError](err); !ok || !strings.Contains(err.Error(), "nowhere is not a zone of vsys1 (its zones: dmz, inside, out)") {
			t.Errorf("given %s -> %s: %v", z[0], z[1], err)
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
		{"pushed without action keeps the built-in", "", entry(inter, ""), "inside", "interzone-default (deny), pushed"},
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

// One derived zone on each side chooses the default rule as given zones do,
// and the answer is inferred (C16): different zones take interzone-default,
// equal zones intrazone-default. Several zones, or none, on a side leave it
// undecided.
func TestDefaultRuleWithDerivedZones(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-zones.xml", false)
	two := simulate.Endpoint{Addrs: []netip.Addr{netip.MustParseAddr("10.2.0.5"), netip.MustParseAddr("10.1.0.6")}}
	for _, c := range []struct {
		name string
		flow simulate.Flow
		want string // the default rule and its action, or the undecided reason
	}{
		{"dmz to inside", simulate.Flow{Source: ep("10.2.0.5"), Destination: ep("10.1.0.5")}, "interzone-default (deny)"},
		{"dmz to dmz", simulate.Flow{Source: ep("10.2.0.5"), Destination: ep("10.2.0.6")}, "intrazone-default (allow)"},
		{"dmz or inside to inside", simulate.Flow{Source: two, Destination: ep("10.1.0.5")}, "the default rule depends on the zones"},
		{"dmz to no zone", simulate.Flow{Source: ep("10.2.0.5"), Destination: ep("192.0.2.9")}, "the default rule depends on the zones"},
	} {
		r, v := run(t, e, c.flow)
		got := v.Default + " (" + v.DefaultAction + ")"
		if o, why := v.Decision(); v.Default == "" {
			got = why.Text()
			if o != Undecided || why[0].Code != "default.zones-unknown" || stage(r, "first-match").Fidelity.Level() != "undermatch" {
				t.Errorf("%s: %s %v, first-match %s", c.name, o, why, stage(r, "first-match").Fidelity)
			}
		}
		if got != c.want || v.Rule != nil {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if v.Default != "" && (r.Fidelity.Level() != "inferred" || v.Zones.Source != "configuration") {
			t.Errorf("%s: derived zones are inferred: %s, %s", c.name, r.Fidelity, v.Zones.Source)
		}
	}
}

// A given zone the vsys does not define is a question the check cannot take
// (C15): the error names the zone and lists the vsys's zones, in the command
// line's words and the tool's.
func TestAnUndefinedGivenZoneIsRefused(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-zones.xml", false)
	for _, c := range []struct {
		from, to, question, tool string
	}{
		{"nowhere", "inside", "--from-zone nowhere", "from_zone nowhere"},
		{"inside", "nowhere", "--to-zone nowhere", "to_zone nowhere"},
	} {
		_, err := Simulation{}.Run(context.Background(), e, simulate.Input{
			Flow:   simulate.Flow{Source: ep("10.2.0.5"), Destination: ep("10.1.0.5"), FromZone: c.from, ToZone: c.to},
			Device: "fw01", Vsys: "vsys1",
		})
		ce, ok := errors.AsType[*simulate.ChoiceError](err)
		zones := " is not a zone of vsys1 (its zones: dmz, empty-zone, inside, loop)"
		if !ok || ce.Question != c.question+zones || ce.ToolText != c.tool+zones || ce.Kind != simulate.ChoiceZone {
			t.Errorf("%s -> %s: %v", c.from, c.to, err)
		}
	}
}

// A configuration without the index's vsys has unknown default rules: the
// built-in action would be a guess.
func TestDefaultRuleWithoutTheVsys(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-ruletype.xml")
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := config.Load("../../../testdata/config/firewall-zones.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys2"}, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	s := &state{known: true, target: simulate.Target{Config: other}, idx: idx}
	s.in.Flow.FromZone, s.in.Flow.ToZone = "inside", "dmz"
	if d, why := s.defaultRule(); d.Name != "" || why != reason.New("default.vsys-missing", "the configuration has no vsys:vsys2, so its default rules are not known") {
		t.Errorf("got %+v, %q", d, why)
	}
}
