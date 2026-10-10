package nat

import (
	"bufio"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/rulebase"
)

func natConfig(t *testing.T, file string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../../../testdata/config/" + file)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// probe is one row of a device's test nat-policy-match answers.
type probe struct {
	name, src, dst          string
	port                    uint16
	from, to, iface, answer string
}

func probes(t *testing.T, file string) []probe {
	t.Helper()
	f, err := os.Open("../../../testdata/opdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []probe
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		c := strings.Split(line, "\t")
		port, _ := strconv.Atoi(c[3])
		out = append(out, probe{c[0], c[1], c[2], uint16(port), c[4], c[5], c[6], c[7]}) //nolint:gosec // a port
	}
	return out
}

func input(cfg *config.Config, p probe) Input {
	return Input{
		Target: withIndexes(cfg, "vsys1"), Vsys: "vsys1",
		Flow: simulate.Flow{
			Source:      simulate.Addr(netip.MustParseAddr(p.src)),
			Destination: simulate.Addr(netip.MustParseAddr(p.dst)),
			Protocol:    "tcp", DestPort: p.port,
		},
		In:     simulate.Port{Device: "fw01", Router: "default", Zone: p.from},
		PreNAT: &simulate.Forward{Out: simulate.Port{Zone: p.to, Interface: p.iface}},
	}
}

// Every flow fw01 answered with test nat-policy-match (2026-09-29) hits the same
// rule here. The one exception is the dynamic destination whose FQDN fw01 could not
// resolve: the device names no rule (spec §18 F17); the engine names the rule, and
// its translation is unresolved (D8).
func TestTheRuleFw01Named(t *testing.T) {
	t.Parallel()
	cfg := natConfig(t, "firewall-nat.xml")
	for _, p := range probes(t, "fw01-nat-policy-match.tsv") {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			m := Match(input(cfg, p))
			got := ""
			if m.Rule != nil {
				got = m.Rule.Name
			}
			want := p.answer
			if p.name == "dnat-fqdn-unresolved" {
				want = "t-dnat-fqdn"
			}
			if got != want {
				t.Errorf("rule %q, device %q; excluded %v, doubts %v", got, p.answer, m.Excluded, m.Doubts)
			}
		})
	}
}

func TestTheImplicitRule(t *testing.T) {
	t.Parallel()
	cfg := natConfig(t, "firewall-nat.xml")
	m := Match(input(cfg, probe{src: "198.18.1.10", dst: "198.18.250.20", port: 443, from: "transport", to: "transport", iface: "ethernet1/1"}))
	if m.Rule == nil || m.Rule.Origin != "t-bidir" || m.Rule.Destination.Address != "198.18.19.50" || m.Rule.label() != "t-bidir (implicit)" {
		t.Fatalf("rule = %+v", m.Rule)
	}
	// Everything above it was excluded for a reason --why can name.
	var fields []string
	for _, e := range m.Excluded {
		fields = append(fields, e.Rule+": "+e.Field)
	}
	if got := strings.Join(fields, "; "); !strings.Contains(got, "t-no-nat: from zone client ≠ transport") ||
		!strings.Contains(got, "t-dnat-port: service t-8443") || !strings.Contains(got, "t-bidir: from zone dmz ≠ transport") {
		t.Errorf("excluded = %s", got)
	}
}

func TestDoubts(t *testing.T) {
	t.Parallel()
	cfg := natConfig(t, "firewall-nat.xml")
	// No port: t-dnat-port may match, and internet-a surely does.
	p := probe{src: "198.18.1.10", dst: "198.18.250.10", from: "transport", to: "transport", iface: "ethernet1/1"}
	m := Match(input(cfg, p))
	if m.Rule == nil || m.Rule.Name != "internet-a" || len(m.Doubts) != 1 || m.Doubts[0].Rule != "t-dnat-port" ||
		!strings.Contains(m.Doubts[0].Text(), "give the destination port") || m.Doubts[0].Reasons[0].Code != "path.nat-no-port" || m.Fidelity.Level() != "overmatch" {
		t.Errorf("no port: %+v", m)
	}
	// The summary has its own code; the doubt keeps its reasons' codes.
	if rs := m.Fidelity.Reasons(); len(rs) != 1 || rs[0].Code != "doubt.nat-rule" || !strings.HasPrefix(rs[0].Text, "may instead hit t-dnat-port") {
		t.Errorf("summary: %v", rs)
	}
	// An unknown ingress zone: every rule naming a source zone is a doubt.
	p = probe{src: "198.18.11.77", dst: "198.18.250.200", port: 443, to: "transport", iface: "ethernet1/1"}
	m = Match(input(cfg, p))
	if m.Rule == nil || m.Rule.Name != "t-dip-pool" && m.Rule.Name != "internet-a" || len(m.Doubts) == 0 || m.Doubts[0].Rule != "t-no-nat" {
		t.Errorf("unknown zone: rule %v, doubts %v", m.Rule, m.Doubts)
	}
}

func TestMatchEnds(t *testing.T) {
	t.Parallel()
	cfg := natConfig(t, "firewall-nat.xml")
	in := input(cfg, probe{src: "198.18.1.10", dst: "198.18.250.10", port: 8443, from: "transport"})
	in.PreNAT = &simulate.Forward{End: simulate.EndNoRoute}
	if m := Match(in); m.Rule != nil || !strings.Contains(m.Dropped, "dropped before NAT") {
		t.Errorf("no route: %+v", m)
	}
	in.PreNAT = &simulate.Forward{End: simulate.EndUnknownType, Fidelity: simulate.UnderMatch(reason.New("path.next-hop-type", "x"))}
	if m := Match(in); m.Rule != nil || m.Fidelity.Level() != "undermatch" {
		t.Errorf("unknown route type: %+v", m)
	}
	in.PreNAT, in.In = &simulate.Forward{Out: simulate.Port{Zone: "transport"}}, simulate.Port{Interface: "ethernet1/9"}
	if m := Match(in); len(m.Unresolved) != 1 || !strings.Contains(m.Unresolved[0].Reason, "virtual wire") || m.Unresolved[0].Code != "path.virtual-wire" {
		t.Errorf("virtual wire: %+v", m)
	}
	in.In, in.Vsys = simulate.Port{Router: "default", Zone: "transport"}, "vsys9"
	if m := Match(in); m.Rule != nil || m.Fidelity.Level() != "overmatch" {
		t.Errorf("no configuration: %+v", m)
	}
	// Lookup is asked when the caller has no pre-NAT lookup.
	in.Vsys, in.PreNAT = "vsys1", nil
	in.Lookup = func(netip.Addr) simulate.Forward {
		return simulate.Forward{Out: simulate.Port{Zone: "transport", Interface: "ethernet1/1"}}
	}
	if m := Match(in); m.Rule == nil || m.Rule.Name != "t-dnat-port" {
		t.Errorf("lookup: %+v", m.Rule)
	}
}

func caseInput(t *testing.T, dst string, proto string, port uint16) Input {
	t.Helper()
	cfg := natConfig(t, "firewall-nat-cases.xml")
	return Input{
		Target: withIndexes(cfg, "vsys1"), Vsys: "vsys1",
		Flow:   simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr(dst)), Protocol: proto, DestPort: port},
		In:     simulate.Port{Device: "fw", Router: "r", Zone: "trust"},
		PreNAT: &simulate.Forward{Out: simulate.Port{Zone: "untrust", Interface: "ethernet1/1"}},
	}
}

func TestServicesAndTypes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, dst, proto string
		port             uint16
		rule, doubt      string
	}{
		{"a range in a group", "203.0.113.1", "tcp", 8005, "by-group", ""},
		{"a list entry", "203.0.113.1", "tcp", 9443, "by-group", ""},
		{"udp in a group", "203.0.113.1", "udp", 53, "by-group", ""},
		{"no service holds it", "203.0.113.1", "tcp", 53, "bound", ""},
		{"a predefined service", "203.0.113.2", "tcp", 443, "bound", "predefined"},
		{"a group that loops", "203.0.113.3", "tcp", 443, "bound", "predefined"},
		{"any service, no port", "198.51.100.1", "tcp", 0, "bound", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := Match(caseInput(t, tc.dst, tc.proto, tc.port))
			if m.Rule == nil || m.Rule.Name != tc.rule {
				t.Fatalf("rule = %v, excluded %v", m.Rule, m.Excluded)
			}
			var doubts strings.Builder
			for _, d := range m.Doubts {
				doubts.WriteString(d.Text())
			}
			if tc.doubt == "" && doubts.String() != "" || tc.doubt != "" && !strings.Contains(doubts.String(), tc.doubt) {
				t.Errorf("doubts = %q", doubts.String())
			}
		})
	}
	// nptv6 is skipped; a nat64 rule that could match stops the answer (spec §18 N6).
	m := Match(caseInput(t, "203.0.113.4", "tcp", 443))
	if m.Rule != nil || len(m.Unresolved) != 1 || !strings.Contains(m.Unresolved[0].Reason, "NAT64 rule six-four") || m.Unresolved[0].Code != "gap.ipv6" {
		t.Errorf("nat64: %+v", m)
	}
	if m.Excluded[0].Field != "nat-type nptv6" {
		t.Errorf("nptv6: %+v", m.Excluded)
	}
	// An HA binding is ignored with a note (D2).
	if m := Match(caseInput(t, "198.51.100.1", "tcp", 443)); len(m.Notes) != 1 || !strings.Contains(m.Notes[0].Text, "bound to HA device 0") || m.Notes[0].Code != "note.ha-binding" {
		t.Errorf("binding: %+v", m.Notes)
	}
}

func TestAVersionGapIsNoted(t *testing.T) {
	t.Parallel()
	in := input(natConfig(t, "firewall-version-12.2.xml"), probe{src: "10.0.0.1", dst: "10.0.0.2", port: 443, from: "trust", to: "untrust"})
	m := Match(in)
	if m.Rule != nil || len(m.Notes) != 1 || !strings.Contains(m.Notes[0].Text, "NAT checked with the") || m.Notes[0].Code != "gap.version" || m.Fidelity.Level() != "inferred" {
		t.Errorf("gap: %+v", m)
	}
	// A destination-only flow, and an unknown egress zone.
	in = caseInput(t, "198.51.100.1", "tcp", 443)
	in.PreNAT = &simulate.Forward{}
	if m := Match(in); m.Rule != nil || len(m.Doubts) == 0 || !strings.Contains(m.Doubts[0].Text(), "egress zone is unknown") || m.Doubts[0].Reasons[0].Code != "zone.missing" {
		t.Errorf("unknown egress: %+v", m)
	}
	if first(nil) != "" || sourceAddr(nil).IsValid() {
		t.Error("helpers")
	}
}

func policyOf(t *testing.T, file string) rulebase.Vsys {
	t.Helper()
	cfg := natConfig(t, file)
	v, ok := rulebase.Load(func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }, "fw", "vsys1")
	if !ok {
		t.Fatal("vsys1")
	}
	return v
}

// A NAT doubt with several reasons reads as one line; JSON keeps each with its
// code.
func TestANATDoubtJoinsItsReasons(t *testing.T) {
	t.Parallel()
	d := Doubt{Rule: "r", Reasons: simulate.Reasons{
		reason.New("zone.missing", "the ingress zone is unknown"), reason.New("doubt.source-unknown", "the source is unknown"),
	}}
	b, err := json.Marshal(d)
	if err != nil || d.Text() != "the ingress zone is unknown; the source is unknown" ||
		string(b) != `{"rule":"r","reasons":[{"code":"zone.missing","text":"the ingress zone is unknown"},{"code":"doubt.source-unknown","text":"the source is unknown"}]}` {
		t.Errorf("json = %s, %v", b, err)
	}
}

// withIndexes is a target over a vsys of cfg with its index provider, as a
// loader gives it.
func withIndexes(cfg *config.Config, vsys string) simulate.Target {
	sc := config.Scope{Sort: config.ScopeVsys, Name: vsys}
	return simulate.Target{Config: cfg, Indexes: index.NewSet(cfg).Provider(sc)}
}

// A port decides only a service the configuration defines: a predefined
// service, or a group of them, is a predefined doubt with or without a port,
// so a caller is never asked for a port that cannot help.
func TestServiceFitsAsksForAPortOnlyWhenItHelps(t *testing.T) {
	t.Parallel()
	cfg := natConfig(t, "firewall-nat-cases.xml")
	svc := map[string]string{
		"service:svc-443":           "tcp/443",
		"service-group:g-defined":   "service-http, svc-443",
		"service-group:g-undefined": "service-http, service-https",
		"service-group:loop":        "loop",
		"service-group:mixed-loop":  "loop, svc-443",
	}
	for _, tc := range []struct {
		name string
		port uint16
		want reason.Code
	}{
		{"service-http", 0, "doubt.service-predefined"},
		{"g-undefined", 0, "doubt.service-predefined"},
		{"loop", 0, "doubt.service-predefined"},
		{"svc-443", 0, "path.nat-no-port"},
		{"g-defined", 0, "path.nat-no-port"},
		{"service-http", 443, "doubt.service-predefined"},
		{"g-defined", 443, "doubt.service-predefined"},
		{"mixed-loop", 443, "doubt.service-predefined"},
		{"svc-443", 443, ""},
	} {
		_, r := serviceFits(tc.name, simulate.Flow{Protocol: "tcp", DestPort: tc.port}, svc, cfg)
		if r.Code != tc.want {
			t.Errorf("%s port %d: %s, want %s", tc.name, tc.port, r.Code, tc.want)
		}
	}
}

// predefinedMatch matches one flow from home to wan, destination 10.88.10.100,
// against the configuration at path, and names the rule hit and the doubts' codes.
func predefinedMatch(t *testing.T, path, proto string, port uint16) (string, MatchResult) {
	t.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	m := Match(Input{
		Target: withIndexes(cfg, "vsys1"), Vsys: "vsys1",
		Flow:   simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr("10.88.10.100")), Protocol: proto, DestPort: port},
		In:     simulate.Port{Device: "fw", Router: "r", Zone: "home"},
		PreNAT: &simulate.Forward{Out: simulate.Port{Zone: "wan", Interface: "ethernet1/2"}},
	})
	rule := "none"
	if m.Rule != nil {
		rule = m.Rule.Name
	}
	return rule, m
}

// As observed on fw02, PAN-OS 12.2.3 (L4b): a DNAT rule with service-https takes
// tcp/443 only; one with service-http takes tcp/80 and tcp/8080; udp/443 and
// tcp/8443 hit neither. The predefined services come from predefined.xml next to
// the configuration, so every answer is decided.
func TestPredefinedServicesDecideNAT(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		proto string
		port  uint16
		rule  string
	}{
		{"tcp", 443, "dnat-https"},
		{"tcp", 80, "dnat-http"},
		{"tcp", 8080, "dnat-http"},
		{"udp", 443, "none"},
		{"tcp", 8443, "none"},
	} {
		rule, m := predefinedMatch(t, "../../../testdata/predefined/config.xml", tc.proto, tc.port)
		if rule != tc.rule || len(m.Doubts) != 0 || m.Fidelity.Level() != "exact" {
			t.Errorf("%s/%d: rule %s, want %s; doubts %v, fidelity %s", tc.proto, tc.port, rule, tc.rule, m.Doubts, m.Fidelity)
		}
	}
}

// As observed on fw02, PAN-OS 12.2.3 (L7): a configured service with a predefined
// name wins. vsys1's service-https is tcp/8443 and shared's service-http is
// tcp/8081, so the predefined ports no longer match.
func TestConfiguredServicesHideThePredefinedOnes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		port uint16
		rule string
	}{
		{8443, "dnat-https"},
		{443, "none"},
		{8081, "dnat-http"},
		{80, "none"},
		{8080, "none"},
	} {
		rule, m := predefinedMatch(t, "../../../testdata/predefined-configured/config.xml", "tcp", tc.port)
		if rule != tc.rule || len(m.Doubts) != 0 || m.Fidelity.Level() != "exact" {
			t.Errorf("tcp/%d: rule %s, want %s; doubts %v, fidelity %s", tc.port, rule, tc.rule, m.Doubts, m.Fidelity)
		}
	}
}

// A snapshot stored before predefined.xml was fetched keeps the doubt, and the
// doubt says that a fetch stores the predefined services.
func TestWithoutPredefinedServicesNATStaysInDoubt(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../testdata/predefined/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rule, m := predefinedMatch(t, path, "tcp", 443)
	if rule != "none" || len(m.Doubts) != 2 || m.Fidelity.Level() != "overmatch" {
		t.Fatalf("rule %s, doubts %v, fidelity %s", rule, m.Doubts, m.Fidelity)
	}
	for _, d := range m.Doubts {
		if r := d.Reasons[0]; r.Code != "doubt.service-predefined" || !strings.HasSuffix(r.Text, "; the snapshot holds no predefined services; a fetch with this release stores them when the device returns them") {
			t.Errorf("%s: %+v", d.Rule, r)
		}
	}
}
