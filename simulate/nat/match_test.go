package nat

import (
	"bufio"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/simulate"
)

func natConfig(t *testing.T, file string) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/" + file)
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
	f, err := os.Open("../../testdata/opdata/" + file)
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
		Target: simulate.Target{Config: cfg}, Vsys: "vsys1",
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
	cfg := natConfig(t, "firewall-nat.xml")
	for _, p := range probes(t, "fw01-nat-policy-match.tsv") {
		t.Run(p.name, func(t *testing.T) {
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
	cfg := natConfig(t, "firewall-nat.xml")
	// No port: t-dnat-port may match, and internet-a surely does.
	p := probe{src: "198.18.1.10", dst: "198.18.250.10", from: "transport", to: "transport", iface: "ethernet1/1"}
	m := Match(input(cfg, p))
	if m.Rule == nil || m.Rule.Name != "internet-a" || len(m.Doubts) != 1 || m.Doubts[0].Rule != "t-dnat-port" ||
		!strings.Contains(m.Doubts[0].Reason, "give --port") || m.Fidelity.Level() != "overmatch" {
		t.Errorf("no port: %+v", m)
	}
	// An unknown ingress zone: every rule naming a source zone is a doubt.
	p = probe{src: "198.18.11.77", dst: "198.18.250.200", port: 443, to: "transport", iface: "ethernet1/1"}
	m = Match(input(cfg, p))
	if m.Rule == nil || m.Rule.Name != "t-dip-pool" && m.Rule.Name != "internet-a" || len(m.Doubts) == 0 || m.Doubts[0].Rule != "t-no-nat" {
		t.Errorf("unknown zone: rule %v, doubts %v", m.Rule, m.Doubts)
	}
}

func TestMatchEnds(t *testing.T) {
	cfg := natConfig(t, "firewall-nat.xml")
	in := input(cfg, probe{src: "198.18.1.10", dst: "198.18.250.10", port: 8443, from: "transport"})
	in.PreNAT = &simulate.Forward{End: simulate.EndNoRoute}
	if m := Match(in); m.Rule != nil || !strings.Contains(m.Dropped, "dropped before NAT") {
		t.Errorf("no route: %+v", m)
	}
	in.PreNAT = &simulate.Forward{End: simulate.EndUnknownType, Fidelity: simulate.UnderMatch("x")}
	if m := Match(in); m.Rule != nil || m.Fidelity.Level() != "undermatch" {
		t.Errorf("unknown route type: %+v", m)
	}
	in.PreNAT, in.In = &simulate.Forward{Out: simulate.Port{Zone: "transport"}}, simulate.Port{Interface: "ethernet1/9"}
	if m := Match(in); len(m.Unresolved) != 1 || !strings.Contains(m.Unresolved[0].Reason, "virtual wire") {
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
		Target: simulate.Target{Config: cfg}, Vsys: "vsys1",
		Flow:   simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr(dst)), Protocol: proto, DestPort: port},
		In:     simulate.Port{Device: "fw", Router: "r", Zone: "trust"},
		PreNAT: &simulate.Forward{Out: simulate.Port{Zone: "untrust", Interface: "ethernet1/1"}},
	}
}

func TestServicesAndTypes(t *testing.T) {
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
			m := Match(caseInput(t, tc.dst, tc.proto, tc.port))
			if m.Rule == nil || m.Rule.Name != tc.rule {
				t.Fatalf("rule = %v, excluded %v", m.Rule, m.Excluded)
			}
			doubts := ""
			for _, d := range m.Doubts {
				doubts += d.Reason
			}
			if tc.doubt == "" && doubts != "" || tc.doubt != "" && !strings.Contains(doubts, tc.doubt) {
				t.Errorf("doubts = %q", doubts)
			}
		})
	}
	// nptv6 is skipped; a nat64 rule that could match stops the answer (spec §18 N6).
	m := Match(caseInput(t, "203.0.113.4", "tcp", 443))
	if m.Rule != nil || len(m.Unresolved) != 1 || !strings.Contains(m.Unresolved[0].Reason, "NAT64 rule six-four") {
		t.Errorf("nat64: %+v", m)
	}
	if m.Excluded[0].Field != "nat-type nptv6" {
		t.Errorf("nptv6: %+v", m.Excluded)
	}
	// An HA binding is ignored with a note (D2).
	if m := Match(caseInput(t, "198.51.100.1", "tcp", 443)); len(m.Notes) != 1 || !strings.Contains(m.Notes[0], "bound to HA device 0") {
		t.Errorf("binding: %+v", m.Notes)
	}
}

func TestAVersionGapIsNoted(t *testing.T) {
	in := input(natConfig(t, "firewall-version-12.2.xml"), probe{src: "10.0.0.1", dst: "10.0.0.2", port: 443, from: "trust", to: "untrust"})
	m := Match(in)
	if m.Rule != nil || len(m.Notes) != 1 || !strings.Contains(m.Notes[0], "NAT checked with the") || m.Fidelity.Level() != "inferred" {
		t.Errorf("gap: %+v", m)
	}
	// A destination-only flow, and an unknown egress zone.
	in = caseInput(t, "198.51.100.1", "tcp", 443)
	in.PreNAT = &simulate.Forward{}
	if m := Match(in); m.Rule != nil || len(m.Doubts) == 0 || !strings.Contains(m.Doubts[0].Reason, "egress zone is unknown") {
		t.Errorf("unknown egress: %+v", m)
	}
	if first(nil) != "" || sourceAddr(nil).IsValid() {
		t.Error("helpers")
	}
}
