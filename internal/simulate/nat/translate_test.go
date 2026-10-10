package nat

import (
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

func fw01Interfaces(t *testing.T) []resolve.InterfaceState {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/opdata/fw01-interface-all.xml")
	if err != nil {
		t.Fatal(err)
	}
	ifs, err := resolve.ReadInterfaceStates(b)
	if err != nil {
		t.Fatal(err)
	}
	return ifs
}

// translate runs a probe flow through the engine, with fw01's interfaces and a
// post-NAT lookup that places everything in 198.18.10.0/24 in zone server.
func translate(t *testing.T, p probe, resolved map[string][]netip.Addr) Result {
	t.Helper()
	in := input(natConfig(t, "firewall-nat.xml"), p)
	in.Interfaces, in.Resolved = fw01Interfaces(t), resolved
	in.Lookup = func(a netip.Addr) simulate.Forward {
		if netip.MustParsePrefix("198.18.10.0/24").Contains(a) {
			return simulate.Forward{Out: simulate.Port{Interface: "ethernet1/2", Zone: "server"}, Fidelity: simulate.Exact}
		}
		return simulate.Forward{Out: simulate.Port{Interface: "ethernet1/1", Zone: "transport"}, Fidelity: simulate.Exact}
	}
	return Translate(in, Match(in))
}

func flowText(f simulate.Flow) string {
	return f.Source.String() + " -> " + f.Destination.String() + ":" + strconv.Itoa(int(f.DestPort))
}

// Each translation as fw01 showed it in `show running nat-policy` (translate-to)
// and, for t-dnat-port and t-bidir's implicit rule, in its traffic log.
func TestTranslationsFw01Showed(t *testing.T) {
	t.Parallel()
	tr := func(src, dst string, port uint16, from string) probe {
		return probe{src: src, dst: dst, port: port, from: from, to: "transport", iface: "ethernet1/1"}
	}
	for _, tc := range []struct {
		name, flow  string
		p           probe
		srcPort     string
		postNATZone string
	}{
		{"t-dnat-port: dst 198.18.10.100:443", "198.18.1.10 -> 198.18.10.100:443", tr("198.18.1.10", "198.18.250.10", 8443, "transport"), "", "server"},
		{"t-dnat-self: dst 198.18.10.100:80", "198.18.1.10 -> 198.18.10.100:80", tr("198.18.1.10", "198.19.0.254", 8080, "transport"), "", "server"},
		{"t-bidir: src 198.18.250.20 (static-ip)", "198.18.250.20 -> 198.18.250.200:443", tr("198.18.19.50", "198.18.250.200", 443, "dmz"), PortUnchanged, ""},
		{"t-bidir implicit: dst 198.18.19.50", "198.18.1.10 -> 198.18.19.50:443", tr("198.18.1.10", "198.18.250.20", 443, "transport"), "", "transport"},
		{"t-static-block: 198.18.250.32-47, .5 -> .37", "198.18.250.37 -> 198.18.250.200:443", tr("198.18.19.5", "198.18.250.200", 443, "dmz"), PortUnchanged, ""},
		{"t-pdipp: ethernet1/1 198.19.0.254", "198.19.0.254 -> 198.18.250.100:443", tr("198.18.11.5", "198.18.250.100", 443, "client"), PortRuntime, ""},
		{"t-dip-pool: 198.18.250.64-71", "198.18.250.64 -> 198.18.250.200:443", tr("198.18.11.5", "198.18.250.200", 443, "client"), PortUnchanged, ""},
		{"internet-a: ethernet1/1 198.19.0.254", "198.19.0.254 -> 8.8.8.8:443", probe{src: "198.18.10.5", dst: "8.8.8.8", port: 443, from: "server", to: "transport", iface: "ethernet1/1"}, PortRuntime, ""},
		{"server-access: ethernet1/2 198.18.10.1", "198.18.10.1 -> 198.18.250.11:443", probe{src: "198.18.1.10", dst: "198.18.250.11", port: 443, from: "transport", to: "server", iface: "ethernet1/2"}, PortRuntime, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := translate(t, tc.p, nil)
			if got := flowText(r.Flow); got != tc.flow {
				t.Errorf("flow %s, want %s (unresolved %v)", got, tc.flow, r.Unresolved)
			}
			if tc.srcPort != "" && (r.Source == nil || r.Source.Port != tc.srcPort) {
				t.Errorf("source = %+v", r.Source)
			}
			if tc.postNATZone != "" && (r.PostNAT == nil || r.PostNAT.Out.Zone != tc.postNATZone) {
				t.Errorf("post-NAT = %+v", r.PostNAT)
			}
		})
	}
	r := translate(t, tr("198.18.11.5", "198.18.250.200", 443, "client"), nil)
	if strings.Join(r.Source.Candidates, ",") != "198.18.250.64/29" || strings.Join(r.Source.Fallback, ",") != "198.19.0.254" {
		t.Errorf("pool = %+v", r.Source)
	}
}

func TestDynamicDestination(t *testing.T) {
	t.Parallel()
	p := probe{src: "198.18.1.10", dst: "198.18.250.30", port: 443, from: "transport", to: "transport", iface: "ethernet1/1"}
	// fw01 could not resolve dns.google, and neither could this run (spec §18 D8).
	r := translate(t, p, nil)
	if len(r.Unresolved) != 1 || !strings.Contains(r.Unresolved[0].Reason, "resolves to no address") {
		t.Errorf("unresolved FQDN: %+v", r.Unresolved)
	}
	r = translate(t, p, map[string][]netip.Addr{"dns.google": {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("8.8.8.8")}})
	if r.Destination.Address.String() != "8.8.4.4" || strings.Join(r.Destination.Others, ",") != "8.8.8.8" ||
		r.Fidelity.Level() != "undermatch" || len(r.Notes) != 1 || !strings.Contains(r.Notes[0].Text, "DNS") || r.Notes[0].Code != "doubt.fqdn-resolution" {
		t.Errorf("resolved: %+v, notes %v, fidelity %s", r.Destination, r.Notes, r.Fidelity)
	}
}

func TestTranslationEdges(t *testing.T) {
	t.Parallel()
	// No match: the packet leaves as it came.
	r := translate(t, probe{src: "198.18.1.10", dst: "198.18.250.30", port: 443, from: "transport", to: "server", iface: "ethernet1/2"}, nil)
	if r.Rule == nil || r.Rule.Name != "server-access" {
		t.Fatalf("rule = %v", r.Rule)
	}
	if got := Translate(Input{Flow: simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr("1.1.1.1"))}}, MatchResult{}); got.Source != nil || got.Flow.Destination.String() != "1.1.1.1" {
		t.Errorf("no rule: %+v", got)
	}
	// internet-b's interface has no address in the interface state.
	r = translate(t, probe{src: "198.18.10.5", dst: "8.8.8.8", port: 443, from: "server", to: "transport", iface: "ethernet1/8"}, nil)
	if len(r.Unresolved) != 1 || !strings.Contains(r.Unresolved[0].Reason, "ethernet1/8") {
		t.Errorf("internet-b: %+v", r.Unresolved)
	}
	for in, want := range map[string]uint64{"10.0.0.1": 1, "10.0.0.0/28": 16, "10.0.0.1-10.0.0.4": 4} {
		if _, n, ok := span(in); !ok || n != want {
			t.Errorf("span(%s) = %d", in, n)
		}
	}
	for _, bad := range []string{"x", "10.0.0.9-10.0.0.1", "2001:db8::/64", "a-b"} {
		if _, _, ok := span(bad); ok {
			t.Errorf("span(%s)", bad)
		}
	}
	if firstAddr([]string{"x"}).IsValid() {
		t.Error("firstAddr")
	}
}

func caseTranslate(t *testing.T, src, dst string) Result {
	t.Helper()
	in := Input{
		Target: withIndexes(natConfig(t, "firewall-nat-translations.xml"), "vsys1"), Vsys: "vsys1",
		Flow:   simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr(dst)), Protocol: "tcp", DestPort: 443},
		In:     simulate.Port{Device: "fw", Router: "r", Zone: "trust"},
		PreNAT: &simulate.Forward{Out: simulate.Port{Zone: "untrust", Interface: "ethernet1/1"}},
	}
	if src != "" {
		in.Flow.Source = simulate.Addr(netip.MustParseAddr(src))
	}
	return Translate(in, Match(in))
}

func TestTranslationCases(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, src, dst, want string }{
		{"dynamic group pool", "10.9.9.9", "203.0.113.11", "dynamic group dyn-grp"},
		{"pool object missing", "10.9.9.9", "203.0.113.12", "nope, which is runtime content"},
		{"IPv6 pool interface", "10.9.9.9", "203.0.113.13", "IPv6 address of ethernet1/9"},
		{"unknown kind", "10.9.9.9", "203.0.113.14", "as magic-ip, which is not read yet"},
		{"static from any", "10.9.9.9", "203.0.113.15", "static translation of any"},
		{"static of different sizes", "10.0.0.1", "203.0.113.16", "static translation of 10.0.0.0/29"},
		{"static to a group", "10.0.0.1", "203.0.113.17", "is not one address"},
		{"static to an FQDN", "10.0.0.1", "203.0.113.18", "is not one address"},
		{"destination of another size", "10.9.9.9", "203.0.113.20", "static translation of 203.0.113.20"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := caseTranslate(t, tc.src, tc.dst)
			if len(r.Unresolved) == 0 || !strings.Contains(r.Unresolved[len(r.Unresolved)-1].Reason, tc.want) {
				t.Errorf("rule %v: unresolved %+v", r.Rule, r.Unresolved)
			}
		})
	}
	r := caseTranslate(t, "10.9.9.9", "203.0.113.10")
	if strings.Join(r.Source.Candidates, ",") != "198.51.100.1,198.51.100.2" || len(r.Notes) != 1 || !strings.Contains(r.Notes[0].Text, "no fallback") || r.Notes[0].Code != "note.nat-no-fallback" {
		t.Errorf("pool group: %+v %v", r.Source, r.Notes)
	}
	r = caseTranslate(t, "10.9.9.9", "203.0.113.19")
	if r.Flow.Destination.String() != "10.1.1.1" || len(r.Notes) != 1 || !strings.Contains(r.Notes[0].Text, "rewrites DNS") || r.Notes[0].Code != "note.dns-rewrite" {
		t.Errorf("dns rewrite: %+v %v", r.Flow, r.Notes)
	}
	r = caseTranslate(t, "10.9.9.9", "203.0.113.21")
	if r.Destination.Address.String() != "10.2.2.1" || strings.Join(r.Destination.Others, ",") != "10.2.2.2" || r.Fidelity.Level() != "undermatch" {
		t.Errorf("dynamic object: %+v %s", r.Destination, r.Fidelity)
	}
	// An address outside the original range is refused, though a match never asks.
	tr := translator{in: Input{}, v: policyOf(t, "firewall-nat-translations.xml"), res: &Result{}}
	if _, err := tr.mapStatic("10.0.0.0/28", "198.51.100.16/28", netip.MustParseAddr("10.0.1.1")); !strings.Contains(err, "outside") {
		t.Errorf("outside: %q", err)
	}
	if _, err := tr.mapStatic("10.0.0.0/28", "198.51.100.16/28", netip.Addr{}); !strings.Contains(err, "not simulated") {
		t.Errorf("no address: %q", err)
	}
	if _, err := tr.mapStatic("pool-grp", "198.51.100.16/28", netip.MustParseAddr("198.51.100.1")); !strings.Contains(err, "not simulated") {
		t.Errorf("a group as the original: %q", err)
	}
}

// A translated port that is not a port number is reported, and the packet keeps
// its original port rather than getting port 0.
func TestABadTranslatedPortIsUnresolved(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../../testdata/config/firewall-nat.xml")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(src), "<translated-port>443</translated-port>", "<translated-port>70000</translated-port>", 1)
	path := filepath.Join(t.TempDir(), "nat.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	in := input(cfg, probe{src: "198.18.1.10", dst: "198.18.250.10", port: 8443, from: "transport", to: "transport", iface: "ethernet1/1"})
	r := Translate(in, Match(in))
	if r.Rule == nil || r.Rule.Name != "t-dnat-port" {
		t.Fatalf("rule = %v", r.Rule)
	}
	if len(r.Unresolved) == 0 || !strings.Contains(r.Unresolved[0].Reason, `"70000"`) {
		t.Errorf("unresolved = %v", r.Unresolved)
	}
	if r.Flow.DestPort != 8443 {
		t.Errorf("port = %d, want the original 8443", r.Flow.DestPort)
	}
}
