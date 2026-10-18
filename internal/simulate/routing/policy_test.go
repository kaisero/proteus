package routing

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/rulebase"
	"github.com/kaisero/proteus/internal/testconfig"
)

// policyNet is one firewall carrying firewall-routing.xml's PBF and NAT rules, and
// an upstream device "up" with no configuration.
func policyNet(t *testing.T, file string) (*network, func(string, string) (simulate.Target, error)) {
	t.Helper()
	cfg, _, err := config.Load("../../../testdata/config/" + file)
	if err != nil {
		t.Fatal(err)
	}
	n := netOf(
		dev("fw", []resolve.InterfaceState{
			iface("ethernet1/3", "branch-vpn", "default", "10.20.0.1/16", "10.99.0.1/24"),
			iface("ethernet1/2", "datacenter", "default", "10.1.0.1/16"),
			iface("ethernet1/4", "sdwan", "default", "10.30.0.1/24"),
			iface("ethernet1/1", "untrust", "default", "203.0.113.9/29"),
		},
			route("default", "10.20.0.0/16", "ethernet1/3", "0.0.0.0"),
			route("default", "10.99.0.0/24", "ethernet1/3", "0.0.0.0"),
			route("default", "10.1.0.0/16", "ethernet1/2", "0.0.0.0"),
			route("default", "10.30.0.0/24", "ethernet1/4", "0.0.0.0"),
			route("default", "198.51.100.10/32", "ethernet1/2", "10.1.0.254"),
			route("default", "0.0.0.0/0", "ethernet1/4", "10.30.0.254"),
		),
		dev("up", []resolve.InterfaceState{iface("e1", "outside", "r", "10.30.0.254/24"), iface("e2", "wan", "r", "203.0.113.2/30")},
			route("r", "0.0.0.0/0", "e2", "203.0.113.1")),
	)
	load := func(device, vsys string) (simulate.Target, error) {
		if device != "fw" {
			return simulate.Target{}, errors.New("no configuration")
		}
		return withIndexes(cfg, vsys), nil
	}
	return n, load
}

func policyRun(t *testing.T, file, src, dst string) Path {
	t.Helper()
	n, load := policyNet(t, file)
	run, err := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load}, simulate.Input{Flow: flow(src, dst)})
	if err != nil {
		t.Fatal(err)
	}
	return run.Output.(Path)
}

func notes(h Hop) string { return h.Notes.Text() }

func TestPBFForwardAndSourceNAT(t *testing.T) {
	t.Parallel()
	p := policyRun(t, "firewall-routing.xml", "10.20.5.5", "10.1.10.100")
	h := p.Hops[0]
	want := "pbf rule branch-to-zscaler may forward this packet to tunnel.1 via 198.19.255.254; " +
		"nat rule snat-out (branch-vpn -> datacenter): source 10.20.5.5 -> 203.0.113.9"
	if notes(h) != want || h.Fidelity.Level() != "inferred" || h.PostNAT == nil || h.PostNAT.Source.String() != "203.0.113.9" ||
		!slices.Equal(h.PBF, []string{"branch-to-zscaler"}) {
		t.Errorf("notes = %q, fidelity %s", notes(h), h.Fidelity)
	}
}

// A PBF rule that may take the packet carries why it may not, and why a no-pbf
// rule above it may match first, each with its own code.
func TestPBFDoubtsKeepTheirCodes(t *testing.T) {
	t.Parallel()
	m := rulebase.PBFMatch{
		Rule:   resolve.PBFRule{Rule: resolve.Rule{Name: "fwd"}},
		Found:  true,
		Doubts: []reason.Reason{reason.New("doubt.service-no-port", "no port")},
		Passed: []rulebase.PBFPassed{{Rule: "keep", Doubts: []reason.Reason{reason.New("doubt.schedule", "schedule")}}},
	}
	got := pbfDoubts(m)
	if len(got) != 2 || got[0] != reason.New("doubt.service-no-port", "PBF rule fwd may not match: no port") ||
		got[1] != reason.New("doubt.schedule", "no-pbf rule keep may match first: schedule") {
		t.Errorf("%v", got)
	}
	if got := pbfDoubts(rulebase.PBFMatch{Found: true}); got != nil {
		t.Errorf("a sure match: %v", got)
	}
}

// A PBF rule by interface, with a negated destination.
func TestPBFByInterface(t *testing.T) {
	t.Parallel()
	if h := policyRun(t, "firewall-routing.xml", "10.99.0.5", "10.1.10.50").Hops[0]; notes(h) != "pbf rule lab-by-interface may drop this packet" ||
		!slices.Equal(h.PBF, []string{"lab-by-interface"}) {
		t.Errorf("notes = %q", notes(h))
	}
	// dc01 is the negated destination: the rule does not match, and nothing else does.
	if h := policyRun(t, "firewall-routing.xml", "10.99.0.5", "10.1.10.100").Hops[0]; notes(h) != "" || h.Fidelity.Level() != "exact" || h.PBF != nil {
		t.Errorf("notes = %q, fidelity %s", notes(h), h.Fidelity)
	}
}

// no-pbf leaves the packet to routing; a static NAT translates the source, and
// the next hop sees the translated packet (spec §18 N5).
func TestNoPBFAndATranslationCarriesOn(t *testing.T) {
	t.Parallel()
	p := policyRun(t, "firewall-routing.xml", "10.1.100.250", "8.8.8.8")
	if notes(p.Hops[0]) != "nat rule static-pve (datacenter -> sdwan): source 10.1.100.250 -> 198.51.100.20" || p.Hops[0].PBF != nil {
		t.Errorf("hop 1 notes = %q", notes(p.Hops[0]))
	}
	if len(p.Hops) != 2 || p.Hops[1].Flow.Source.String() != "198.51.100.20" || notes(p.Hops[1]) != "" {
		t.Errorf("hop 2 = %+v", p.Hops[1])
	}
}

// A pool translation: later hops match against its first address, and say so.
func TestAPoolCarriesANote(t *testing.T) {
	t.Parallel()
	p := policyRun(t, "firewall-nat-routing.xml", "10.1.100.250", "8.8.8.8")
	if len(p.Hops) != 2 || notes(p.Hops[1]) != "nat on fw translates the source to one of 198.51.100.64/29" ||
		p.Hops[1].Flow.Source.String() != "198.51.100.64" {
		t.Errorf("hops = %+v", p.Hops)
	}
}

// A destination NAT replaces the egress with the lookup of the translated
// destination, and the box shows both lookups (spec §18 N5).
func TestDestinationNAT(t *testing.T) {
	t.Parallel()
	n, load := policyNet(t, "firewall-routing.xml")
	f := flow("10.30.0.7", "198.51.100.10")
	f.Protocol, f.DestPort = "tcp", 3389
	run, err := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load}, simulate.Input{Flow: f, Params: map[string]string{"device": "fw"}})
	h := run.Output.(Path).Hops[0]
	if err != nil || !strings.HasSuffix(notes(h), "; nat rule dnat-portal (sdwan -> datacenter): destination 198.51.100.10 -> 10.1.10.100") ||
		h.Out.Interface != "ethernet1/2" || h.Flow.ToZone != "datacenter" || len(h.Lookups) != 2 ||
		h.Lookups[0].Stage != "pre-NAT" || h.Lookups[1].Stage != "post-NAT" || run.Output.(Path).Outcome != Delivered {
		t.Errorf("hop = %+v, %v", h, err)
	}
	// Without a port the rule naming a service is a doubt, and nothing translates.
	if h := policyRun(t, "firewall-routing.xml", "10.1.5.5", "198.51.100.10").Hops[0]; !strings.Contains(notes(h), "nat rule dnat-portal may match instead: service svc-rdp not known without a port") {
		t.Errorf("notes = %q", notes(h))
	}
	// Traffic to a bi-directional rule's translated address is translated back.
	h = policyRun(t, "firewall-routing.xml", "10.1.5.5", "198.51.100.20").Hops[0]
	if notes(h) != "nat rule static-pve, implicit (datacenter -> sdwan): destination 198.51.100.20 -> 10.1.100.250" || h.Flow.ToZone != "datacenter" {
		t.Errorf("notes = %q, to %s", notes(h), h.Flow.ToZone)
	}
}

// A configuration of another PAN-OS version checks PBF with the one schema: no
// note, nothing unresolved.
func TestAnotherVersionChecksPBFExactly(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-version-12.2.xml")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	n, _ := policyNet(t, "firewall-routing.xml")
	load := func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }
	run, err := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load}, simulate.Input{Flow: flow("10.1.5.5", "10.30.0.9")})
	h := run.Output.(Path).Hops[0]
	if err != nil || notes(h) != "" || h.Fidelity.Level() != "exact" {
		t.Errorf("hop = %+v, %v", h, err)
	}
	for _, st := range run.Stages {
		if len(st.Unresolved) > 0 {
			t.Errorf("%s: %v", st.Slug, st.Unresolved)
		}
	}
}

// With no source, any source could match; a sdwan arrival is sent to vsys2.
func TestPBFToAnotherVsysWithoutASource(t *testing.T) {
	t.Parallel()
	n, load := policyNet(t, "firewall-routing.xml")
	run, err := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load},
		simulate.Input{Flow: flow("10.30.0.7", "10.1.10.9"), Params: map[string]string{"device": "fw"}})
	if h := run.Output.(Path).Hops[0]; err != nil || notes(h) != "pbf rule sdwan-to-vsys2 may forward this packet to vsys2" {
		t.Errorf("notes = %q, %v", notes(h), err)
	}
	run, _ = Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load},
		simulate.Input{Flow: flow("", "10.1.10.9"), Params: map[string]string{"device": "fw"}})
	// No source and no ingress: the vsys is unknown when PBF runs, so PBF is not
	// evaluated; NAT, after the lookup, cannot rule out the first rule by zone.
	h := run.Output.(Path).Hops[0]
	if notes(h) != "the ingress is unknown: no source was given; nat rule snat-out may match instead: the ingress zone is unknown; the source is unknown" ||
		!strings.Contains(h.Fidelity.String(), "policy-based forwarding") {
		t.Errorf("notes = %q, fidelity %s", notes(h), h.Fidelity)
	}
}

func TestPolicyLoadsOnlyAKnownVsys(t *testing.T) {
	t.Parallel()
	n, load := policyNet(t, "firewall-routing.xml")
	s := newState(&simulate.Env{Network: n, Load: load}, simulate.Input{Flow: flow("10.1.5.5", "10.1.10.9")})
	if _, ok := s.policy(&Hop{Device: "fw", Vsys: "vsys9"}); ok {
		t.Error("a vsys the configuration lacks has no policy")
	}
	if _, ok := s.policy(&Hop{Device: "fw", Vsys: "vsys1"}); !ok {
		t.Error("vsys1")
	}
}

// A translated port, and a dynamic destination resolved through Env.Resolve.
func TestDestinationNATPortAndFQDN(t *testing.T) {
	t.Parallel()
	n, load := policyNet(t, "firewall-nat-routing.xml")
	env := &simulate.Env{Network: n, Load: load, Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
		if name != "portal.example.com" {
			t.Errorf("resolved %s", name)
		}
		return []netip.Addr{netip.MustParseAddr("10.1.10.101")}, nil
	}}
	f := flow("10.1.5.5", "198.51.100.40")
	f.Protocol, f.DestPort = "tcp", 3389
	run, _ := Simulation{}.Run(context.Background(), env, simulate.Input{Flow: f})
	if h := run.Output.(Path).Hops[0]; !strings.Contains(notes(h), "destination 198.51.100.40 -> 10.1.10.100:3390") || h.PostNAT.DestPort != 3390 {
		t.Errorf("port: %q", notes(h))
	}
	run, _ = Simulation{}.Run(context.Background(), env, simulate.Input{Flow: flow("10.1.5.5", "198.51.100.41")})
	if h := run.Output.(Path).Hops[0]; !strings.Contains(notes(h), "destination 198.51.100.41 -> 10.1.10.101") {
		t.Errorf("fqdn: %q", notes(h))
	}
}

// A translated destination the firewall has no route to is dropped there: the
// rule translates to 10.1.10.100, and this firewall has no route to it.
func TestTheTranslatedDestinationHasNoRoute(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-nat-routing.xml")
	if err != nil {
		t.Fatal(err)
	}
	n := netOf(dev("fw", []resolve.InterfaceState{iface("ethernet1/4", "sdwan", "default", "10.30.0.1/24")},
		route("default", "10.30.0.0/24", "ethernet1/4", "0.0.0.0"),
		route("default", "198.51.100.40/32", "ethernet1/4", "10.30.0.254"),
	))
	load := func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }
	f := flow("10.1.5.5", "198.51.100.40")
	f.Protocol, f.DestPort = "tcp", 3389
	run, _ := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load},
		simulate.Input{Flow: f, Params: map[string]string{"device": "fw", "router": "default"}})
	p := run.Output.(Path)
	if p.Outcome != Dropped || !strings.Contains(p.End, "no route to the translated 10.1.10.100") {
		t.Errorf("path = %+v", p)
	}
}

// withIndexes is a target over a vsys of cfg with its index provider, as a
// loader gives it.
func withIndexes(cfg *config.Config, vsys string) simulate.Target {
	sc := config.Scope{Sort: config.ScopeVsys, Name: vsys}
	return simulate.Target{Config: cfg, Indexes: index.NewSet(cfg).Provider(sc)}
}

// The PBF stage matches the flow's service (L3): on the same addresses, tcp/22
// takes the no-pbf rule and routing decides; tcp/443 and udp/22 reach the
// forward rule, which makes the hop inferred. A no-pbf rule that only may match is
// named in the stage, and the scan goes on.
func TestPBFStageMatchesTheService(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-pbf-service.xml")
	if err != nil {
		t.Fatal(err)
	}
	n := netOf(dev("fw", []resolve.InterfaceState{
		iface("ethernet1/1", "home", "default", "10.88.3.1/24"),
		iface("ethernet1/2", "wan", "default", "10.88.9.1/24"),
		iface("ethernet1/3", "lab", "default", "10.88.4.1/24"),
	},
		route("default", "10.88.3.0/24", "ethernet1/1", "0.0.0.0"),
		route("default", "10.88.9.0/24", "ethernet1/2", "0.0.0.0"),
		route("default", "10.88.4.0/24", "ethernet1/3", "0.0.0.0"),
	))
	load := func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }
	for _, tc := range []struct {
		src, proto string
		port       uint16
		pbf        []string
		detail     string
	}{
		{"10.88.3.5", "tcp", 22, nil, "no-pbf rule ssh-no-pbf leaves the packet to routing"},
		{"10.88.3.5", "tcp", 443, []string{"home-out"}, "pbf rule home-out may forward this packet to ethernet1/4 via 198.18.0.1"},
		{"10.88.3.5", "udp", 22, []string{"home-out"}, "pbf rule home-out may forward this packet to ethernet1/4 via 198.18.0.1"},
		{"10.88.4.5", "tcp", 22, []string{"lab-out"}, "pbf rule lab-out may forward this packet to ethernet1/4; " +
			"no-pbf rule lab-app-no-pbf may match (the rule names an application, which is not evaluated)"},
	} {
		f := flow(tc.src, "10.88.9.5")
		f.Protocol, f.DestPort = tc.proto, tc.port
		run, err := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load}, simulate.Input{Flow: f})
		if err != nil {
			t.Fatal(err)
		}
		h := run.Output.(Path).Hops[0]
		var detail string
		for _, st := range run.Stages {
			if strings.HasSuffix(st.Slug, "pbf") {
				detail = st.Detail
			}
		}
		if !slices.Equal(h.PBF, tc.pbf) || detail != tc.detail {
			t.Errorf("%s %s/%d: pbf %v, detail %q", tc.src, tc.proto, tc.port, h.PBF, detail)
		}
	}
}

// §4.7: PBF keeps doubt.application for a rule with an application, also with a
// flow application and application data. App-based PBF uses the App-ID cache,
// so the first session of an application does not match by application.
func TestPBFKeepsTheApplicationDoubt(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-pbf-service.xml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "apps.xml.gz")
	testconfig.Content(t, path)
	data, err := appid.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	n := netOf(dev("fw", []resolve.InterfaceState{
		iface("ethernet1/2", "wan", "default", "10.88.9.1/24"),
		iface("ethernet1/3", "lab", "default", "10.88.4.1/24"),
	},
		route("default", "10.88.9.0/24", "ethernet1/2", "0.0.0.0"),
		route("default", "10.88.4.0/24", "ethernet1/3", "0.0.0.0"),
	))
	load := func(_, vsys string) (simulate.Target, error) {
		tg := withIndexes(cfg, vsys)
		tg.Providers.Apps = data
		return tg, nil
	}
	f := flow("10.88.4.5", "10.88.9.5")
	f.Protocol, f.DestPort, f.Application = "tcp", 22, "ssl"
	run, err := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load}, simulate.Input{Flow: f})
	if err != nil {
		t.Fatal(err)
	}
	h := run.Output.(Path).Hops[0]
	found := false
	for _, d := range h.PBFDoubts {
		found = found || d.Code == "doubt.application" && strings.Contains(d.Text, "lab-app-no-pbf")
	}
	if !found {
		t.Errorf("PBF doubts %v", h.PBFDoubts)
	}
}
