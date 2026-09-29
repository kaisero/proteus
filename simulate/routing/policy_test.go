package routing

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/resolve"
	"github.com/okaiser/panos-analyst/simulate"
)

// policyNet is one firewall carrying firewall-routing.xml's PBF and NAT rules, and
// an upstream device "up" with no configuration.
func policyNet(t *testing.T, file string) (*network, func(string, string) (simulate.Target, error)) {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/" + file)
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
	load := func(device, _ string) (simulate.Target, error) {
		if device != "fw" {
			return simulate.Target{}, errors.New("no configuration")
		}
		return simulate.Target{Config: cfg}, nil
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

func notes(h Hop) string { return strings.Join(h.Notes, "; ") }

func TestPBFForwardAndSourceNAT(t *testing.T) {
	p := policyRun(t, "firewall-routing.xml", "10.20.5.5", "10.1.10.100")
	h := p.Hops[0]
	want := "pbf rule branch-to-zscaler may forward this packet to tunnel.1 via 198.19.255.254; " +
		"nat rule snat-out (branch-vpn -> datacenter): source 10.20.5.5 -> 203.0.113.9"
	if notes(h) != want || h.Fidelity.Level() != "inferred" || h.PostNAT == nil || h.PostNAT.Source.String() != "203.0.113.9" {
		t.Errorf("notes = %q, fidelity %s", notes(h), h.Fidelity)
	}
}

// A PBF rule by interface, with a negated destination.
func TestPBFByInterface(t *testing.T) {
	if h := policyRun(t, "firewall-routing.xml", "10.99.0.5", "10.1.10.50").Hops[0]; notes(h) != "pbf rule lab-by-interface may drop this packet" {
		t.Errorf("notes = %q", notes(h))
	}
	// dc01 is the negated destination: the rule does not match, and nothing else does.
	if h := policyRun(t, "firewall-routing.xml", "10.99.0.5", "10.1.10.100").Hops[0]; notes(h) != "" || h.Fidelity.Level() != "exact" {
		t.Errorf("notes = %q, fidelity %s", notes(h), h.Fidelity)
	}
}

// no-pbf leaves the packet to routing; a static NAT translates the source, and
// the next hop sees the translated packet (spec §18 N5).
func TestNoPBFAndATranslationCarriesOn(t *testing.T) {
	p := policyRun(t, "firewall-routing.xml", "10.1.100.250", "8.8.8.8")
	if notes(p.Hops[0]) != "nat rule static-pve (datacenter -> sdwan): source 10.1.100.250 -> 198.51.100.20" {
		t.Errorf("hop 1 notes = %q", notes(p.Hops[0]))
	}
	if len(p.Hops) != 2 || p.Hops[1].Flow.Source.String() != "198.51.100.20" || notes(p.Hops[1]) != "" {
		t.Errorf("hop 2 = %+v", p.Hops[1])
	}
}

// A pool translation: later hops match against its first address, and say so.
func TestAPoolCarriesANote(t *testing.T) {
	p := policyRun(t, "firewall-nat-routing.xml", "10.1.100.250", "8.8.8.8")
	if len(p.Hops) != 2 || notes(p.Hops[1]) != "nat on fw translates the source to one of 198.51.100.64/29" ||
		p.Hops[1].Flow.Source.String() != "198.51.100.64" {
		t.Errorf("hops = %+v", p.Hops)
	}
}

// A destination NAT replaces the egress with the lookup of the translated
// destination, and the box shows both lookups (spec §18 N5).
func TestDestinationNAT(t *testing.T) {
	n, load := policyNet(t, "firewall-routing.xml")
	f := flow("10.30.0.7", "198.51.100.10")
	f.DestPort = 3389
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

func TestAVersionGapIsInferredNotUnresolved(t *testing.T) {
	cfg, _, err := config.Load("../../testdata/config/firewall-version-12.2.xml")
	if err != nil || cfg.VersionGap() == "" {
		t.Fatalf("fixture: %v", err)
	}
	n, _ := policyNet(t, "firewall-routing.xml")
	load := func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg}, nil }
	run, err := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load}, simulate.Input{Flow: flow("10.1.5.5", "10.30.0.9")})
	h := run.Output.(Path).Hops[0]
	if err != nil || !strings.HasPrefix(notes(h), "schema: PBF checked with the 11.2") || h.Fidelity.Level() != "inferred" {
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
	n, load := policyNet(t, "firewall-nat-routing.xml")
	env := &simulate.Env{Network: n, Load: load, Resolve: func(_ context.Context, name string) ([]netip.Addr, error) {
		if name != "portal.example.com" {
			t.Errorf("resolved %s", name)
		}
		return []netip.Addr{netip.MustParseAddr("10.1.10.101")}, nil
	}}
	f := flow("10.1.5.5", "198.51.100.40")
	f.DestPort = 3389
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
	cfg, _, err := config.Load("../../testdata/config/firewall-nat-routing.xml")
	if err != nil {
		t.Fatal(err)
	}
	n := netOf(dev("fw", []resolve.InterfaceState{iface("ethernet1/4", "sdwan", "default", "10.30.0.1/24")},
		route("default", "10.30.0.0/24", "ethernet1/4", "0.0.0.0"),
		route("default", "198.51.100.40/32", "ethernet1/4", "10.30.0.254"),
	))
	load := func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg}, nil }
	f := flow("10.1.5.5", "198.51.100.40")
	f.DestPort = 3389
	run, _ := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load},
		simulate.Input{Flow: f, Params: map[string]string{"device": "fw", "router": "default"}})
	p := run.Output.(Path)
	if p.Outcome != Dropped || !strings.Contains(p.End, "no route to the translated 10.1.10.100") {
		t.Errorf("path = %+v", p)
	}
}
