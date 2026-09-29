package routing

import (
	"context"
	"errors"
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
	want := "pbf rule branch-to-zscaler may forward this packet to tunnel.1 via 198.19.255.254; nat rule snat-out may change the source"
	if notes(h) != want || h.Fidelity.Level() != "inferred" {
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

// no-pbf leaves the packet to routing; a static NAT names its source; the next
// hop is Inferred because of it.
func TestNoPBFAndATranslationCarriesOn(t *testing.T) {
	p := policyRun(t, "firewall-routing.xml", "10.1.100.250", "8.8.8.8")
	if notes(p.Hops[0]) != "nat rule static-pve may change the source" {
		t.Errorf("hop 1 notes = %q", notes(p.Hops[0]))
	}
	if len(p.Hops) != 2 || notes(p.Hops[1]) != "nat on fw may change the addresses this hop sees" {
		t.Errorf("hop 2 = %+v", p.Hops[1])
	}
}

func TestDestinationNAT(t *testing.T) {
	if h := policyRun(t, "firewall-routing.xml", "10.1.5.5", "198.51.100.10").Hops[0]; notes(h) != "nat rule dnat-portal may change the destination" {
		t.Errorf("notes = %q", notes(h))
	}
	// Traffic to a bi-directional rule's translated address is translated back.
	if h := policyRun(t, "firewall-routing.xml", "10.1.5.5", "198.51.100.20").Hops[0]; notes(h) != "nat rule static-pve may change the destination (bi-directional)" {
		t.Errorf("notes = %q", notes(h))
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
	if err != nil || !strings.HasPrefix(notes(h), "schema: PBF and NAT checked with the 11.2") || h.Fidelity.Level() != "inferred" {
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
	if notes(h) != "the ingress is unknown: no source was given; nat rule snat-out may change the source" ||
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
