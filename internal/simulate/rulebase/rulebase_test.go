package rulebase

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func routingVsys(t *testing.T) Vsys {
	t.Helper()
	cfg, _, err := config.Load("../../../testdata/config/firewall-routing.xml")
	if err != nil {
		t.Fatal(err)
	}
	v, ok := Load(func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg}, nil }, "fw", "vsys1")
	if !ok {
		t.Fatal("vsys1")
	}
	return v
}

func TestLoad(t *testing.T) {
	load := func(string, string) (simulate.Target, error) { return simulate.Target{}, errors.New("none") }
	if _, ok := Load(load, "fw", "vsys1"); ok {
		t.Error("a failing loader")
	}
	if _, ok := Load(nil, "fw", "vsys1"); ok {
		t.Error("no loader")
	}
	cfg, _, _ := config.Load("../../../testdata/config/firewall-routing.xml")
	ok := func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg}, nil }
	if _, found := Load(ok, "fw", "vsys9"); found {
		t.Error("a vsys the configuration lacks")
	}
	if _, found := Load(ok, "fw", ""); found {
		t.Error("an unknown vsys")
	}
}

func pbf(t *testing.T, v Vsys, src, dst string, in simulate.Port) PBFMatch {
	t.Helper()
	return v.PBF(ip(src), ip(dst), in)
}

func TestPBF(t *testing.T) {
	v := routingVsys(t)
	branch := simulate.Port{Zone: "branch-vpn", Interface: "ethernet1/3"}
	if m := pbf(t, v, "10.20.5.5", "10.1.10.100", branch); !m.Found || m.Rule.Name != "branch-to-zscaler" ||
		m.Note != "pbf rule branch-to-zscaler may forward this packet to tunnel.1 via 198.19.255.254" {
		t.Errorf("forward: %+v", m)
	}
	// By interface, destination negated: dc01 is excluded.
	if m := pbf(t, v, "10.99.0.5", "10.1.10.50", branch); m.Note != "pbf rule lab-by-interface may drop this packet" {
		t.Errorf("discard: %q", m.Note)
	}
	if m := pbf(t, v, "10.99.0.5", "10.1.10.100", branch); m.Found {
		t.Error("the negated destination")
	}
	dc := simulate.Port{Zone: "datacenter", Interface: "ethernet1/2"}
	if m := pbf(t, v, "10.1.1.1", "10.30.0.9", dc); !m.Found || m.Note != "" || m.Rule.Name != "keep-routing" {
		t.Errorf("no-pbf: %+v", m)
	}
	sdwan := simulate.Port{Zone: "sdwan", Interface: "ethernet1/4"}
	if m := pbf(t, v, "10.30.0.7", "10.1.1.1", sdwan); m.Note != "pbf rule sdwan-to-vsys2 may forward this packet to vsys2" {
		t.Errorf("to vsys: %q", m.Note)
	}
}

// A rulebase that cannot be indexed yields no rule and says so, never a silent
// "no rule": that would be a wrong answer that looks complete.
func TestAnUnbuildableIndexIsUnresolved(t *testing.T) {
	bad := routingVsys(t)
	bad.Scope = config.Scope{Sort: config.ScopeVsys, Name: "vsys9"}
	noNegation := func(int) (bool, bool) { return false, false }
	s, d, un := bad.Sides(resolve.NAT, ip("1.1.1.1"), ip("1.1.1.1"), noNegation)
	if !s.IsEmpty() || !d.IsEmpty() || s == d || len(un) != 1 || !strings.Contains(un[0].Reason, "not checked") {
		t.Errorf("Sides: %v %v %v", s.ToArray(), d.ToArray(), un)
	}
	if m := bad.PBF(ip("1.1.1.1"), ip("1.1.1.1"), simulate.Port{}); m.Found || len(m.Unresolved) != 1 {
		t.Errorf("PBF: %+v", m)
	}
}

func TestSidesAndHolds(t *testing.T) {
	v := routingVsys(t)
	src, dst, un := v.Sides(resolve.NAT, netip.Addr{}, ip("198.51.100.10"), func(int) (bool, bool) { return false, false })
	if len(un) != 0 || src.GetCardinality() != 4 || !dst.Contains(1) {
		t.Errorf("src %v, dst %v, unresolved %v", src.ToArray(), dst.ToArray(), un)
	}
	if !v.Holds("dc01", ip("10.1.10.100")) || v.Holds("dc01", ip("10.1.10.101")) || !v.Holds("10.0.0.0/8", ip("10.1.1.1")) {
		t.Error("Holds")
	}
}

func TestFromFits(t *testing.T) {
	if !FromFits(resolve.PBFRule{From: []string{"any"}}, simulate.Port{Zone: "x"}) ||
		!FromFits(resolve.PBFRule{FromKind: "interface", From: []string{"e1"}}, simulate.Port{}) ||
		FromFits(resolve.PBFRule{FromKind: "zone", From: []string{"a"}}, simulate.Port{Zone: "b"}) {
		t.Error("FromFits")
	}
}

func TestCertainty(t *testing.T) {
	if f := Certainty(resolve.NAT, nil); f.String() != simulate.Exact.String() {
		t.Errorf("no unresolved value: %s", f)
	}
	f := Certainty(resolve.PBF, []index.Unresolved{{Value: "x", Reason: "y"}})
	if !strings.Contains(f.String(), "undermatch") || !strings.Contains(f.String(), "pbf rule") {
		t.Errorf("an unresolved value: %s", f)
	}
}

func TestWithoutGap(t *testing.T) {
	un := []index.Unresolved{{Value: "a", Reason: "gap"}, {Value: "b", Reason: "other"}}
	if got := withoutGap(un, "gap"); len(got) != 1 || got[0].Value != "b" {
		t.Errorf("with a gap: %v", got)
	}
	if got := withoutGap(un, ""); len(got) != 2 {
		t.Errorf("without a gap: %v", got)
	}
}
