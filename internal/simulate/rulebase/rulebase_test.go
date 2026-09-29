package rulebase

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/okaiser/proteus/internal/config"
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

func TestPBF(t *testing.T) {
	v := routingVsys(t)
	branch := simulate.Port{Zone: "branch-vpn", Interface: "ethernet1/3"}
	if r, note, ok := v.PBF(ip("10.20.5.5"), ip("10.1.10.100"), branch); !ok || r.Name != "branch-to-zscaler" ||
		note != "pbf rule branch-to-zscaler may forward this packet to tunnel.1 via 198.19.255.254" {
		t.Errorf("forward: %s %q %v", r.Name, note, ok)
	}
	// By interface, destination negated: dc01 is excluded.
	if _, note, _ := v.PBF(ip("10.99.0.5"), ip("10.1.10.50"), branch); note != "pbf rule lab-by-interface may drop this packet" {
		t.Errorf("discard: %q", note)
	}
	if _, _, ok := v.PBF(ip("10.99.0.5"), ip("10.1.10.100"), branch); ok {
		t.Error("the negated destination")
	}
	if r, note, ok := v.PBF(ip("10.1.1.1"), ip("10.30.0.9"), simulate.Port{Zone: "datacenter", Interface: "ethernet1/2"}); !ok || note != "" || r.Name != "keep-routing" {
		t.Errorf("no-pbf: %s %q", r.Name, note)
	}
	if _, note, _ := v.PBF(ip("10.30.0.7"), ip("10.1.1.1"), simulate.Port{Zone: "sdwan", Interface: "ethernet1/4"}); note != "pbf rule sdwan-to-vsys2 may forward this packet to vsys2" {
		t.Errorf("to vsys: %q", note)
	}
}

func TestSidesAndHolds(t *testing.T) {
	v := routingVsys(t)
	src, dst := v.Sides(resolve.NAT, netip.Addr{}, ip("198.51.100.10"), func(int) (bool, bool) { return false, false })
	if src.GetCardinality() != 4 || !dst.Contains(1) {
		t.Errorf("src %v, dst %v", src.ToArray(), dst.ToArray())
	}
	bad := v
	bad.Scope = config.Scope{Sort: config.ScopeVsys, Name: "vsys9"}
	if s, d := bad.Sides(resolve.NAT, ip("1.1.1.1"), ip("1.1.1.1"), func(int) (bool, bool) { return false, false }); !s.IsEmpty() || !d.IsEmpty() {
		t.Error("an index that cannot be built returns no rule")
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
