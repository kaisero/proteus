package resolve

import (
	"testing"

	"github.com/okaiser/panos-analyst/config"
)

func routingTarget(t *testing.T) *Target {
	t.Helper()
	cfg, _, err := config.Load("../testdata/config/firewall-routing.xml")
	if err != nil {
		t.Fatal(err)
	}
	tgs, err := Targets(cfg)
	if err != nil || len(tgs) != 1 {
		t.Fatalf("targets: %v %v", tgs, err)
	}
	return tgs[0]
}

func TestPBFRules(t *testing.T) {
	rs := routingTarget(t).PBFRules()
	if len(rs) != 5 {
		t.Fatalf("got %d PBF rules", len(rs))
	}
	fw := rs[0]
	if fw.Name != "branch-to-zscaler" || fw.FromKind != "zone" || fw.From[0] != "branch-vpn" ||
		fw.ActionKind != PBFForward || fw.EgressInterface != "tunnel.1" || fw.NextHop != "198.19.255.254" ||
		fw.Fields["source"][0] != "branch-networks" || fw.Position != 1 {
		t.Errorf("forward rule = %+v", fw)
	}
	byIf := rs[1]
	if byIf.FromKind != "interface" || byIf.From[0] != "ethernet1/3" || byIf.ActionKind != PBFDiscard || !byIf.NegateDestination {
		t.Errorf("interface rule = %+v", byIf)
	}
	if rs[2].ActionKind != PBFNoPBF {
		t.Errorf("no-pbf = %+v", rs[2])
	}
	if rs[3].ActionKind != PBFForwardToVsys || rs[3].ForwardVsys != "vsys2" || !rs[3].Disabled {
		t.Errorf("to vsys = %+v", rs[3])
	}
	if rules, _ := routingTarget(t).Rules(PBF); len(rules) != 5 || PBF.String() != "pbf" {
		t.Error("Rules(PBF)")
	}
}

func TestNATRules(t *testing.T) {
	rs := routingTarget(t).NATRules()
	if len(rs) != 4 {
		t.Fatalf("got %d NAT rules", len(rs))
	}
	snat, dnat, static, n64 := rs[0], rs[1], rs[2], rs[3]
	if snat.Source.Kind != DIPP || snat.Destination != nil || snat.ToInterface != "any" ||
		snat.NATType != "ipv4" || snat.Fields["from"][0] != "branch-vpn" || snat.Fields["to"][0] != "datacenter" {
		t.Errorf("snat = %+v", snat)
	}
	if dnat.Destination.Kind != StaticDestination || dnat.ToInterface != "ethernet1/2" || dnat.Service != "svc-rdp" {
		t.Errorf("dnat = %+v", dnat)
	}
	if static.Source.Kind != StaticIP || !static.Source.BiDirectional || static.Source.Addresses[0] != "198.51.100.20" {
		t.Errorf("static = %+v", static)
	}
	if n64.NATType != "nat64" {
		t.Errorf("nat64 = %+v", n64)
	}
}
