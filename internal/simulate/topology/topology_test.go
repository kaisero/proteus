package topology

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// iface is "name zone router address...".
func iface(name, zone, router string, addrs ...string) resolve.InterfaceState {
	st := resolve.InterfaceState{Name: name, Zone: zone, Router: router, Vsys: "1"}
	for _, a := range addrs {
		p := netip.MustParsePrefix(a)
		if st.Addrs == nil {
			st.Prefix = p
		}
		st.Addrs = append(st.Addrs, p)
	}
	return st
}

// route is "router destination interface next-hop".
func route(router, dst, ifc, nh string) resolve.FIBRoute {
	return resolve.FIBRoute{Router: router, Destination: netip.MustParsePrefix(dst), Interface: ifc, NextHop: nh, NextHopType: "0"}
}

func dev(name string, ifs []resolve.InterfaceState, fib ...resolve.FIBRoute) simulate.DeviceData {
	return simulate.DeviceData{Name: name, Interfaces: ifs, FIB: fib}
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// The lab's shape: fw01 and fw02 share 198.19.0.0/24 and 198.18.100.0/24.
func lab() *Topology {
	return NewTopology([]simulate.DeviceData{
		dev("fw01", []resolve.InterfaceState{
			iface("ethernet1/1", "transport", "default", "198.19.0.254/24"),
			iface("ethernet1/2", "server", "default", "198.18.10.1/24"),
			iface("ethernet1/5", "mgmt", "default", "198.18.100.1/24"),
			iface("ethernet1/7", "int-link-b", "lte", "198.19.11.1/24"),
			iface("tunnel.1", "prisma", "default"),
		},
			route("default", "0.0.0.0/0", "ethernet1/1", "198.19.0.1"),
			route("default", "198.18.10.0/24", "ethernet1/2", "0.0.0.0"),
			route("default", "198.19.0.0/24", "ethernet1/1", "0.0.0.0"),
			route("default", "198.18.100.0/24", "ethernet1/5", "0.0.0.0"),
			route("lte", "198.19.11.0/24", "ethernet1/7", "0.0.0.0"),
		),
		dev("fw02", []resolve.InterfaceState{
			iface("ethernet1/1", "wan", "default", "192.168.0.138/24"),
			iface("vlan.1", "home", "default", "198.18.1.1/24"),
			iface("vlan.32", "labor", "default", "198.19.0.1/24"),
			iface("vlan.100", "labor", "default", "198.18.100.254/24"),
			iface("ethernet1/2", "layer2", ""),
		},
			route("default", "0.0.0.0/0", "ethernet1/1", "192.168.0.1"),
			route("default", "198.18.0.0/15", "vlan.32", "198.19.0.254"),
			route("default", "198.18.1.0/24", "vlan.1", "0.0.0.0"),
			route("default", "198.19.0.0/24", "vlan.32", "0.0.0.0"),
			route("default", "198.18.100.0/24", "vlan.100", "0.0.0.0"),
		),
	})
}

func TestPlaceConnected(t *testing.T) {
	t.Parallel()
	pl, err := lab().Place(ip("198.18.10.5"))
	if err != nil || pl.How != PlacedConnected || pl.Port.Device != "fw01" || pl.Port.Interface != "ethernet1/2" ||
		pl.Port.Zone != "server" || len(pl.Ties) != 0 {
		t.Errorf("placement = %+v, %v", pl, err)
	}
}

// 198.18.100.0/24 is connected on both lab devices: a tie the admin resolves.
func TestPlaceTie(t *testing.T) {
	t.Parallel()
	pl, err := lab().Place(ip("198.18.100.50"))
	if err != nil || len(pl.Ties) != 2 || pl.Ties[0].Device != "fw01" || pl.Ties[1].Device != "fw02" {
		t.Errorf("placement = %+v, %v", pl, err)
	}
}

// 198.18.20.5 is connected nowhere. fw02's 198.18.0.0/15 leads to fw01, but fw01
// reaches it only by its default route, so the walk stops and fw02 is the start.
func TestPlaceRouted(t *testing.T) {
	t.Parallel()
	pl, err := lab().Place(ip("198.18.20.5"))
	if err != nil || pl.How != PlacedRouted || pl.Port.Device != "fw02" || pl.Port.Interface != "vlan.32" ||
		pl.Via.String() != "198.18.0.0/15" {
		t.Errorf("placement = %+v, %v", pl, err)
	}
}

// A transit node's route leads to the node nearer the source: the start is there.
func TestPlaceWalksTowardTheSource(t *testing.T) {
	t.Parallel()
	topo := NewTopology([]simulate.DeviceData{
		dev("edge", []resolve.InterfaceState{iface("e1", "out", "r", "10.0.0.1/30")},
			route("r", "172.16.0.0/12", "e1", "10.0.0.2")),
		dev("core", []resolve.InterfaceState{
			iface("c1", "in", "r", "10.0.0.2/30"), iface("c2", "branch", "r", "10.9.0.1/30"),
		}, route("r", "172.16.0.0/16", "c2", "10.9.0.2")),
	})
	pl, err := topo.Place(ip("172.16.5.5"))
	if err != nil || pl.Port.Device != "core" || pl.Port.Interface != "c2" || pl.Via.String() != "172.16.0.0/16" || len(pl.Ties) != 0 {
		t.Errorf("placement = %+v, %v", pl, err)
	}
}

func TestPlaceDefaultOnly(t *testing.T) {
	t.Parallel()
	if _, err := lab().Place(ip("8.8.8.8")); !errors.Is(err, ErrUnplaced) {
		t.Errorf("err = %v", err)
	}
}

func TestPlaceRoutedTie(t *testing.T) {
	t.Parallel()
	topo := NewTopology([]simulate.DeviceData{
		dev("a", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.1/30")}, route("r", "172.16.0.0/16", "e1", "10.0.0.2")),
		dev("b", []resolve.InterfaceState{iface("e1", "z", "r", "10.1.0.1/30")}, route("r", "172.16.0.0/16", "e1", "10.1.0.2")),
	})
	pl, err := topo.Place(ip("172.16.5.5"))
	if err != nil || len(pl.Ties) != 2 {
		t.Errorf("placement = %+v, %v", pl, err)
	}
}

// ECMP entries apart in the table come back grouped and ordered by next hop.
func TestLookupGroupsECMP(t *testing.T) {
	t.Parallel()
	topo := NewTopology([]simulate.DeviceData{dev("a", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.1/24")},
		route("r", "10.50.0.0/16", "e1", "10.0.0.9"),
		route("r", "10.0.0.0/24", "e1", "0.0.0.0"),
		route("r", "10.50.0.0/16", "e1", "10.0.0.3"),
		route("r", "10.60.0.0/16", "e1", "not-an-address"),
		route("r", "10.60.0.0/16", "e1", "10.0.0.4"),
		resolve.FIBRoute{Router: "r", IPv6: true, Destination: netip.MustParsePrefix("::/0")},
	)})
	m, ok := topo.Lookup("a", "r", ip("10.50.1.1"))
	if !ok || m.Destination.String() != "10.50.0.0/16" || len(m.NextHops) != 2 || m.First().NextHop != "10.0.0.3" {
		t.Errorf("match = %+v", m)
	}
	if m, _ := topo.Lookup("a", "r", ip("10.60.1.1")); m.First().NextHop != "10.0.0.4" {
		t.Errorf("an unreadable next hop sorts as text: %+v", m)
	}
	if _, ok := topo.Lookup("a", "r", ip("192.0.2.1")); ok {
		t.Error("no route")
	}
	if _, ok := topo.Lookup("a", "nope", ip("10.50.1.1")); ok {
		t.Error("no router")
	}
}

// Secondary and DHCP addresses own their address too; a /31 link works.
func TestOwnersAndPeers(t *testing.T) {
	t.Parallel()
	topo := NewTopology([]simulate.DeviceData{
		dev("a", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.0/31", "10.5.0.1/24", "203.0.113.5/29")}),
		dev("b", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.1/31"), iface("e2", "z", "r", "2001:db8::1/64")}),
		dev("c", []resolve.InterfaceState{iface("e9", "z", "r", "10.0.0.1/24")}), // same address, other net
	})
	if o := topo.Owners(ip("203.0.113.5")); len(o) != 1 || o[0].Device != "a" {
		t.Errorf("owners = %+v", o)
	}
	out, _ := topo.Interface("a", "e1")
	if p := topo.Peers(out, ip("10.0.0.1")); len(p) != 1 || p[0].Device != "b" {
		t.Errorf("peers = %+v", p)
	}
	if _, ok := topo.Interface("a", "nope"); ok {
		t.Error("no interface")
	}
	if got := topo.Routers("a"); len(got) != 0 {
		t.Errorf("routers = %v", got)
	}
}

func TestInterfaceWithoutAddress(t *testing.T) {
	t.Parallel()
	p, ok := lab().Interface("fw01", "tunnel.1")
	if !ok || p.Zone != "prisma" || p.Addr.IsValid() {
		t.Errorf("tunnel.1 = %+v", p)
	}
	if r := lab().Routers("fw01"); len(r) != 2 || r[0] != "default" || r[1] != "lte" {
		t.Errorf("routers = %v", r)
	}
	if n := lab().Nodes(); len(n) != 2 {
		t.Errorf("nodes = %v", n)
	}
}

func TestStart(t *testing.T) {
	t.Parallel()
	topo := lab()
	var ce *simulate.ChoiceError
	if _, _, _, err := topo.Start("fw01", "", ip("8.8.8.8")); !errors.As(err, &ce) || !strings.Contains(err.Error(), "default, lte") {
		t.Errorf("several routers: %v", err)
	}
	if _, _, _, err := topo.Start("fw01", "x", netip.Addr{}); !errors.As(err, &ce) {
		t.Errorf("no such router: %v", err)
	}
	if p, via, connected, err := topo.Start("fw02", "", ip("198.18.100.7")); err != nil || !connected || p.Interface != "vlan.100" || via.IsValid() {
		t.Errorf("connected: %+v %v %v %v", p, via, connected, err)
	}
	if p, via, connected, _ := topo.Start("fw02", "", ip("198.18.10.9")); connected || p.Interface != "vlan.32" || via != netip.MustParsePrefix("198.18.0.0/15") {
		t.Errorf("return route: %+v %v", p, via)
	}
	if p, via, _, _ := topo.Start("fw01", "lte", ip("10.9.9.9")); p.Interface != "" || p.Router != "lte" || via.IsValid() {
		t.Errorf("no route back: %+v %v", p, via)
	}
	if p, via, _, _ := topo.Start("fw01", "default", netip.Addr{}); p.Interface != "" || p.Device != "fw01" || via.IsValid() {
		t.Errorf("no source: %+v %v", p, via)
	}
}

func TestForward(t *testing.T) {
	t.Parallel()
	topo := NewTopology([]simulate.DeviceData{dev("a",
		[]resolve.InterfaceState{iface("e1", "out", "r", "10.0.0.1/24"), iface("e2", "in", "r", "10.9.0.1/24")},
		route("r", "0.0.0.0/0", "e1", "10.0.0.2"),
		route("r", "10.9.0.0/24", "e2", "0.0.0.0"),
		route("r", "172.16.0.0/12", "e1", "10.0.0.3"), route("r", "172.16.0.0/12", "e1", "10.0.0.4"),
		resolve.FIBRoute{Router: "r", Destination: netip.MustParsePrefix("10.66.0.0/16"), Interface: "e1", NextHop: "0.0.0.0", NextHopType: "7"},
		resolve.FIBRoute{Router: "r", Destination: netip.MustParsePrefix("10.8.0.1/32"), Interface: "e1", NextHop: "0.0.0.0", NextHopType: resolve.NextHopLocal},
	)})
	for _, tc := range []struct{ addr, out, end, level string }{
		{"8.8.8.8", "e1", "", "exact"},
		{"10.9.0.1", "e2", simulate.EndLocal, "exact"},
		{"10.8.0.1", "e1", simulate.EndLocal, "exact"},
		{"10.66.1.1", "e1", simulate.EndUnknownType, "undermatch"},
		{"172.16.1.1", "e1", "", "undermatch"},
	} {
		f := topo.Forward("a", "r", ip(tc.addr))
		if f.Out.Interface != tc.out || f.End != tc.end || f.Fidelity.Level() != tc.level {
			t.Errorf("%s: %+v", tc.addr, f)
		}
	}
	if f := topo.Forward("a", "none", ip("8.8.8.8")); f.End != simulate.EndNoRoute || f.Out.Device != "a" {
		t.Errorf("no route: %+v", f)
	}
}
