package routing

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/topology"
)

// network is simulate.Network over fixed data.
type network struct {
	names []string
	data  map[string]simulate.DeviceData
}

func netOf(devs ...simulate.DeviceData) *network {
	n := &network{data: map[string]simulate.DeviceData{}}
	for _, d := range devs {
		n.names = append(n.names, d.Name)
		n.data[d.Name] = d
	}
	return n
}

func (n *network) Devices() []string { return n.names }

func (n *network) Device(name string) (simulate.DeviceData, error) {
	d, ok := n.data[name]
	if !ok {
		return d, fmt.Errorf("no snapshot of %s", name)
	}
	return d, nil
}

// labNet is the lab as data: fw01 and fw02 joined by 198.19.0.0/24.
func labNet() *network {
	return netOf(
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
			route("default", "198.19.255.254/32", "tunnel.1", "0.0.0.0"),
			route("lte", "198.19.11.0/24", "ethernet1/7", "0.0.0.0"),
		),
		dev("fw02", []resolve.InterfaceState{
			iface("ethernet1/1", "wan", "default", "192.168.0.138/24"),
			iface("vlan.1", "home", "default", "198.18.1.1/24"),
			iface("vlan.32", "labor", "default", "198.19.0.1/24"),
			iface("vlan.100", "labor", "default", "198.18.100.254/24"),
		},
			route("default", "0.0.0.0/0", "ethernet1/1", "192.168.0.1"),
			route("default", "198.18.0.0/15", "vlan.32", "198.19.0.254"),
			route("default", "198.18.1.0/24", "vlan.1", "0.0.0.0"),
			route("default", "198.19.0.0/24", "vlan.32", "0.0.0.0"),
			route("default", "198.18.100.0/24", "vlan.100", "0.0.0.0"),
			resolve.FIBRoute{Router: "default", Destination: netip.MustParsePrefix("198.19.0.1/32"), Interface: "vlan.32", NextHop: "0.0.0.0", NextHopType: resolve.NextHopLocal},
		),
	)
}

func flow(src, dst string) simulate.Flow {
	f := simulate.Flow{}
	if src != "" {
		f.Source = simulate.Addr(netip.MustParseAddr(src))
	}
	f.Destination = simulate.Addr(netip.MustParseAddr(dst))
	return f
}

func simulateOn(t *testing.T, n simulate.Network, f simulate.Flow, params map[string]string) (simulate.Run, Path, error) {
	t.Helper()
	env := &simulate.Env{Network: n}
	run, err := Simulation{}.Run(context.Background(), env, simulate.Input{Flow: f, Params: params})
	p, _ := run.Output.(Path)
	return run, p, err
}

func trail(p Path) string {
	var out []string
	for _, h := range p.Hops {
		out = append(out, fmt.Sprintf("%s(%s->%s)", h.Device, h.Flow.FromZone, h.Flow.ToZone))
	}
	return strings.Join(out, " ")
}

func TestAPathLeavesTheEstate(t *testing.T) {
	t.Parallel()
	run, p, err := simulateOn(t, labNet(), flow("198.18.10.5", "8.8.8.8"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := trail(p); got != "fw01(server->transport) fw02(labor->wan)" {
		t.Errorf("trail = %s", got)
	}
	if p.Outcome != LeftEstate || p.End != "192.168.0.1   leaves the estate (not in the inventory)" || p.Placed != topology.PlacedConnected {
		t.Errorf("path = %+v", p)
	}
	if run.Fidelity.Level() != "undermatch" || run.Device != "fw01" || run.Vsys != "vsys1" {
		t.Errorf("run = %s %s/%s", run.Fidelity, run.Device, run.Vsys)
	}
	h := p.Hops[0]
	if h.In.Interface != "ethernet1/2" || h.Out.Interface != "ethernet1/1" || h.Lookups[0].Match.Destination.String() != "0.0.0.0/0" ||
		h.Flow.Source.String() != "198.18.10.5" || h.Flow.Destination.String() != "8.8.8.8" {
		t.Errorf("hop 1 = %+v", h)
	}
	var slugs []string
	for _, st := range run.Stages {
		slugs = append(slugs, st.Slug)
	}
	if strings.Join(slugs[:6], ",") != "place,hop1/pbf,hop1/lookup,hop1/zones,hop1/nat,hop1/next" || len(slugs) != 11 {
		t.Errorf("stages = %v", slugs)
	}
}

func TestAPathIsDelivered(t *testing.T) {
	t.Parallel()
	run, p, err := simulateOn(t, labNet(), flow("198.18.1.10", "198.18.10.100"), nil)
	if err != nil || trail(p) != "fw02(home->labor) fw01(transport->server)" || p.Outcome != Delivered ||
		p.End != "198.18.10.100   delivered" {
		t.Errorf("path = %s %+v, %v", trail(p), p, err)
	}
	// PBF and NAT are not checked yet, so the run over-matches.
	if run.Fidelity.Level() != "overmatch" {
		t.Errorf("fidelity = %s", run.Fidelity)
	}
}

// The destination is fw02's own address on the link: the path ends on fw02.
func TestAPathTerminatesOnAFirewall(t *testing.T) {
	t.Parallel()
	_, p, err := simulateOn(t, labNet(), flow("198.18.10.5", "198.19.0.1"), nil)
	if err != nil || trail(p) != "fw01(server->transport) fw02(labor->labor)" || p.Outcome != Local ||
		p.End != "198.19.0.1   terminates on fw02" {
		t.Errorf("path = %s %+v, %v", trail(p), p, err)
	}
}

func TestAPathLeavesByATunnel(t *testing.T) {
	t.Parallel()
	_, p, err := simulateOn(t, labNet(), flow("198.18.10.5", "198.19.255.254"), nil)
	if err != nil || p.Outcome != LeftByInterface || p.End != "leaves by tunnel.1 (zone prisma)" {
		t.Errorf("path = %+v, %v", p, err)
	}
}

func TestTheStartNeedsAChoice(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		f      simulate.Flow
		params map[string]string
		want   string
	}{
		"tie":            {flow("198.18.100.50", "8.8.8.8"), nil, "fw01 ethernet1/5, fw02 vlan.100"},
		"default only":   {flow("8.8.4.4", "198.18.10.5"), nil, "only default routes reach 8.8.4.4"},
		"no source":      {flow("", "8.8.8.8"), nil, "give a source, or a start device with --device"},
		"routers":        {flow("", "8.8.8.8"), map[string]string{"device": "fw01"}, "fw01 has several routers; name one with --router: default, lte"},
		"no such router": {flow("", "8.8.8.8"), map[string]string{"device": "fw01", "router": "x"}, `fw01 has no router "x"`},
		"no such device": {flow("", "8.8.8.8"), map[string]string{"device": "fw09"}, "cannot start on fw09"},
		"ipv6":           {simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr("2001:db8::1"))}, nil, "IPv6"},
		"ipv6 source": {simulate.Flow{
			Source:      simulate.Addr(netip.MustParseAddr("2001:db8::1")),
			Destination: simulate.Addr(netip.MustParseAddr("192.0.2.1")),
		}, nil, "IPv6"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, _, err := simulateOn(t, labNet(), tc.f, tc.params)
			var ce *simulate.ChoiceError
			if !errors.As(err, &ce) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v", err)
			}
		})
	}
	if _, err := (Simulation{}).Run(context.Background(), &simulate.Env{}, simulate.Input{}); err == nil {
		t.Error("a run without a network fails")
	}
}

func TestAGivenStart(t *testing.T) {
	t.Parallel()
	// No source: the ingress is unknown.
	_, p, err := simulateOn(t, labNet(), flow("", "8.8.8.8"), map[string]string{"device": "fw01", "router": "default"})
	if err != nil || p.Placed != topology.PlacedGiven || p.Hops[0].Flow.FromZone != "" || !strings.Contains(strings.Join(p.Hops[0].Notes, ";"), "ingress is unknown") {
		t.Errorf("path = %+v, %v", p, err)
	}
	// A source connected on the device gives the ingress.
	_, p, _ = simulateOn(t, labNet(), flow("198.18.100.7", "8.8.8.8"), map[string]string{"device": "fw02"})
	if p.Hops[0].In.Interface != "vlan.100" {
		t.Errorf("connected ingress = %+v", p.Hops[0].In)
	}
	// A source not connected: the interface its return route leaves by.
	_, p, _ = simulateOn(t, labNet(), flow("198.18.10.9", "8.8.8.8"), map[string]string{"device": "fw02"})
	if p.Hops[0].In.Interface != "vlan.32" {
		t.Errorf("routed ingress = %+v", p.Hops[0].In)
	}
	// A router without a return route to the source leaves the ingress unknown.
	_, p, _ = simulateOn(t, labNet(), flow("10.9.9.9", "198.19.11.5"), map[string]string{"device": "fw01", "router": "lte"})
	if p.Hops[0].In.Interface != "" || p.Outcome != Delivered {
		t.Errorf("lte = %+v", p)
	}
}

func TestARoutedStartIsInferred(t *testing.T) {
	t.Parallel()
	run, p, err := simulateOn(t, labNet(), flow("198.18.20.5", "8.8.8.8"), nil)
	if err != nil || p.Placed != topology.PlacedRouted || p.PlacedVia != "198.18.0.0/15" || p.Hops[0].Device != "fw02" ||
		run.Stages[0].Fidelity.Level() != "inferred" {
		t.Errorf("path = %+v, %v", p, err)
	}
}

func TestDropsAndUnknownRoutes(t *testing.T) {
	t.Parallel()
	n := netOf(dev("a", []resolve.InterfaceState{iface("e1", "in", "r", "10.0.0.1/24")},
		route("r", "10.0.0.0/24", "e1", "0.0.0.0"),
		resolve.FIBRoute{Router: "r", Destination: netip.MustParsePrefix("10.66.0.0/16"), Interface: "e1", NextHop: "0.0.0.0", NextHopType: "7"},
	))
	_, p, _ := simulateOn(t, n, flow("10.0.0.5", "192.0.2.1"), nil)
	if p.Outcome != Dropped || p.End != "dropped on a: no route to 192.0.2.1" {
		t.Errorf("no route = %+v", p)
	}
	run, p, _ := simulateOn(t, n, flow("10.0.0.5", "10.66.1.1"), nil)
	if p.Outcome != Unresolved || !strings.Contains(p.End, "next-hop type 7") || len(run.Stages[2].Unresolved) != 1 {
		t.Errorf("unknown type = %+v", p)
	}
}

func TestECMPFollowsOneAndNamesTheOthers(t *testing.T) {
	t.Parallel()
	n := netOf(
		dev("a", []resolve.InterfaceState{iface("e0", "in", "r", "10.9.0.1/24"), iface("e1", "out", "r", "10.0.0.1/24")},
			route("r", "10.9.0.0/24", "e0", "0.0.0.0"),
			route("r", "172.16.0.0/12", "e1", "10.0.0.3"),
			route("r", "172.16.0.0/12", "e1", "10.0.0.2"),
			route("r", "172.16.0.0/12", "e1", "10.0.0.9")),
		dev("b", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.2/24")}),
		dev("c", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.3/24")}),
	)
	run, p, _ := simulateOn(t, n, flow("10.9.0.5", "172.16.1.1"), nil)
	h := p.Hops[0]
	if len(h.ECMP) != 2 || h.ECMP[0] != (NotFollowed{NextHop: "10.0.0.3", Reaches: "c"}) || h.ECMP[1].Reaches != "" {
		t.Errorf("ecmp = %+v", h.ECMP)
	}
	if p.Hops[1].Device != "b" || h.Fidelity.Level() != "undermatch" || run.Fidelity.Level() != "undermatch" {
		t.Errorf("path = %s, hop fidelity %s", trail(p), h.Fidelity)
	}
}

// Two devices sending a net to each other, with snapshots of different ages.
func TestALoop(t *testing.T) {
	t.Parallel()
	a := dev("a", []resolve.InterfaceState{iface("e0", "in", "r", "10.9.0.1/24"), iface("e1", "z", "r", "10.0.0.1/30")},
		route("r", "10.9.0.0/24", "e0", "0.0.0.0"), route("r", "0.0.0.0/0", "e1", "10.0.0.2"))
	b := dev("b", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.2/30")}, route("r", "0.0.0.0/0", "e1", "10.0.0.1"))
	b.TakenAt = time.Unix(100, 0)
	_, p, _ := simulateOn(t, netOf(a, b), flow("10.9.0.5", "8.8.8.8"), nil)
	if p.Outcome != Loop || p.End != "loop: a -> b -> a" || !strings.Contains(strings.Join(p.Hops[1].Notes, ";"), "different times") {
		t.Errorf("loop = %+v", p)
	}
}

func TestTooManyHops(t *testing.T) {
	t.Parallel()
	var devs []simulate.DeviceData
	for i := 0; i <= MaxHops; i++ {
		ifs := []resolve.InterfaceState{iface("in", "z", "r", fmt.Sprintf("10.%d.0.2/30", i))}
		if i == 0 {
			ifs = append(ifs, iface("src", "z", "r", "10.200.0.1/24"))
		}
		ifs = append(ifs, iface("out", "z", "r", fmt.Sprintf("10.%d.0.1/30", i+1)))
		devs = append(devs, dev(fmt.Sprintf("d%02d", i), ifs, route("r", "0.0.0.0/0", "out", fmt.Sprintf("10.%d.0.2", i+1))))
	}
	run, p, _ := simulateOn(t, netOf(devs...), flow("10.200.0.5", "8.8.8.8"), nil)
	if p.Outcome != TooLong || len(p.Hops) != MaxHops || run.Fidelity.Level() != "undermatch" {
		t.Errorf("path = %s, %s", p.Outcome, run.Fidelity)
	}
}

func TestANextHopWithTwoOwners(t *testing.T) {
	t.Parallel()
	n := netOf(
		dev("a", []resolve.InterfaceState{iface("e0", "in", "r", "10.9.0.1/24"), iface("e1", "z", "r", "10.0.0.1/24")},
			route("r", "10.9.0.0/24", "e0", "0.0.0.0"), route("r", "0.0.0.0/0", "e1", "10.0.0.2")),
		dev("b", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.2/24")}),
		dev("c", []resolve.InterfaceState{iface("e1", "z", "r", "10.0.0.2/24")}),
	)
	_, p, _ := simulateOn(t, n, flow("10.9.0.5", "8.8.8.8"), nil)
	if p.Outcome != Unresolved || !strings.Contains(p.End, "owned by b, c") {
		t.Errorf("path = %+v", p)
	}
}

func TestADeviceWithoutASnapshotIsAHole(t *testing.T) {
	t.Parallel()
	n := labNet()
	n.names = append(n.names, "fw03")
	run, p, err := simulateOn(t, n, flow("198.18.10.5", "8.8.8.8"), nil)
	if err != nil || len(run.Stages[0].Unresolved) != 1 || !strings.Contains(run.Stages[0].Unresolved[0].Reason, "fw03 cannot be read") ||
		p.Outcome != LeftEstate {
		t.Errorf("run = %+v, %v", run.Stages[0], err)
	}
}

func TestRIBAlternates(t *testing.T) {
	t.Parallel()
	n := labNet()
	d := n.data["fw01"]
	d.RIB = []resolve.RIBRoute{
		{Router: "default", Destination: netip.MustParsePrefix("0.0.0.0/0"), Protocol: "static", Distance: 200},
		{Router: "default", Destination: netip.MustParsePrefix("0.0.0.0/0"), Protocol: "static", Distance: 10, Selected: true},
		{Router: "default", Destination: netip.MustParsePrefix("8.0.0.0/8"), Protocol: "bgp", Distance: 20},
		{Router: "lte", Destination: netip.MustParsePrefix("0.0.0.0/0"), Protocol: "static"},
	}
	n.data["fw01"] = d
	_, p, _ := simulateOn(t, n, flow("198.18.10.5", "8.8.8.8"), map[string]string{"rib": "true"})
	alts := p.Hops[0].Alternates
	if p.Hops[0].Lookups[0].Protocol != "static" || p.Hops[1].Lookups[0].Protocol != "" {
		t.Errorf("protocols = %+v %+v", p.Hops[0].Lookups, p.Hops[1].Lookups)
	}
	if len(alts) != 3 || alts[0].Protocol != "bgp" || !alts[1].Selected || alts[2].Distance != 200 {
		t.Errorf("alternates = %+v", alts)
	}
	// fw02 has no routing table stored: a hole, only because --rib asked.
	run, _, _ := simulateOn(t, n, flow("198.18.10.5", "8.8.8.8"), map[string]string{"rib": "true"})
	if run.Fidelity.Level() != "undermatch" || !strings.Contains(run.Stages[len(run.Stages)-4].Unresolved[0].Reason, "fw02's snapshot has no routing table") {
		t.Errorf("stages = %+v", run.Stages[len(run.Stages)-4])
	}
}

// A path from vsys1 into vsys2 on one firewall: two boxes, joined by the external
// zones of the configuration.
func TestAVsysCrossing(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-intervsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	in := iface("ethernet1/1", "trust", "default", "10.1.0.1/24")
	out := iface("ethernet1/2", "dmz", "default", "10.2.0.1/24")
	out.Vsys = "2"
	n := netOf(dev("fw", []resolve.InterfaceState{in, out},
		route("default", "10.1.0.0/24", "ethernet1/1", "0.0.0.0"), route("default", "10.2.0.0/24", "ethernet1/2", "0.0.0.0")))
	load := func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg}, nil }
	run, err := Simulation{}.Run(context.Background(), &simulate.Env{Network: n, Load: load}, simulate.Input{Flow: flow("10.1.0.5", "10.2.0.9")})
	p := run.Output.(Path)
	if err != nil || trail(p) != "fw(trust->to-vsys2) fw(from-vsys1->dmz)" || p.Hops[1].Vsys != "vsys2" || p.Outcome != Delivered {
		t.Errorf("path = %s %+v, %v", trail(p), p, err)
	}
	// Without external zones in the configuration, placeholders, and Inferred.
	run, _ = Simulation{}.Run(context.Background(), &simulate.Env{Network: n}, simulate.Input{Flow: flow("10.1.0.5", "10.2.0.9")})
	p = run.Output.(Path)
	if trail(p) != "fw(trust->external) fw(external->dmz)" || p.Hops[0].Fidelity.Level() != "overmatch" && p.Hops[0].Fidelity.Level() != "inferred" {
		t.Errorf("placeholders = %s, %s", trail(p), p.Hops[0].Fidelity)
	}
}

func TestHiddenFirewalls(t *testing.T) {
	t.Parallel()
	n := labNet()
	n.names = append(n.names, "fw05")
	n.data["fw05"] = dev("fw05", []resolve.InterfaceState{iface("ethernet1/1", "vw-in", "")})
	n.data["fw02"] = dev("fw02", append(n.data["fw02"].Interfaces, iface("ethernet1/2", "layer2", "")), n.data["fw02"].FIB...)
	_, p, _ := simulateOn(t, n, flow("198.18.10.5", "8.8.8.8"), nil)
	if len(p.Hidden) != 1 || p.Hidden[0] != "fw05 (Layer 2 or virtual wire)" {
		t.Errorf("hidden = %v", p.Hidden)
	}
}

func TestAnFQDNNamesTheAddressesNotTraced(t *testing.T) {
	t.Parallel()
	f := flow("198.18.10.5", "8.8.8.8")
	f.Destination = simulate.Endpoint{Name: "dns.example", Addrs: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}, Resolved: true}
	_, p, _ := simulateOn(t, labNet(), f, nil)
	if len(p.Notes) != 1 || p.Notes[0] != "dns.example resolved to 2 addresses; traced 8.8.8.8, not 8.8.4.4" {
		t.Errorf("notes = %v", p.Notes)
	}
}

func TestDescribe(t *testing.T) {
	t.Parallel()
	s := Simulation{}
	if s.Kind() != "routing" || s.Describe() == "" || len(s.Stages()) != 6 {
		t.Error("describe")
	}
	if (&simulate.ChoiceError{Question: "q"}).Error() != "q" || vsysName("vsys3") != "vsys3" || vsysName("") != "" {
		t.Error("helpers")
	}
}

// An ECMP member without a next-hop address reaches no node.
func TestECMPMemberWithoutAnAddress(t *testing.T) {
	t.Parallel()
	n := netOf(dev("a", []resolve.InterfaceState{iface("e0", "in", "r", "10.9.0.1/24"), iface("e1", "out", "r", "10.0.0.1/24")},
		route("r", "10.9.0.0/24", "e0", "0.0.0.0"),
		route("r", "172.16.0.0/12", "e1", "10.0.0.2"),
		route("r", "172.16.0.0/12", "e1", "unnumbered")))
	_, p, _ := simulateOn(t, n, flow("10.9.0.5", "172.16.1.1"), nil)
	if len(p.Hops[0].ECMP) != 1 || p.Hops[0].ECMP[0] != (NotFollowed{NextHop: "unnumbered"}) {
		t.Errorf("ecmp = %+v", p.Hops[0].ECMP)
	}
}

// unreadableNetwork has devices and no data for any of them.
type unreadableNetwork []string

func (n unreadableNetwork) Devices() []string { return n }
func (n unreadableNetwork) Device(name string) (simulate.DeviceData, error) {
	return simulate.DeviceData{}, &simulate.UnavailableError{Missing: []simulate.Missing{{Device: name, Reason: "no snapshot"}}}
}

// When every device in the inventory is unreadable, the source cannot be placed
// on any of them; that is missing data, not a question for the user.
func TestAnUnreadableEstateIsUnavailableNotAQuestion(t *testing.T) {
	t.Parallel()
	_, _, err := simulateOn(t, unreadableNetwork{"fw1", "fw2"}, flow("10.0.0.1", "8.8.8.8"), nil)
	u, ok := errors.AsType[*simulate.UnavailableError](err)
	if !ok || len(u.Missing) != 2 {
		t.Fatalf("err = %v, want an UnavailableError for both devices", err)
	}
}

// Naming an unreadable device with --device is also missing data, not a choice.
func TestAnUnreadableGivenDeviceIsUnavailable(t *testing.T) {
	t.Parallel()
	_, _, err := simulateOn(t, unreadableNetwork{"fw1"}, flow("", "8.8.8.8"), map[string]string{"device": "fw1"})
	if _, ok := errors.AsType[*simulate.UnavailableError](err); !ok {
		t.Errorf("err = %v, want an UnavailableError", err)
	}
}
