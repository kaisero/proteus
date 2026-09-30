package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/topology"
)

type fixedNet map[string]simulate.DeviceData

func (n fixedNet) Devices() []string {
	return []string{"fw01", "fw02"}
}

func (n fixedNet) Device(name string) (simulate.DeviceData, error) {
	d, ok := n[name]
	if !ok {
		return d, fmt.Errorf("no %s", name)
	}
	return d, nil
}

func ifst(name, zone, router, pfx string) resolve.InterfaceState {
	st := resolve.InterfaceState{Name: name, Zone: zone, Router: router, Vsys: "1"}
	if pfx != "" {
		p := netip.MustParsePrefix(pfx)
		st.Prefix, st.Addrs = p, []netip.Prefix{p}
	}
	return st
}

func fib(router, dst, ifc, nh string) resolve.FIBRoute {
	return resolve.FIBRoute{Router: router, Destination: netip.MustParsePrefix(dst), Interface: ifc, NextHop: nh, NextHopType: "0"}
}

var viewNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func viewNet() fixedNet {
	return fixedNet{
		"fw01": {Name: "fw01", TakenAt: viewNow.Add(-7 * time.Minute), Interfaces: []resolve.InterfaceState{
			ifst("ethernet1/1", "transport", "default", "198.19.0.254/24"),
			ifst("ethernet1/2", "server", "default", "198.18.10.1/24"),
		}, FIB: []resolve.FIBRoute{
			fib("default", "0.0.0.0/0", "ethernet1/1", "198.19.0.1"),
			fib("default", "198.18.10.0/24", "ethernet1/2", "0.0.0.0"),
			fib("default", "198.19.0.0/24", "ethernet1/1", "0.0.0.0"),
		}, RIB: []resolve.RIBRoute{{
			Router: "default", Destination: netip.MustParsePrefix("0.0.0.0/0"), Protocol: "static", Selected: true, Distance: 10,
			NextHops: []resolve.RIBNextHop{{IP: netip.MustParseAddr("198.19.0.1")}},
		}}},
		"fw02": {Name: "fw02", TakenAt: viewNow.Add(-2 * time.Hour), Interfaces: []resolve.InterfaceState{
			ifst("ethernet1/1", "wan", "default", "192.168.0.138/24"),
			ifst("vlan.32", "labor", "default", "198.19.0.1/24"),
		}, FIB: []resolve.FIBRoute{
			fib("default", "0.0.0.0/0", "ethernet1/1", "192.168.0.1"),
			fib("default", "198.18.0.0/15", "vlan.32", "198.19.0.254"),
			fib("default", "198.19.0.0/24", "vlan.32", "0.0.0.0"),
		}},
	}
}

func render(t *testing.T, src, dst string, params map[string]string, why bool) string {
	t.Helper()
	f := simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr(dst))}
	if src != "" {
		f.Source = simulate.Addr(netip.MustParseAddr(src))
	}
	run, err := routing.Simulation{}.Run(context.Background(), &simulate.Env{Network: viewNet()}, simulate.Input{Flow: f, Params: params})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	renderPath(&textOut{w: &b}, run, run.Output.(routing.Path), viewNow, why)
	return b.String()
}

func TestRenderAPath(t *testing.T) {
	t.Parallel()
	got := render(t, "198.18.20.5", "198.18.10.9", nil, false)
	want := `simulate routing 198.18.20.5 -> 198.18.10.9            fidelity: inferred

  198.18.20.5   placed by route 198.18.0.0/15 on fw02 (inferred)
     │ 198.19.0.0/24
  ┌─ fw02 ─ vsys1 ─ router default ─ snapshot 2h ────────┐
  │  zones   labor -> labor                              │
  │  in      vlan.32       198.19.0.1/24                 │
  │  out     vlan.32       198.19.0.1/24                 │
  │  route   198.18.0.0/15 via 198.19.0.254              │
  └──┬───────────────────────────────────────────────────┘
     │ 198.19.0.0/24   198.19.0.1 -> 198.19.0.254
  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 7m ────────┐
  │  zones   transport -> server                         │
  │  in      ethernet1/1   198.19.0.254/24               │
  │  out     ethernet1/2   198.18.10.1/24                │
  │  route   198.18.10.0/24  connected                   │
  └──┬───────────────────────────────────────────────────┘
     │ 198.18.10.0/24
  198.18.10.9   delivered

firewalls on the path: fw02 (labor -> labor), fw01 (transport -> server)
may be incomplete: not evaluated: policy-based forwarding, NAT
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// Every box of a path is as wide as the widest; --rib and --why add rows.
func TestRenderRIBAndWhy(t *testing.T) {
	t.Parallel()
	got := render(t, "198.18.10.5", "8.8.8.8", map[string]string{"rib": "true"}, true)
	for _, want := range []string{
		"│  route   0.0.0.0/0 via 198.19.0.1   static                       │\n",
		"│  alt     0.0.0.0/0 via 198.19.0.1   static, distance 10 (active) │\n",
		"┌─ fw02 ─ vsys1 ─ router default ─ snapshot 2h ────────────────────┐\n",
		"  192.168.0.1   leaves the estate (not in the inventory)\n",
		"may be incomplete: fw02's snapshot has no routing table; fetch it again; the path leaves the estate at 192.168.0.1",
		"  hop2/next      undermatch the path leaves the estate at 192.168.0.1\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestRenderWithoutASource(t *testing.T) {
	t.Parallel()
	got := render(t, "", "198.18.10.9", map[string]string{"device": "fw01"}, false)
	for _, want := range []string{
		"simulate routing (no source) -> 198.18.10.9", "  start on fw01, router default\n",
		"│  zones   ? -> server", "firewalls on the path: fw01 (? -> server)",
		"│  note    the ingress is unknown: no source was given",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// Hand-built paths for the rows a two-device lab does not produce.
func TestRenderRowsAndEnds(t *testing.T) {
	t.Parallel()
	pfx := netip.MustParsePrefix
	lk := routing.Lookup{Router: "r", Match: simulate.Match{
		Destination: pfx("10.0.0.0/8"),
		NextHops:    []resolve.FIBRoute{{NextHop: "10.1.0.2"}},
	}}
	hop := func(dev, vsys string, notes ...string) routing.Hop {
		return routing.Hop{
			Device: dev, Vsys: vsys, Lookups: []routing.Lookup{lk}, Notes: notes,
			In:  simulate.Port{Interface: "e1", Addr: pfx("10.0.0.1/24")},
			Out: simulate.Port{Interface: "tunnel.1"}, Flow: simulate.Flow{FromZone: "a", ToZone: "b"},
		}
	}
	h1 := hop("fw", "vsys1", "pbf rule x may drop this packet", "nat rule y may change the source", "schema: PBF and NAT checked with the 11.2 digest", "other")
	h1.ECMP = []routing.NotFollowed{{NextHop: "10.1.0.3", Reaches: "fw9"}, {NextHop: "10.1.0.4"}}
	h1.Alternates = []resolve.RIBRoute{{
		Destination: pfx("10.0.0.0/8"), Protocol: "static", Distance: 200,
		NextHops: []resolve.RIBNextHop{{Interface: "tunnel.1"}},
	}}
	h2 := hop("fw", "vsys2")
	p := routing.Path{
		Source: simulate.Addr(netip.MustParseAddr("10.0.0.5")), Destination: simulate.Addr(netip.MustParseAddr("10.9.9.9")),
		Placed: topology.PlacedConnected, Outcome: routing.LeftByInterface, End: "leaves by tunnel.1 (zone b)",
		Hops: []routing.Hop{h1, h2}, Hidden: []string{"fw5 (Layer 2 or virtual wire)"}, Notes: []string{"n.example resolved to 2 addresses"},
	}
	var b bytes.Buffer
	renderPath(&textOut{w: &b}, simulate.Run{Fidelity: simulate.Inferred}, p, viewNow, false)
	got := b.String()
	for _, want := range []string{
		"  note: n.example resolved to 2 addresses\n",
		"│  ecmp    2 other next hops not followed: 10.1.0.3 (fw9), 10.1.0.4",
		"│  pbf     rule x may drop this packet", "│  nat     rule y may change the source",
		"│  schema  PBF and NAT checked with the 11.2 digest", "│  note    other",
		"│  alt     10.0.0.0/8 via tunnel.1   static, distance 200",
		"│  out     tunnel.1 ", "     │ vsys1 -> vsys2\n", "     │ tunnel.1\n  leaves by tunnel.1 (zone b)\n",
		"may be on the path, not detected: fw5 (Layer 2 or virtual wire)\n",
		"may be incomplete: inferred: some hops rest on assumptions; see their notes\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// A path that stops inside a firewall has a closed box and no line out.
	p = routing.Path{
		Source: p.Source, Destination: p.Destination, Outcome: routing.Dropped, End: "dropped on fw: no route to 10.9.9.9",
		Hops: []routing.Hop{hop("fw", "vsys1")},
	}
	b.Reset()
	renderPath(&textOut{w: &b}, simulate.Run{Fidelity: simulate.Exact}, p, viewNow, false)
	if got := b.String(); !strings.Contains(got, "  └────") || strings.Contains(got, "┬") || strings.Contains(got, "may be incomplete") {
		t.Errorf("dropped:\n%s", got)
	}
}
