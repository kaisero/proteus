// Package topology is the estate as a routing simulation sees it: every
// firewall's interfaces and forwarding tables, who owns an address, which nets
// are connected where, and where a packet from a source enters. It is built once
// per run from simulate.Network data and is shared by the routing, NAT and
// security-policy simulations (spec §17, §18.4).
package topology

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/gaissmai/bart"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// Placed says how the start of a path was found.
type Placed string

// How a start is placed (spec §17 R2).
const (
	PlacedConnected Placed = "connected"
	PlacedRouted    Placed = "routed"
	PlacedGiven     Placed = "given"
)

// Placement is where a path starts: the node and the interface a packet from the
// source arrives on.
type Placement struct {
	Port simulate.Port
	How  Placed
	Via  netip.Prefix    // the route that placed a routed start
	Ties []simulate.Port // several equally good starts; the caller asks for --device
}

// ErrUnplaced is a source that only default routes reach: no node is nearer to it
// than another.
var ErrUnplaced = errors.New("only default routes reach the source")

// Topology is the estate's interfaces and forwarding tables, built once per run.
// It answers who owns an address, which nets are connected where, and where a
// node's table sends an address. IPv4 only (spec §17 R9).
type Topology struct {
	nodes  []string
	ports  map[string][]simulate.Port                            // node -> routed ports with an address
	byIf   map[string]map[string]simulate.Port                   // node -> interface -> port, address or not
	tables map[string]map[string]*bart.Table[[]resolve.FIBRoute] // node -> router -> table
}

// NewTopology indexes the nodes' data.
func NewTopology(devs []simulate.DeviceData) *Topology {
	t := &Topology{
		ports:  map[string][]simulate.Port{},
		byIf:   map[string]map[string]simulate.Port{},
		tables: map[string]map[string]*bart.Table[[]resolve.FIBRoute]{},
	}
	for _, d := range devs {
		t.nodes = append(t.nodes, d.Name)
		t.byIf[d.Name] = map[string]simulate.Port{}
		for _, i := range d.Interfaces {
			p := simulate.Port{Device: d.Name, Vsys: i.Vsys, Router: i.Router, Interface: i.Name, Zone: i.Zone}
			t.byIf[d.Name][i.Name] = p
			if i.Router == "" {
				continue
			}
			for _, a := range i.Addrs {
				if !a.Addr().Is4() {
					continue
				}
				p.Addr = a
				t.ports[d.Name] = append(t.ports[d.Name], p)
			}
		}
		t.tables[d.Name] = map[string]*bart.Table[[]resolve.FIBRoute]{}
		for _, r := range d.FIB {
			if r.IPv6 || !r.Destination.Addr().Is4() {
				continue
			}
			tb := t.tables[d.Name][r.Router]
			if tb == nil {
				tb = new(bart.Table[[]resolve.FIBRoute])
				t.tables[d.Name][r.Router] = tb
			}
			rs, _ := tb.Get(r.Destination)
			tb.Insert(r.Destination, append(rs, r))
		}
	}
	return t
}

// Nodes names the nodes, in the order given.
func (t *Topology) Nodes() []string { return t.nodes }

// Routers names a node's routers, sorted.
func (t *Topology) Routers(node string) []string {
	out := make([]string, 0, len(t.tables[node]))
	for r := range t.tables[node] {
		out = append(out, r)
	}
	slices.Sort(out)
	return out
}

// Interface returns a node's interface by name, with or without an address.
func (t *Topology) Interface(node, name string) (simulate.Port, bool) {
	p, ok := t.byIf[node][name]
	if !ok {
		return p, false
	}
	for _, q := range t.ports[node] {
		if q.Interface == name {
			return q, true
		}
	}
	return p, true
}

// Owners returns every port holding a as one of its addresses.
func (t *Topology) Owners(a netip.Addr) []simulate.Port {
	var out []simulate.Port
	for _, n := range t.nodes {
		for _, p := range t.ports[n] {
			if p.Addr.Addr() == a {
				out = append(out, p)
			}
		}
	}
	return out
}

// Peers returns the ports that own next hop nh in the link net of out: the
// devices a packet leaving by out towards nh reaches (spec §17 R6). The link-net
// check keeps two sites that reuse private addresses apart.
func (t *Topology) Peers(out simulate.Port, nh netip.Addr) []simulate.Port {
	var peers []simulate.Port
	for _, p := range t.Owners(nh) {
		if p.Device != out.Device && p.Link() == out.Link() {
			peers = append(peers, p)
		}
	}
	return peers
}

// Connected returns the ports whose net holds a, most specific net first; only
// the most specific length is kept, so a /30 inside a /24 wins.
func (t *Topology) Connected(a netip.Addr) []simulate.Port {
	var out []simulate.Port
	best := -1
	for _, n := range t.nodes {
		for _, p := range t.ports[n] {
			if !p.Addr.Contains(a) {
				continue
			}
			switch bits := p.Addr.Bits(); {
			case bits > best:
				best, out = bits, []simulate.Port{p}
			case bits == best:
				out = append(out, p)
			}
		}
	}
	return out
}

// Lookup is a longest-prefix match of a in one router's table.
func (t *Topology) Lookup(node, router string, a netip.Addr) (simulate.Match, bool) {
	tb := t.tables[node][router]
	if tb == nil {
		return simulate.Match{}, false
	}
	rs, ok := tb.Lookup(a)
	if !ok || len(rs) == 0 {
		return simulate.Match{}, false
	}
	hops := append([]resolve.FIBRoute(nil), rs...)
	slices.SortStableFunc(hops, func(a, b resolve.FIBRoute) int { return compareAddr(a.NextHop, b.NextHop) })
	return simulate.Match{Destination: hops[0].Destination, NextHops: hops}, true
}

// compareAddr orders next hops as addresses, and as text when one is not an address.
func compareAddr(a, b string) int {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return strings.Compare(a, b)
	}
	return x.Compare(y)
}

// Place finds where a packet from src enters the estate (spec §17 R2).
//
// A node with an interface in the source's net is the start (connected). Failing
// that, the node with the most specific non-default route to the source is, and
// its route's interface is the ingress: traffic is assumed to arrive where its
// return leaves (routed). A node whose route to the source leads to another node
// is not the start: the walk continues on that node, toward the source. Several
// equally good starts are ties; only default routes is ErrUnplaced.
func (t *Topology) Place(src netip.Addr) (Placement, error) {
	if conn := t.Connected(src); len(conn) > 0 {
		pl := Placement{Port: conn[0], How: PlacedConnected}
		if nodes(conn) > 1 {
			pl.Ties = conn
		}
		return pl, nil
	}
	type start struct {
		port simulate.Port
		via  netip.Prefix
	}
	var starts []start
	best := 0
	for _, n := range t.nodes {
		m, port, ok := t.towards(n, src)
		if !ok {
			continue
		}
		// Walk toward the source while the route leads to another node.
		seen := map[string]bool{n: true}
		for {
			peers := t.Peers(port, addrOf(m.First().NextHop))
			if len(peers) != 1 || seen[peers[0].Device] {
				break
			}
			nm, np, ok := t.towards(peers[0].Device, src)
			if !ok {
				break
			}
			seen[peers[0].Device] = true
			m, port = nm, np
		}
		bits := m.Destination.Bits()
		switch {
		case bits > best:
			best, starts = bits, []start{{port, m.Destination}}
		case bits == best && !hasDevice(starts, port.Device, func(s start) string { return s.port.Device }):
			starts = append(starts, start{port, m.Destination})
		}
	}
	if len(starts) == 0 {
		return Placement{}, ErrUnplaced
	}
	pl := Placement{Port: starts[0].port, How: PlacedRouted, Via: starts[0].via}
	if len(starts) > 1 {
		for _, s := range starts {
			pl.Ties = append(pl.Ties, s.port)
		}
	}
	return pl, nil
}

// towards is a node's most specific non-default route to a, over all its routers,
// and the port it leaves by.
func (t *Topology) towards(node string, a netip.Addr) (simulate.Match, simulate.Port, bool) {
	var best simulate.Match
	var port simulate.Port
	found := false
	for _, r := range t.Routers(node) {
		m, ok := t.Lookup(node, r, a)
		if !ok || m.Destination.Bits() == 0 {
			continue
		}
		if !found || m.Destination.Bits() > best.Destination.Bits() {
			p, _ := t.Interface(node, m.First().Interface)
			best, port, found = m, p, true
		}
	}
	return best, port, found
}

func addrOf(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}

func nodes(ps []simulate.Port) int {
	seen := map[string]bool{}
	for _, p := range ps {
		seen[p.Device] = true
	}
	return len(seen)
}

func hasDevice[T any](in []T, dev string, of func(T) string) bool {
	for _, x := range in {
		if of(x) == dev {
			return true
		}
	}
	return false
}

// Start is the start of a path or a NAT answer on a named node: its only router or
// the one named, and the ingress for src — the interface src is connected to
// (connected is true), else the one its return route leaves by, with that route's
// prefix. With no source, or no route back in that router, the ingress is the
// router alone. The prefix is zero unless a route gave the ingress.
func (t *Topology) Start(node, router string, src netip.Addr) (simulate.Port, netip.Prefix, bool, error) {
	routers := t.Routers(node)
	switch {
	case router != "" && !slices.Contains(routers, router):
		return simulate.Port{}, netip.Prefix{}, false, &simulate.ChoiceError{Kind: simulate.ChoiceRouter, Question: fmt.Sprintf("%s has no router %q", node, router), Options: routers}
	case router == "" && len(routers) == 1:
		router = routers[0]
	case router == "":
		return simulate.Port{}, netip.Prefix{}, false, &simulate.ChoiceError{Kind: simulate.ChoiceRouter, Question: fmt.Sprintf("%s has several routers; name one with --router", node), Options: routers}
	}
	start := simulate.Port{Device: node, Router: router}
	if !src.IsValid() {
		return start, netip.Prefix{}, false, nil
	}
	for _, p := range t.Connected(src) {
		if p.Device == node && p.Router == router {
			return p, netip.Prefix{}, true, nil
		}
	}
	if m, ok := t.Lookup(node, router, src); ok {
		if p, ok := t.Interface(node, m.First().Interface); ok && p.Router == router {
			return p, m.Destination, false, nil
		}
	}
	return start, netip.Prefix{}, false, nil
}

// Next-hop types a lookup knows (spec §17.2, verified on fw01 and fw02).
var knownNextHopTypes = map[string]bool{"": true, "0": true, resolve.NextHopLocal: true}

// Forward is one lookup's whole answer in a router: the egress, or the interface
// owning a local address, the route, the end when nothing is forwarded, and ECMP as
// UnderMatch. A local end takes the zone of the interface owning the address (spec
// §18 F15, verified on fw01).
func (t *Topology) Forward(node, router string, a netip.Addr) simulate.Forward {
	m, ok := t.Lookup(node, router, a)
	if !ok {
		return simulate.Forward{Out: simulate.Port{Device: node, Router: router}, End: simulate.EndNoRoute, Fidelity: simulate.Exact}
	}
	f := simulate.Forward{Routes: []simulate.Match{m}, Fidelity: simulate.Exact}
	first := m.First()
	f.Out, _ = t.Interface(node, first.Interface)
	for _, p := range t.Owners(a) {
		if p.Device == node {
			f.Out, f.End = p, simulate.EndLocal
			return f
		}
	}
	switch {
	case first.NextHopType == resolve.NextHopLocal:
		f.End = simulate.EndLocal
	case !knownNextHopTypes[first.NextHopType]:
		f.End = simulate.EndUnknownType
		f.Fidelity = simulate.UnderMatch(reason.New("path.next-hop-type",
			fmt.Sprintf("route %s on %s has next-hop type %s, which is not read yet", m.Destination, node, first.NextHopType)))
	case len(m.NextHops) > 1:
		f.Fidelity = simulate.UnderMatch(reason.New("path.ecmp",
			fmt.Sprintf("ECMP on %s: %d other next hops not followed", node, len(m.NextHops)-1)))
	}
	return f
}
