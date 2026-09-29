package routing

import (
	"errors"
	"net/netip"
	"sort"

	"github.com/gaissmai/bart"

	"github.com/okaiser/panos-analyst/resolve"
	"github.com/okaiser/panos-analyst/simulate"
)

// Port is one interface of one node, with the address that placed it.
type Port struct {
	Device    string       `json:"device"`
	Vsys      string       `json:"vsys"` // as the device reports it: "1"
	Router    string       `json:"router"`
	Interface string       `json:"interface"`
	Zone      string       `json:"zone,omitempty"`
	Addr      netip.Prefix `json:"address,omitzero"` // the interface address; its masked form is the link net
}

// Link is the net a port's address sits in.
func (p Port) Link() netip.Prefix { return p.Addr.Masked() }

// Match is the forwarding entry a lookup found: the destination prefix and every
// next hop the table holds for it, sorted by next-hop address (spec §17 R4).
type Match struct {
	Destination netip.Prefix       `json:"destination"`
	NextHops    []resolve.FIBRoute `json:"next_hops"`
}

// First is the next hop the path follows.
func (m Match) First() resolve.FIBRoute { return m.NextHops[0] }

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
	Port Port
	How  Placed
	Via  netip.Prefix // the route that placed a routed start
	Ties []Port       // several equally good starts; the caller asks for --device
}

// ErrUnplaced is a source that only default routes reach: no node is nearer to it
// than another.
var ErrUnplaced = errors.New("only default routes reach the source")

// Topology is the estate's interfaces and forwarding tables, built once per run.
// It answers who owns an address, which nets are connected where, and where a
// node's table sends an address. IPv4 only (spec §17 R9).
type Topology struct {
	nodes  []string
	ports  map[string][]Port                                     // node -> routed ports with an address
	byIf   map[string]map[string]Port                            // node -> interface -> port, address or not
	tables map[string]map[string]*bart.Table[[]resolve.FIBRoute] // node -> router -> table
}

// NewTopology indexes the nodes' data.
func NewTopology(devs []simulate.DeviceData) *Topology {
	t := &Topology{
		ports:  map[string][]Port{},
		byIf:   map[string]map[string]Port{},
		tables: map[string]map[string]*bart.Table[[]resolve.FIBRoute]{},
	}
	for _, d := range devs {
		t.nodes = append(t.nodes, d.Name)
		t.byIf[d.Name] = map[string]Port{}
		for _, i := range d.Interfaces {
			p := Port{Device: d.Name, Vsys: i.Vsys, Router: i.Router, Interface: i.Name, Zone: i.Zone}
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
	sort.Strings(out)
	return out
}

// Interface returns a node's interface by name, with or without an address.
func (t *Topology) Interface(node, name string) (Port, bool) {
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
func (t *Topology) Owners(a netip.Addr) []Port {
	var out []Port
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
func (t *Topology) Peers(out Port, nh netip.Addr) []Port {
	var peers []Port
	for _, p := range t.Owners(nh) {
		if p.Device != out.Device && p.Link() == out.Link() {
			peers = append(peers, p)
		}
	}
	return peers
}

// Connected returns the ports whose net holds a, most specific net first; only
// the most specific length is kept, so a /30 inside a /24 wins.
func (t *Topology) Connected(a netip.Addr) []Port {
	var out []Port
	best := -1
	for _, n := range t.nodes {
		for _, p := range t.ports[n] {
			if !p.Addr.Contains(a) {
				continue
			}
			switch bits := p.Addr.Bits(); {
			case bits > best:
				best, out = bits, []Port{p}
			case bits == best:
				out = append(out, p)
			}
		}
	}
	return out
}

// Lookup is a longest-prefix match of a in one router's table.
func (t *Topology) Lookup(node, router string, a netip.Addr) (Match, bool) {
	tb := t.tables[node][router]
	if tb == nil {
		return Match{}, false
	}
	rs, ok := tb.Lookup(a)
	if !ok || len(rs) == 0 {
		return Match{}, false
	}
	hops := append([]resolve.FIBRoute(nil), rs...)
	sort.SliceStable(hops, func(i, k int) bool { return lessAddr(hops[i].NextHop, hops[k].NextHop) })
	return Match{Destination: hops[0].Destination, NextHops: hops}, true
}

func lessAddr(a, b string) bool {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a < b
	}
	return x.Less(y)
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
		port Port
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
func (t *Topology) towards(node string, a netip.Addr) (Match, Port, bool) {
	var best Match
	var port Port
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

func nodes(ps []Port) int {
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
