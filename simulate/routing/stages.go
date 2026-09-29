package routing

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/resolve"
	"github.com/okaiser/panos-analyst/simulate"
)

// state is what the stages share across hops.
type state struct {
	env    *simulate.Env
	in     simulate.Input
	topo   *Topology
	data   map[string]simulate.DeviceData
	holes  []index.Unresolved
	src    netip.Addr // invalid when only a destination was given
	dst    netip.Addr
	path   Path
	port   Port   // the current hop's ingress
	router string // the current hop's router
	seen   map[string]bool
	done   bool
	// translated names the device where NAT may have changed the addresses;
	// every later hop is Inferred.
	translated string
}

func newState(env *simulate.Env, in simulate.Input) *state {
	s := &state{
		env: env, in: in, data: map[string]simulate.DeviceData{}, seen: map[string]bool{},
		dst:  in.Flow.Destination.Addrs[0],
		path: Path{Source: in.Flow.Source, Destination: in.Flow.Destination},
	}
	if len(in.Flow.Source.Addrs) > 0 {
		s.src = in.Flow.Source.Addrs[0]
	}
	var devs []simulate.DeviceData
	for _, name := range env.Network.Devices() {
		d, err := env.Network.Device(name)
		if err != nil {
			s.holes = append(s.holes, index.Unresolved{
				Value:  name,
				Reason: fmt.Sprintf("%s cannot be read (%v); a path through it is not seen", name, err),
			})
			continue
		}
		s.data[d.Name] = d
		devs = append(devs, d)
	}
	s.topo = NewTopology(devs)
	return s
}

// hop is the hop the stages work on.
func (s *state) hop() *Hop { return &s.path.Hops[len(s.path.Hops)-1] }

// newHop opens a hop at the current ingress.
func (s *state) newHop() {
	h := Hop{
		Device: s.port.Device, Vsys: vsysName(s.port.Vsys),
		SnapshotID: s.data[s.port.Device].SnapshotID, TakenAt: s.data[s.port.Device].TakenAt,
		In: s.port, Flow: s.flow(),
	}
	if n := len(s.path.Hops); n == 0 || s.path.Hops[n-1].Device != h.Device {
		h.Notes = append(h.Notes, s.data[h.Device].Notes...)
	}
	s.seen[s.key(s.port)] = true
	s.path.Hops = append(s.path.Hops, h)
}

func (s *state) flow() simulate.Flow {
	f := s.in.Flow
	f.FromZone, f.ToZone = s.port.Zone, ""
	return f
}

func (s *state) closeHop(stages []simulate.Stage) { s.hop().Fidelity = simulate.Overall(stages) }

func (s *state) key(p Port) string { return p.Device + "|" + vsysName(p.Vsys) + "|" + p.Router }

// ended is what a stage reports after an earlier stage of its hop ended the path.
var ended = simulate.Outcome{Fidelity: simulate.Exact, Detail: "the path ended"}

// end closes the path.
func (s *state) end(o Outcome, text string) {
	s.path.Outcome, s.path.End, s.done = o, text, true
}

// place finds the first hop (spec §17 R2, R5).
func place(_ context.Context, s *state) (simulate.Outcome, error) {
	out := simulate.Outcome{Unresolved: s.holes}
	fid := simulate.Exact
	if dev := s.in.Params["device"]; dev != "" {
		if err := s.placeGiven(dev); err != nil {
			return out, err
		}
		s.path.Placed = PlacedGiven
		out.Detail = fmt.Sprintf("given: %s, router %s", s.port.Device, s.router)
	} else {
		if !s.src.IsValid() {
			return out, &ChoiceError{Question: "give a source, or a start device with --device"}
		}
		pl, err := s.topo.Place(s.src)
		if errors.Is(err, ErrUnplaced) {
			return out, &ChoiceError{Question: fmt.Sprintf("only default routes reach %s, so its first firewall is unknown; name it with --device", s.src), Options: s.topo.Nodes()}
		}
		if len(pl.Ties) > 0 {
			var opts []string
			for _, p := range pl.Ties {
				opts = append(opts, p.Device+" "+p.Interface)
			}
			return out, &ChoiceError{Question: fmt.Sprintf("%s could enter at several firewalls; name one with --device", s.src), Options: opts}
		}
		s.port, s.router, s.path.Placed = pl.Port, pl.Port.Router, pl.How
		if pl.How == PlacedRouted {
			s.path.PlacedVia = pl.Via.String()
			fid = simulate.Inferred
			out.Detail = fmt.Sprintf("routed: %s by %s on %s; traffic is assumed to arrive where its return leaves", s.src, pl.Via, pl.Port.Device)
		} else {
			out.Detail = fmt.Sprintf("connected: %s on %s %s", s.src, pl.Port.Device, pl.Port.Interface)
		}
	}
	for _, h := range s.holes {
		fid = simulate.Weakest(fid, simulate.UnderMatch(h.Reason))
	}
	out.Fidelity = fid
	return out, nil
}

// placeGiven starts on a named device, in its only router or the one named.
func (s *state) placeGiven(dev string) error {
	d, err := s.env.Network.Device(dev)
	if err != nil {
		return &ChoiceError{Question: fmt.Sprintf("cannot start on %s: %v", dev, err), Options: s.topo.Nodes()}
	}
	node := d.Name
	routers := s.topo.Routers(node)
	router := s.in.Params["router"]
	switch {
	case router != "" && !slices.Contains(routers, router):
		return &ChoiceError{Question: fmt.Sprintf("%s has no router %q", node, router), Options: routers}
	case router == "" && len(routers) == 1:
		router = routers[0]
	case router == "":
		return &ChoiceError{Question: fmt.Sprintf("%s has several routers; name one with --router", node), Options: routers}
	}
	s.port, s.router = Port{Device: node, Router: router}, router
	if !s.src.IsValid() {
		return nil
	}
	// The ingress is the interface the source is connected to, or the one its
	// return route leaves by, in the router asked.
	for _, p := range s.topo.Connected(s.src) {
		if p.Device == node && p.Router == router {
			s.port = p
			return nil
		}
	}
	if m, ok := s.topo.Lookup(node, router, s.src); ok {
		if p, ok := s.topo.Interface(node, m.First().Interface); ok && p.Router == router {
			s.port = p
		}
	}
	return nil
}

// Next-hop types the lookup knows (spec §17.2, verified on fw01 and fw02).
var knownNextHopTypes = map[string]bool{"": true, "0": true, resolve.NextHopLocal: true}

// lookup is the longest-prefix match in the hop's router (spec §17 R3, R4, R7).
func lookup(_ context.Context, s *state) (simulate.Outcome, error) {
	h := s.hop()
	m, ok := s.topo.Lookup(h.Device, s.router, s.dst)
	if !ok {
		s.end(Dropped, fmt.Sprintf("dropped on %s: no route to %s", h.Device, s.dst))
		return simulate.Outcome{Fidelity: simulate.Exact, Detail: "no route"}, nil
	}
	h.Lookups = append(h.Lookups, Lookup{Router: s.router, Match: m, Protocol: s.protocol(h.Device, m.Destination)})
	first := m.First()
	out := simulate.Outcome{
		Fidelity: simulate.Exact,
		Detail:   fmt.Sprintf("%s in router %s: %s via %s on %s", s.dst, s.router, m.Destination, first.NextHop, first.Interface),
	}
	if !knownNextHopTypes[first.NextHopType] {
		reason := fmt.Sprintf("route %s on %s has next-hop type %s, which is not read yet", m.Destination, h.Device, first.NextHopType)
		out.Unresolved = append(out.Unresolved, index.Unresolved{Value: m.Destination.String(), Reason: reason})
		out.Fidelity = simulate.UnderMatch(reason)
		s.end(Unresolved, "stopped on "+h.Device+": "+reason)
		return out, nil
	}
	if len(m.NextHops) > 1 {
		for _, nh := range m.NextHops[1:] {
			h.ECMP = append(h.ECMP, NotFollowed{NextHop: nh.NextHop, Reaches: s.reaches(h.Device, nh)})
		}
		out.Fidelity = simulate.UnderMatch(fmt.Sprintf("ECMP on %s: %d other next hops not followed", h.Device, len(h.ECMP)))
	}
	if s.in.Params["rib"] == "true" {
		alts, un := s.alternates(h.Device)
		h.Alternates = alts
		if un != nil {
			out.Unresolved = append(out.Unresolved, *un)
			out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(un.Reason))
		}
	}
	return out, nil
}

// protocol is the routing table's protocol for the selected route to dst.
func (s *state) protocol(node string, dst netip.Prefix) string {
	for _, r := range s.data[node].RIB {
		if r.Router == s.router && r.Destination == dst && r.Selected {
			return r.Protocol
		}
	}
	return ""
}

// reaches names the node an ECMP next hop leads to, if any.
func (s *state) reaches(node string, nh resolve.FIBRoute) string {
	out, _ := s.topo.Interface(node, nh.Interface)
	a, ok := addr(nh.NextHop)
	if !ok {
		return ""
	}
	if peers := s.topo.Peers(out, a); len(peers) == 1 {
		return peers[0].Device
	}
	return ""
}

// alternates are the routing table's routes in this router that cover the
// destination, the selected one first, then the most specific.
func (s *state) alternates(node string) ([]resolve.RIBRoute, *index.Unresolved) {
	d := s.data[node]
	if d.RIB == nil {
		return nil, &index.Unresolved{Value: node, Reason: node + "'s snapshot has no routing table; fetch it again"}
	}
	var out []resolve.RIBRoute
	for _, r := range d.RIB {
		if r.Router == s.router && r.Destination.Contains(s.dst) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, k int) bool {
		if out[i].Selected != out[k].Selected {
			return out[i].Selected
		}
		return out[i].Destination.Bits() > out[k].Destination.Bits()
	})
	return out, nil
}

// zones reads the hop's ingress and egress zone off interface state.
func zones(_ context.Context, s *state) (simulate.Outcome, error) {
	if s.done {
		return ended, nil
	}
	h := s.hop()
	first := h.Lookups[len(h.Lookups)-1].Match.First()
	h.Out, _ = s.topo.Interface(h.Device, first.Interface)
	if h.Vsys == "" {
		h.Vsys = vsysName(h.Out.Vsys)
	}
	// An address of the device itself ends here, in the zone of the interface
	// holding it.
	for _, p := range s.topo.Owners(s.dst) {
		if p.Device == h.Device {
			h.Out = p
		}
	}
	h.Flow.ToZone = h.Out.Zone
	detail := fmt.Sprintf("%s -> %s", orUnknown(h.Flow.FromZone), orUnknown(h.Flow.ToZone))
	if h.In.Interface == "" {
		h.Notes = append(h.Notes, "the ingress is unknown: no source was given")
	}
	return simulate.Outcome{Fidelity: simulate.Exact, Detail: detail}, nil
}

func orUnknown(z string) string {
	if z == "" {
		return "(unknown)"
	}
	return z
}

// next decides where the packet goes after this hop (spec §17 R6, R7, R16).
func next(_ context.Context, s *state) (simulate.Outcome, error) {
	if s.done {
		return ended, nil
	}
	h := s.hop()
	out := simulate.Outcome{Fidelity: simulate.Exact}
	first := h.Lookups[len(h.Lookups)-1].Match.First()

	if first.NextHopType == resolve.NextHopLocal || h.Out.Addr.Addr() == s.dst {
		s.end(Local, fmt.Sprintf("%s   terminates on %s", s.dst, h.Device))
		out.Detail = "local"
		return out, nil
	}
	if in, o := h.In.Vsys, h.Out.Vsys; in != "" && o != "" && in != o {
		return s.crossVsys(h, out)
	}
	nh, isAddr := addr(first.NextHop)
	if !isAddr {
		if !h.Out.Addr.IsValid() || !h.Out.Link().Contains(s.dst) {
			reason := fmt.Sprintf("the path leaves %s by %s; firewalls beyond it see the tunnel's outer packets, not this flow", h.Device, h.Out.Interface)
			s.end(LeftByInterface, fmt.Sprintf("leaves by %s (zone %s)", h.Out.Interface, orUnknown(h.Out.Zone)))
			out.Fidelity, out.Detail = simulate.UnderMatch(reason), reason
			return out, nil
		}
		nh = s.dst // a connected net: the destination itself is the next hop
	}
	peers := s.topo.Peers(h.Out, nh)
	switch {
	case len(peers) > 1:
		var names []string
		for _, p := range peers {
			names = append(names, p.Device)
		}
		reason := fmt.Sprintf("%s in %s is owned by %s", nh, h.Out.Link(), strings.Join(names, ", "))
		out.Unresolved = append(out.Unresolved, index.Unresolved{Value: nh.String(), Reason: reason})
		out.Fidelity = simulate.UnderMatch(reason)
		s.end(Unresolved, "stopped after "+h.Device+": "+reason)
	case len(peers) == 0 && nh == s.dst:
		s.end(Delivered, fmt.Sprintf("%s   delivered", s.dst))
		out.Detail = "delivered in " + h.Out.Link().String()
	case len(peers) == 0:
		reason := fmt.Sprintf("the path leaves the estate at %s", nh)
		s.end(LeftEstate, fmt.Sprintf("%s   leaves the estate (not in the inventory)", nh))
		out.Fidelity, out.Detail = simulate.UnderMatch(reason), reason
	default:
		return s.chain(peers[0], out)
	}
	return out, nil
}

// chain moves the path to the next hop's device.
func (s *state) chain(p Port, out simulate.Outcome) (simulate.Outcome, error) {
	if s.seen[s.key(p)] {
		s.end(Loop, "loop: "+s.trail(p.Device))
		if s.agesDiffer() {
			s.hop().Notes = append(s.hop().Notes, "the loop crosses snapshots taken at different times; it may come from their ages")
		}
		out.Detail = "loop"
		return out, nil
	}
	if len(s.path.Hops) >= MaxHops {
		reason := fmt.Sprintf("more than %d hops", MaxHops)
		out.Unresolved = append(out.Unresolved, index.Unresolved{Value: s.dst.String(), Reason: reason})
		out.Fidelity = simulate.UnderMatch(reason)
		s.end(TooLong, "stopped: "+reason)
		return out, nil
	}
	s.port, s.router = p, p.Router
	out.Detail = fmt.Sprintf("next: %s %s", p.Device, p.Interface)
	return out, nil
}

// crossVsys splits a hop at a vsys boundary: each vsys evaluates its own zone
// pair through its external zone (PAN-OS admin guide, "Inter-VSYS Traffic That
// Remains Within the Firewall", "External Zone"). Not seen on a lab device.
func (s *state) crossVsys(h *Hop, out simulate.Outcome) (simulate.Outcome, error) {
	fromExt, ok1 := s.externalZone(h.Device, h.In.Vsys, h.Out.Vsys)
	toExt, ok2 := s.externalZone(h.Device, h.Out.Vsys, h.In.Vsys)
	egress := h.Out
	h.Out = Port{Device: h.Device, Vsys: h.In.Vsys, Router: s.router, Zone: fromExt}
	h.Flow.ToZone = fromExt
	if !ok1 || !ok2 {
		out.Fidelity = simulate.Inferred
		h.Notes = append(h.Notes, "no external zone joins these vsys in the configuration; the zone names are placeholders")
	}
	out.Detail = fmt.Sprintf("into %s by the external zones", vsysName(egress.Vsys))
	return s.chain(Port{Device: h.Device, Vsys: egress.Vsys, Router: s.router, Zone: toExt}, out)
}

// externalZone is the external zone of vsys from that lists vsys to.
func (s *state) externalZone(dev, from, to string) (string, bool) {
	if s.env.Load != nil {
		if t, err := s.env.Load(dev, vsysName(from)); err == nil && t.Config != nil {
			zs, _ := resolve.ZonesInScope(t.Config, config.Scope{Sort: config.ScopeVsys, Name: vsysName(from)})
			for _, z := range zs {
				if z.Mode == "external" && slices.Contains(z.Interfaces, vsysName(to)) {
					return z.Name, true
				}
			}
		}
	}
	return "external", false
}

func (s *state) trail(to string) string {
	var names []string
	for _, h := range s.path.Hops {
		names = append(names, h.Device)
	}
	return strings.Join(append(names, to), " -> ")
}

func (s *state) agesDiffer() bool {
	ids := map[string]bool{}
	for _, h := range s.path.Hops {
		ids[s.data[h.Device].TakenAt.String()] = true
	}
	return len(ids) > 1
}

// hidden names the nodes off the path with interfaces that forward without a
// router — Layer 2 or virtual wire — where a firewall can sit on a path unseen
// (spec §17 R19).
func (s *state) hidden() {
	on := map[string]bool{}
	for _, h := range s.path.Hops {
		on[h.Device] = true
	}
	for _, n := range s.topo.Nodes() {
		if on[n] {
			continue
		}
		for _, i := range s.data[n].Interfaces {
			if i.Router == "" && i.Zone != "" {
				s.path.Hidden = append(s.path.Hidden, n+" (Layer 2 or virtual wire)")
				break
			}
		}
	}
}
