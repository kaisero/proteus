package routing

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/okaiser/panos-analyst/simulate"
	natsim "github.com/okaiser/panos-analyst/simulate/nat"
	"github.com/okaiser/panos-analyst/simulate/rulebase"
)

// Policy-based forwarding and NAT are detected, not simulated (spec §17 R10): a
// rule that could match the flow at this hop is named in a note and makes the hop
// Inferred, and the path still follows the forwarding table. PAN-OS evaluates PBF
// before the route lookup and NAT after it, on the pre-NAT addresses with the
// egress zone from the route lookup (KB "Packet Flow Sequence in PAN-OS").

// policy loads the hop's configuration; false when there is none to read.
func (s *state) policy(h *Hop) (rulebase.Vsys, bool) {
	return rulebase.Load(s.env.Load, h.Device, h.Vsys)
}

// pbf names the first PBF rule of the hop's vsys that could take this packet.
func pbf(_ context.Context, s *state) (simulate.Outcome, error) {
	h := s.hop()
	v, ok := s.policy(h)
	if !ok {
		return simulate.Outcome{
			Fidelity: simulate.NotEvaluated("policy-based forwarding"),
			Detail:   "no configuration for " + h.Device + " " + orUnknown(h.Vsys),
		}, nil
	}
	out := simulate.Outcome{Fidelity: simulate.Exact, Detail: "no PBF rule could match"}
	if gap := v.Config.VersionGap(); gap != "" {
		h.Notes = append(h.Notes, fmt.Sprintf("schema: PBF checked with the %s digest", v.Config.DigestVersion()))
		out.Fidelity = simulate.Inferred
	}
	if r, note, ok := v.PBF(s.src, s.dst, h.In); ok {
		if note != "" {
			h.Notes = append(h.Notes, note)
			out.Fidelity, out.Detail = simulate.Inferred, note
		} else {
			out.Detail = "pbf rule " + r.Name + " leaves the packet to routing"
		}
	}
	return out, nil
}

// nat runs the NAT engine on the hop (spec §18 N1, N5): the rule the packet hits
// and the packet after it. A destination NAT replaces the hop's egress with the
// lookup of the translated destination; every later hop routes on, and matches its
// rules against, the translated packet (spec §18 F4).
func nat(ctx context.Context, s *state) (simulate.Outcome, error) {
	if s.done {
		return ended, nil
	}
	h := s.hop()
	out := simulate.Outcome{Fidelity: simulate.Exact, Detail: "no NAT rule matches"}
	if s.pool != "" {
		h.Notes = append(h.Notes, s.pool)
		out.Fidelity = simulate.Inferred
	}
	if s.env.Load == nil || h.Vsys == "" {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.NotEvaluated("NAT"))
		out.Detail = "no configuration for " + h.Device + " " + orUnknown(h.Vsys)
		return out, nil
	}
	t, err := s.env.Load(h.Device, h.Vsys)
	if err != nil || t.Config == nil {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.NotEvaluated("NAT"))
		out.Detail = "no configuration for " + h.Device + " " + h.Vsys
		return out, nil
	}
	last := &h.Lookups[len(h.Lookups)-1]
	pre := simulate.Forward{Out: h.Out, Routes: []simulate.Match{last.Match}, Fidelity: simulate.Exact}
	router := s.router
	in := natsim.Input{
		Target: t, Vsys: h.Vsys, Flow: s.cur, In: h.In, PreNAT: &pre,
		Interfaces: s.data[h.Device].Interfaces,
		Lookup:     func(a netip.Addr) simulate.Forward { return s.topo.Forward(h.Device, router, a) },
	}
	m := natsim.Match(in)
	if names := natsim.FQDNs(in, m.Rule); len(names) > 0 && s.env.Resolve != nil {
		in.Resolved = map[string][]netip.Addr{}
		for _, n := range names {
			in.Resolved[n], _ = s.env.Resolve(ctx, n)
		}
	}
	r := natsim.Translate(in, m)
	h.Notes = append(h.Notes, r.Notes...)
	for _, d := range r.Doubts {
		h.Notes = append(h.Notes, "nat rule "+d.Rule+" may match instead: "+d.Reason)
	}
	out.Unresolved = r.Unresolved
	out.Fidelity = simulate.Weakest(out.Fidelity, r.Fidelity)
	if r.Rule == nil {
		return out, nil
	}
	note := fmt.Sprintf("nat rule %s (%s -> %s):", r.Rule.Name, orUnknown(h.In.Zone), orUnknown(pre.Out.Zone))
	if r.Rule.Origin != "" {
		note = fmt.Sprintf("nat rule %s, implicit (%s -> %s):", r.Rule.Name, orUnknown(h.In.Zone), orUnknown(pre.Out.Zone))
	}
	if tr := r.Source; tr != nil {
		note += fmt.Sprintf(" source %s -> %s", s.cur.Source, strings.Join(tr.Candidates, ", "))
		if len(tr.Candidates) > 1 || strings.Contains(strings.Join(tr.Candidates, ""), "/") || strings.Contains(strings.Join(tr.Candidates, ""), "-") {
			s.pool = fmt.Sprintf("nat on %s translates the source to one of %s", h.Device, strings.Join(tr.Candidates, ", "))
		}
	}
	if tr := r.Destination; tr != nil && tr.Address.IsValid() {
		note += fmt.Sprintf(" destination %s -> %s", s.cur.Destination, tr.Address)
		if tr.Port != natsim.PortUnchanged {
			note += ":" + tr.Port
		}
	}
	h.Notes = append(h.Notes, note)
	out.Detail = note
	if r.PostNAT != nil {
		last.Stage = "pre-NAT"
		if len(r.PostNAT.Routes) > 0 {
			h.Lookups = append(h.Lookups, Lookup{Router: router, Match: r.PostNAT.Routes[0], Stage: "post-NAT"})
		}
		h.Out = r.PostNAT.Out
		h.Flow.ToZone = h.Out.Zone
		if r.PostNAT.End == simulate.EndNoRoute {
			s.end(Dropped, fmt.Sprintf("dropped on %s: no route to the translated %s", h.Device, r.Flow.Destination))
		}
	}
	post := r.Flow
	h.PostNAT = &post
	s.cur = r.Flow
	if len(r.Flow.Source.Addrs) > 0 {
		s.src = r.Flow.Source.Addrs[0]
	}
	s.dst = r.Flow.Destination.Addrs[0]
	return out, nil
}
