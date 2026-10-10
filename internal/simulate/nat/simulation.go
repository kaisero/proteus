package nat

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/rulebase"
	"github.com/okaiser/proteus/internal/simulate/topology"
)

// Kind is the registry key and the command name.
const Kind = "nat"

// Simulation is the NAT simulation on one firewall (spec §18 N8).
type Simulation struct{}

var _ simulate.Simulation = Simulation{}

// Kind implements simulate.Simulation.
func (Simulation) Kind() string { return Kind }

// Describe implements simulate.Simulation.
func (Simulation) Describe() string {
	return "which NAT rule a packet hits on one firewall, and the packet after translation"
}

// Stages implements simulate.Simulation, in PAN-OS packet-flow order: PBF before the
// route lookup, NAT on the original packet, then the lookup of a translated
// destination (spec §18 F4, F14).
func (Simulation) Stages() []string {
	return []string{"place", "pbf", "lookup", "match", "translate", "post-lookup"}
}

// state is what the stages share.
type state struct {
	env    *simulate.Env
	in     simulate.Input
	topo   *topology.Topology
	data   simulate.DeviceData
	nat    Input
	pre    simulate.Forward
	result Result
	notes  simulate.Reasons // from stages before the match, such as PBF
}

// Run implements simulate.Simulation.
//
// Params: "device" (required), "router", "from-zone" or "from-interface" to set
// the ingress instead of deriving it.
func (Simulation) Run(ctx context.Context, env *simulate.Env, in simulate.Input) (simulate.Run, error) {
	run := simulate.Run{Kind: Kind, Device: in.Params["device"], Input: in}
	switch {
	case env.Network == nil:
		return run, errors.New("nat: no network to read")
	case in.Params["device"] == "":
		return run, &simulate.ChoiceError{Question: "name the firewall with --device", ToolText: "name the firewall in device"}
	case len(in.Flow.Destination.Addrs) == 0 || !in.Flow.Destination.Addrs[0].Is4():
		return run, &simulate.ChoiceError{Question: "the destination must be an IPv4 address; IPv6 is not simulated yet"}
	case len(in.Flow.Source.Addrs) > 0 && !in.Flow.Source.Addrs[0].Is4():
		return run, &simulate.ChoiceError{Question: "the source must be an IPv4 address; IPv6 is not simulated yet"}
	}
	d, err := env.Network.Device(in.Params["device"])
	if u, ok := errors.AsType[*simulate.UnavailableError](err); ok {
		return run, u // the device is in the inventory; its data is missing
	}
	if err != nil {
		return run, &simulate.ChoiceError{Question: fmt.Sprintf("cannot read %s: %v", in.Params["device"], err)}
	}
	s := &state{env: env, in: in, data: d, topo: topology.NewTopology([]simulate.DeviceData{d})}
	steps := []simulate.Step[state]{
		{Name: "place the ingress", Slug: "place", Do: place},
		{Name: "policy-based forwarding", Slug: "pbf", Do: pbfStage},
		{Name: "pre-NAT route lookup", Slug: "lookup", Do: lookupStage},
		{Name: "NAT rule", Slug: "match", Do: matchStage},
		{Name: "translation", Slug: "translate", Do: translateStage},
		{Name: "post-NAT route lookup", Slug: "post-lookup", Do: postLookupStage},
	}
	stages, err := simulate.Execute(ctx, Kind, s, steps, false, env.Log)
	run.Stages = stages
	run.Device, run.Vsys = d.Name, s.nat.Vsys
	run.Fidelity = simulate.Overall(stages)
	s.result.Notes = append(append(simulate.DNSNotes(in.Flow, true), s.notes...), s.result.Notes...)
	run.Output = s.result
	run.Notes = d.Notes
	return run, err
}

// place sets the ingress: an override, else where the source is connected (Exact)
// or where its return route leaves (Inferred), as a routing path's given start.
func place(_ context.Context, s *state) (simulate.Outcome, error) {
	src := sourceAddr(s.in.Flow.Source.Addrs)
	router := s.in.Params["router"]
	// Without --router, the interface given or the one the source is connected to
	// names it; only then does a firewall with several routers need the question.
	if router == "" {
		if p, ok := s.topo.Interface(s.data.Name, s.in.Params["from-interface"]); ok {
			router = p.Router
		}
		for _, p := range s.topo.Connected(src) {
			if router == "" && p.Device == s.data.Name {
				router = p.Router
			}
		}
	}
	port, _, connected, err := s.topo.Start(s.data.Name, router, src)
	if err != nil {
		return simulate.Outcome{}, err
	}
	out := simulate.Outcome{Fidelity: simulate.Exact}
	switch ifc, zone := s.in.Params["from-interface"], s.in.Params["from-zone"]; {
	case ifc != "":
		p, ok := s.topo.Interface(s.data.Name, ifc)
		if !ok {
			return out, &simulate.ChoiceError{Question: fmt.Sprintf("%s has no interface %s", s.data.Name, ifc)}
		}
		port = p
		out.Detail = "given: " + ifc
	case zone != "":
		port.Zone, port.Interface = zone, ""
		out.Detail = "given: zone " + zone
	case connected:
		out.Detail = fmt.Sprintf("connected: %s on %s", src, port.Interface)
	case port.Interface != "":
		out.Fidelity = simulate.Inferred
		out.Detail = fmt.Sprintf("routed: %s by the return route on %s", src, port.Interface)
	default:
		out.Detail = "the ingress is unknown: give --from-zone or --from-interface"
	}
	s.nat = Input{
		Target: simulate.Target{}, Flow: s.in.Flow, In: port, Interfaces: s.data.Interfaces,
		Lookup: func(a netip.Addr) simulate.Forward { return s.topo.Forward(s.data.Name, port.Router, a) },
	}
	return out, nil
}

// pbfStage checks policy-based forwarding before the route lookup (spec §18 D4).
func pbfStage(_ context.Context, s *state) (simulate.Outcome, error) {
	pre := s.topo.Forward(s.data.Name, s.nat.In.Router, s.in.Flow.Destination.Addrs[0])
	s.pre = pre
	s.nat.Vsys = vsysName(s.nat.In.Vsys, pre.Out.Vsys)
	v, ok := rulebase.Load(s.env.Load, s.data.Name, s.nat.Vsys)
	if !ok {
		return simulate.Outcome{
			Fidelity: simulate.NotEvaluated("policy-based forwarding"),
			Detail:   "no configuration for " + s.data.Name + " " + s.nat.Vsys,
		}, nil
	}
	s.nat.Target = simulate.Target{Config: v.Config, Indexes: v.Indexes}
	f := s.in.Flow
	m := v.PBF(sourceAddr(f.Source.Addrs), f.Destination.Addrs[0], f.Protocol, f.DestPort, s.nat.In)
	out := simulate.Outcome{
		Fidelity:   rulebase.Certainty(resolve.PBF, m.Unresolved),
		Detail:     "no PBF rule could take the packet",
		Unresolved: m.Unresolved,
	}
	switch {
	case !m.Found:
	case m.Note.Text == "":
		out.Detail = "no-pbf rule " + m.Rule.Name + " leaves the packet to routing"
	default:
		s.notes = append(s.notes, reason.Reason{Code: m.Note.Code, Text: m.Note.Text + "; the NAT zones below assume it does not"})
		out.Fidelity, out.Detail = simulate.Weakest(out.Fidelity, simulate.Inferred), m.Note.Text
	}
	out.Detail += rulebase.PassedText(m.Passed)
	return out, nil
}

// lookupStage is the pre-NAT route lookup that gives the NAT rule's destination
// zone and interface (spec §18 F3).
func lookupStage(_ context.Context, s *state) (simulate.Outcome, error) {
	detail := fmt.Sprintf("%s leaves by %s (zone %s)", s.in.Flow.Destination, s.pre.Out.Interface, orUnknown(s.pre.Out.Zone))
	if s.pre.End != "" {
		detail = fmt.Sprintf("%s: %s", s.in.Flow.Destination, s.pre.End)
	}
	return simulate.Outcome{Fidelity: s.pre.Fidelity, Detail: detail}, nil
}

// matchStage finds the rule.
func matchStage(_ context.Context, s *state) (simulate.Outcome, error) {
	s.nat.PreNAT = &s.pre
	m := Match(s.nat)
	s.result.MatchResult = m
	out := simulate.Outcome{Fidelity: m.Fidelity, Unresolved: m.Unresolved}
	switch {
	case m.Dropped != "":
		out.Detail = m.Dropped
	case m.Rule == nil:
		out.Detail = "no rule: the packet leaves untranslated"
	default:
		out.Detail = "rule " + m.Rule.label()
	}
	for _, e := range m.Excluded {
		out.Debug = append(out.Debug, "excluded "+e.Rule+": "+e.Field)
	}
	return out, nil
}

// translateStage applies the rule, resolving a dynamic destination's FQDNs first.
func translateStage(ctx context.Context, s *state) (simulate.Outcome, error) {
	m := s.result.MatchResult
	if m.Rule == nil {
		s.result.Flow = s.in.Flow
		return simulate.Outcome{Fidelity: simulate.Exact, Detail: "nothing to translate"}, nil
	}
	resolved := map[string][]netip.Addr{}
	for _, name := range FQDNs(s.nat, m) {
		if s.env.Resolve != nil {
			addrs, _ := s.env.Resolve(ctx, name)
			resolved[name] = addrs
		}
	}
	s.nat.Resolved = resolved
	r := Translate(s.nat, m)
	s.result = r
	var parts []string
	if r.Source != nil {
		parts = append(parts, "source -> "+strings.Join(r.Source.Candidates, ", "))
	}
	if r.Destination != nil {
		parts = append(parts, "destination -> "+strings.Join(r.Destination.Candidates, ", "))
	}
	return simulate.Outcome{Fidelity: r.Fidelity, Unresolved: r.Unresolved[len(m.Unresolved):], Detail: strings.Join(parts, "; ")}, nil
}

// postLookupStage reports the lookup of a translated destination (spec §18 F4).
func postLookupStage(_ context.Context, s *state) (simulate.Outcome, error) {
	f := s.result.PostNAT
	if f == nil {
		return simulate.Outcome{Fidelity: simulate.Exact, Detail: "no destination translation"}, nil
	}
	return simulate.Outcome{Fidelity: f.Fidelity, Detail: fmt.Sprintf("%s leaves by %s (zone %s)", s.result.Flow.Destination, f.Out.Interface, orUnknown(f.Out.Zone))}, nil
}

// vsysName is the configuration's name of the ingress vsys, else the egress's; a
// firewall without vsys reports none and has vsys1.
func vsysName(nums ...string) string {
	for _, n := range nums {
		switch {
		case n == "":
		case strings.HasPrefix(n, "vsys"):
			return n
		default:
			return "vsys" + n
		}
	}
	return "vsys1"
}

func orUnknown(z string) string {
	if z == "" {
		return "unknown"
	}
	return z
}
