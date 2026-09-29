package nat

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/rulebase"
)

// Rules returns a vsys's NAT rules in the dataplane's order: each bi-directional
// static rule followed directly by its implicit destination rule (spec §18 F9,
// verified on fw01: `show running nat-policy` lists `t-bidir; index: 4` and
// `t-bidir; index: 5`). The implicit rule matches from any zone and any source, to
// the origin's destination zone, the translated address, and translates the
// destination back to the origin's source.
func Rules(t *resolve.Target) []Rule {
	var out []Rule
	for i, r := range t.NATRules() {
		out = append(out, Rule{NATRule: r, explicit: i})
		s := r.Source
		if r.Disabled || s == nil || s.Kind != resolve.StaticIP || !s.BiDirectional || len(s.Addresses) == 0 {
			continue
		}
		implicit := resolve.NATRule{
			Rule:        r.Rule,
			ToInterface: "any",
			NATType:     r.NATType,
			Service:     "any",
			Destination: &resolve.DestinationTranslation{Kind: resolve.StaticDestination, Address: first(r.Fields["source"])},
		}
		implicit.Fields = map[string][]string{
			"from": {"any"}, "to": r.Fields["to"], "source": {"any"}, "destination": {s.Addresses[0]},
		}
		out = append(out, Rule{NATRule: implicit, Origin: r.Name, explicit: -1})
	}
	return out
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Match finds the NAT rule the flow hits: the first rule that surely matches, the
// rules above it that could have (doubts), and those that did not, with the field
// that excluded them.
func Match(in Input) MatchResult {
	out := MatchResult{In: in.In, Fidelity: simulate.Exact}
	if in.PreNAT != nil {
		out.PreNAT = *in.PreNAT
	} else if in.Lookup != nil {
		out.PreNAT = in.Lookup(in.Flow.Destination.Addrs[0])
	}
	switch out.PreNAT.End {
	case simulate.EndNoRoute:
		// A packet without a route is dropped before NAT (KB "Packet Flow Sequence in PAN-OS").
		out.Dropped = fmt.Sprintf("no route to %s: dropped before NAT", in.Flow.Destination)
		return out
	case simulate.EndUnknownType, simulate.EndDiscard:
		out.Fidelity = out.PreNAT.Fidelity
		out.Dropped = "the route lookup ends in a route that is not read yet"
		return out
	}
	// A virtual-wire ingress has no route lookup (spec §18 D3).
	if in.In.Interface != "" && in.In.Router == "" {
		reason := in.In.Interface + " forwards without a router (virtual wire or Layer 2): NAT there is not simulated"
		out.Unresolved = append(out.Unresolved, index.Unresolved{Value: in.In.Interface, Reason: reason})
		out.Fidelity = simulate.UnderMatch(reason)
		return out
	}
	v, ok := rulebase.Load(func(string, string) (simulate.Target, error) { return in.Target, nil }, in.In.Device, in.Vsys)
	if !ok {
		out.Fidelity = simulate.NotEvaluated("NAT")
		out.Dropped = "no configuration for " + in.Vsys
		return out
	}
	if v.Config.VersionGap() != "" {
		out.Notes = append(out.Notes, fmt.Sprintf("schema: NAT checked with the %s digest", v.Config.DigestVersion()))
		out.Fidelity = simulate.Inferred
	}
	out.vsys = v
	rules := Rules(v.Target)
	noNegation := func(int) (bool, bool) { return false, false }
	src, dst, un := v.Sides(resolve.NAT, sourceAddr(in.Flow.Source.Addrs), in.Flow.Destination.Addrs[0], noNegation)
	out.Unresolved = append(out.Unresolved, un...)
	out.Fidelity = simulate.Weakest(out.Fidelity, rulebase.Certainty(resolve.NAT, un))
	svc := services(v)
	for i := range rules {
		r := &rules[i]
		why, doubt := r.fits(in, out.PreNAT, src, dst, v, svc)
		switch {
		case why != "":
			out.Excluded = append(out.Excluded, Excluded{Rule: r.label(), Field: why})
			continue
		case r.NATType == "nat64":
			reason := fmt.Sprintf("NAT64 rule %s may translate this flow to IPv6, which is not simulated", r.Name)
			out.Unresolved = append(out.Unresolved, index.Unresolved{Value: r.Name, Reason: reason})
			out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(reason))
			return out
		case doubt != "":
			out.Doubts = append(out.Doubts, Doubt{Rule: r.label(), Reason: doubt})
			continue
		}
		out.Rule = r
		if r.HABinding != "" {
			out.Notes = append(out.Notes, fmt.Sprintf("rule %s is bound to HA device %s, which is ignored", r.Name, r.HABinding))
		}
		break
	}
	if len(out.Doubts) > 0 {
		var names []string
		for _, d := range out.Doubts {
			names = append(names, d.Rule+" ("+d.Reason+")")
		}
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause("may instead hit "+strings.Join(names, ", ")))
	}
	return out
}

// sourceAddr is the flow's source; invalid when only a destination is known.
func sourceAddr(addrs []netip.Addr) netip.Addr {
	if len(addrs) == 0 {
		return netip.Addr{}
	}
	return addrs[0]
}

// label names a rule as the device does, marking an implicit one.
func (r *Rule) label() string {
	if r.Origin != "" {
		return r.Name + " (implicit)"
	}
	return r.Name
}

// fits decides one rule: a field that excludes it, or a doubt, or neither (a sure
// match).
func (r *Rule) fits(in Input, pre simulate.Forward, src, dst *roaring.Bitmap, v rulebase.Vsys, svc map[string]string) (string, string) {
	if r.Disabled {
		return "disabled", ""
	}
	if r.NATType == "nptv6" {
		return "nat-type nptv6", ""
	}
	var doubts []string
	from := r.Fields["from"]
	switch {
	case len(from) == 0 || slices.Contains(from, "any"):
	case in.In.Zone == "":
		doubts = append(doubts, "the ingress zone is unknown")
	case !slices.Contains(from, in.In.Zone):
		return "from zone " + strings.Join(from, ",") + " ≠ " + in.In.Zone, ""
	}
	switch to := first(r.Fields["to"]); {
	case pre.Out.Zone == "":
		doubts = append(doubts, "the egress zone is unknown")
	case to != pre.Out.Zone:
		return "to zone " + to + " ≠ " + pre.Out.Zone, ""
	}
	if r.ToInterface != "any" && r.ToInterface != "" && r.ToInterface != pre.Out.Interface {
		return "to-interface " + r.ToInterface + " ≠ " + pre.Out.Interface, ""
	}
	if why, doubt := serviceFits(r.Service, in.Flow, svc); why != "" {
		return why, ""
	} else if doubt != "" {
		doubts = append(doubts, doubt)
	}
	// With no source, a rule that names one cannot be decided (spec §18 N11).
	if src := r.Fields["source"]; len(in.Flow.Source.Addrs) == 0 && len(src) > 0 && !slices.Contains(src, "any") {
		doubts = append(doubts, "the source is unknown")
	}
	if r.explicit >= 0 {
		pos := uint32(r.explicit) //nolint:gosec // a rulebase position fits in 32 bits
		if !src.Contains(pos) {
			return "source", ""
		}
		if !dst.Contains(pos) {
			return "destination", ""
		}
	} else if !v.Holds(first(r.Fields["destination"]), in.Flow.Destination.Addrs[0]) {
		return "destination", ""
	}
	return "", strings.Join(doubts, "; ")
}

// services maps each service and service group name of the vsys to its value:
// "tcp/443,8443" for a service, "a, b" for a group.
func services(v rulebase.Vsys) map[string]string {
	out := map[string]string{}
	for _, kind := range []string{"service", "service-group"} {
		objs := resolve.ObjectsInScope(v.Config, v.Scope, kind)
		for _, o := range objs {
			out[kind+":"+o.Name] = o.Value
		}
	}
	return out
}

// serviceFits matches a NAT rule's single service against the flow's protocol and
// destination port. A service the configuration does not define, such as the
// predefined service-http, and a flow without a port are doubts. A service object's
// source port is not read (spec §18, the probe flows set none).
func serviceFits(name string, f simulate.Flow, svc map[string]string) (string, string) {
	if name == "" || name == "any" {
		return "", ""
	}
	if f.DestPort == 0 {
		return "", "service " + name + " not known without a port: give --port"
	}
	matched, known := serviceHolds(name, strings.ToLower(f.Protocol), int(f.DestPort), svc, 0)
	switch {
	case !known:
		return "", "service " + name + " is not defined in the configuration (a predefined service?)"
	case !matched:
		return "service " + name, ""
	}
	return "", ""
}

func serviceHolds(name, proto string, port int, svc map[string]string, depth int) (matched, known bool) {
	if depth > 8 {
		return false, false
	}
	if members, ok := svc["service-group:"+name]; ok {
		for m := range strings.SplitSeq(members, ", ") {
			if mm, mk := serviceHolds(m, proto, port, svc, depth+1); mm || !mk {
				return mm, mk
			}
		}
		return false, true
	}
	value, ok := svc["service:"+name]
	if !ok {
		return false, false
	}
	p, ports, _ := strings.Cut(value, "/")
	if proto != "" && p != proto {
		return false, true
	}
	for r := range strings.SplitSeq(ports, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(r), "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		if err1 == nil && err2 == nil && port >= a && port <= b {
			return true, true
		}
	}
	return false, true
}
