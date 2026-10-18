package nat

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/rulebase"
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
		why := reason.New("path.virtual-wire",
			in.In.Interface+" forwards without a router (virtual wire or Layer 2): NAT there is not simulated")
		out.Unresolved = append(out.Unresolved, index.NewUnresolved(in.In.Interface, "", why))
		out.Fidelity = simulate.UnderMatch(why)
		return out
	}
	v, ok := rulebase.Load(func(string, string) (simulate.Target, error) { return in.Target, nil }, in.In.Device, in.Vsys)
	if !ok {
		out.Fidelity = simulate.NotEvaluated("NAT")
		out.Dropped = "no configuration for " + in.Vsys
		return out
	}
	out.vsys = v
	rules := Rules(v.Target)
	noNegation := func(int) (bool, bool) { return false, false }
	src, dst, un := v.Sides(resolve.NAT, sourceAddr(in.Flow.Source.Addrs), in.Flow.Destination.Addrs[0], noNegation)
	out.Unresolved = append(out.Unresolved, un...)
	out.Fidelity = simulate.Weakest(out.Fidelity, rulebase.Certainty(resolve.NAT, un))
	env := matchEnv{vsys: v, svc: services(v)}
	// Only an implicit rule asks which address an object holds: read the
	// objects once, and only for a rulebase that has one.
	if slices.ContainsFunc(rules, func(r Rule) bool { return r.explicit < 0 }) {
		env.addrs = v.Addresses()
	}
	for i := range rules {
		r := &rules[i]
		why, doubts := r.fits(in, out.PreNAT, src, dst, env)
		switch {
		case why != "":
			out.Excluded = append(out.Excluded, Excluded{Rule: r.label(), Field: why})
			continue
		case r.NATType == "nat64":
			ipv6 := reason.New("gap.ipv6", fmt.Sprintf("NAT64 rule %s may translate this flow to IPv6, which is not simulated", r.Name))
			out.Unresolved = append(out.Unresolved, index.NewUnresolved(r.Name, "", ipv6))
			out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(ipv6))
			return out
		case len(doubts) > 0:
			out.Doubts = append(out.Doubts, Doubt{Rule: r.label(), Reasons: doubts})
			continue
		}
		out.Rule = r
		if r.HABinding != "" {
			out.Notes = append(out.Notes, reason.New("note.ha-binding", fmt.Sprintf("rule %s is bound to HA device %s, which is ignored", r.Name, r.HABinding)))
		}
		break
	}
	if len(out.Doubts) > 0 {
		var names []string
		for _, d := range out.Doubts {
			names = append(names, d.Rule+" ("+d.Text()+")")
		}
		// One code for the summary; each doubt keeps its own reasons and codes.
		why := reason.New("doubt.nat-rule", "may instead hit "+strings.Join(names, ", "))
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(why))
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

// matchEnv is what every rule of one match reads: the vsys, its services and
// service groups by kind and name, and its address objects.
type matchEnv struct {
	vsys  rulebase.Vsys
	svc   map[string]string
	addrs rulebase.Addresses
}

// fits decides one rule: a field that excludes it, or a doubt, or neither (a sure
// match).
func (r *Rule) fits(in Input, pre simulate.Forward, src, dst rulebase.Side, env matchEnv) (string, simulate.Reasons) {
	if r.Disabled {
		return "disabled", nil
	}
	if r.NATType == "nptv6" {
		return "nat-type nptv6", nil
	}
	var doubts simulate.Reasons
	from := r.Fields["from"]
	switch {
	case len(from) == 0 || slices.Contains(from, "any"):
	case in.In.Zone == "":
		doubts = append(doubts, reason.New("zone.missing", "the ingress zone is unknown"))
	case !slices.Contains(from, in.In.Zone):
		return "from zone " + strings.Join(from, ",") + " ≠ " + in.In.Zone, nil
	}
	switch to := first(r.Fields["to"]); {
	case pre.Out.Zone == "":
		doubts = append(doubts, reason.New("zone.missing", "the egress zone is unknown"))
	case to != pre.Out.Zone:
		return "to zone " + to + " ≠ " + pre.Out.Zone, nil
	}
	if r.ToInterface != "any" && r.ToInterface != "" && r.ToInterface != pre.Out.Interface {
		return "to-interface " + r.ToInterface + " ≠ " + pre.Out.Interface, nil
	}
	if why, doubt := serviceFits(r.Service, in.Flow, env.svc, env.vsys.Config); why != "" {
		return why, nil
	} else if doubt.Text != "" {
		doubts = append(doubts, doubt)
	}
	// With no source, a rule that names one cannot be decided (spec §18 N11).
	if src := r.Fields["source"]; len(in.Flow.Source.Addrs) == 0 && len(src) > 0 && !slices.Contains(src, "any") {
		doubts = append(doubts, reason.New("doubt.source-unknown", "the source is unknown"))
	}
	if r.explicit >= 0 {
		pos := uint32(r.explicit) //nolint:gosec // a rulebase position fits in 32 bits
		if !src.Holds(pos) {
			return "source", nil
		}
		if !dst.Holds(pos) {
			return "destination", nil
		}
		// A side naming an external list, a region or a dynamic group only
		// may hold the address, as in PBF and the security check (spec E23).
		doubts = append(doubts, src.May[pos]...)
		doubts = append(doubts, dst.May[pos]...)
	} else if !env.addrs.Holds(first(r.Fields["destination"]), in.Flow.Destination.Addrs[0]) {
		return "destination", nil
	}
	return "", doubts
}

// services maps each service and service group name of the vsys to its value:
// "tcp/443,8443" for a service, "a, b" for a group. A name means the object of
// the nearest scope that defines it, whatever its kind (L9).
func services(v rulebase.Vsys) map[string]string {
	out := map[string]string{}
	for kind, objs := range resolve.ObjectsOfKindsInScope(v.Config, v.Scope, "service", "service-group") {
		for _, o := range objs {
			out[kind+":"+o.Name] = o.Value
		}
	}
	return out
}

// serviceFits matches a NAT rule's single service against the flow's protocol and
// destination port. A service no scope defines, such as service-http in a
// snapshot without the predefined services, a flow without a port, and a flow
// without a protocol whose port the service holds are doubts. A protocol given
// by number compares by its name. A service object's source port is not read
// (spec §18, the probe flows set none).
func serviceFits(name string, f simulate.Flow, svc map[string]string, cfg *config.Config) (string, reason.Reason) {
	if name == "" || name == "any" {
		return "", reason.Reason{}
	}
	// A port decides only a service the configuration defines: when neither
	// the service nor any group member is defined, no port helps.
	if !anyDefined(name, svc, 0) {
		return "", rulebase.UndefinedService(cfg, "service "+name+" is not defined in the configuration (a predefined service?)")
	}
	proto := rulebase.Protocol(f.Protocol)
	// A service names tcp or udp and its ports (schemas/schema.xml,
	// service/entry/protocol, 11.2.0), so a flow of another protocol, such as
	// icmp, has no port to give: no service holds it.
	switch proto {
	case "", "tcp", "udp", "sctp":
		if f.DestPort == 0 {
			return "", reason.New("path.nat-no-port", "service "+name+" not known without a port: give the destination port")
		}
	}
	matched, known := serviceHolds(name, proto, int(f.DestPort), svc, 0)
	switch {
	case !known:
		return "", rulebase.UndefinedService(cfg, "service "+name+" is not defined in the configuration (a predefined service?)")
	case !matched:
		return "service " + name, reason.Reason{}
	case proto == "":
		// The port fits a protocol of the service; without the flow's own, the
		// rule only may match.
		return "", reason.New("path.nat-no-protocol", "service "+name+" not known without a protocol: give the protocol")
	}
	return "", reason.Reason{}
}

// anyDefined reports whether the configuration defines a service or service
// group of this name with at least one defined service in it.
func anyDefined(name string, svc map[string]string, depth int) bool {
	if depth > 8 {
		return false
	}
	if members, ok := svc["service-group:"+name]; ok {
		for m := range strings.SplitSeq(members, ", ") {
			if anyDefined(m, svc, depth+1) {
				return true
			}
		}
		return false
	}
	_, ok := svc["service:"+name]
	return ok
}

// serviceHolds reports whether a service or group holds the port, and whether
// that is known. A group holds it when one member does, whatever the others
// are; it is unknown only when no member holds it and one is unknown.
func serviceHolds(name, proto string, port int, svc map[string]string, depth int) (matched, known bool) {
	if depth > 8 {
		return false, false
	}
	if members, ok := svc["service-group:"+name]; ok {
		known = true
		for m := range strings.SplitSeq(members, ", ") {
			mm, mk := serviceHolds(m, proto, port, svc, depth+1)
			if mm {
				return true, true
			}
			known = known && mk
		}
		return false, known
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
