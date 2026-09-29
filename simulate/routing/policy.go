package routing

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/resolve"
	"github.com/okaiser/panos-analyst/simulate"
)

// Policy-based forwarding and NAT are detected, not simulated (spec §17 R10): a
// rule that could match the flow at this hop is named in a note and makes the hop
// Inferred, and the path still follows the forwarding table. PAN-OS evaluates PBF
// before the route lookup and NAT after it, on the pre-NAT addresses with the
// egress zone from the route lookup (KB "Packet Flow Sequence in PAN-OS").

// hopPolicy is one hop's configuration, loaded once for both stages.
type hopPolicy struct {
	cfg    *config.Config
	target *resolve.Target
	scope  config.Scope
}

// policy loads the hop's configuration; false when there is none to read.
func (s *state) policy(h *Hop) (hopPolicy, bool) {
	if s.env.Load == nil || h.Vsys == "" {
		return hopPolicy{}, false
	}
	t, err := s.env.Load(h.Device, h.Vsys)
	if err != nil || t.Config == nil {
		return hopPolicy{}, false
	}
	tgs, _ := resolve.Targets(t.Config)
	for _, tg := range tgs {
		if tg.Scope().Name == h.Vsys {
			return hopPolicy{cfg: t.Config, target: tg, scope: tg.Scope()}, true
		}
	}
	return hopPolicy{}, false
}

// pbf names the first PBF rule of the hop's vsys that could take this packet.
func pbf(_ context.Context, s *state) (simulate.Outcome, error) {
	h := s.hop()
	hp, ok := s.policy(h)
	if !ok {
		return simulate.Outcome{
			Fidelity: simulate.NotEvaluated("policy-based forwarding"),
			Detail:   "no configuration for " + h.Device + " " + orUnknown(h.Vsys),
		}, nil
	}
	out := simulate.Outcome{Fidelity: simulate.Exact, Detail: "no PBF rule could match"}
	if gap := hp.cfg.VersionGap(); gap != "" {
		h.Notes = append(h.Notes, fmt.Sprintf("schema: PBF and NAT checked with the %s digest", hp.cfg.DigestVersion()))
		out.Fidelity = simulate.Inferred
	}
	rules := hp.target.PBFRules()
	src, dst := s.sides(hp, resolve.PBF, func(i int) (bool, bool) { return rules[i].NegateSource, rules[i].NegateDestination })
	for i, r := range rules {
		if r.Disabled || !src.Contains(uint32(i)) || !dst.Contains(uint32(i)) || !pbfFrom(r, h.In) {
			continue
		}
		note := ""
		switch r.ActionKind {
		case resolve.PBFForward:
			note = fmt.Sprintf("pbf rule %s may forward this packet to %s", r.Name, r.EgressInterface)
			if r.NextHop != "" {
				note += " via " + r.NextHop
			}
		case resolve.PBFForwardToVsys:
			note = fmt.Sprintf("pbf rule %s may forward this packet to %s", r.Name, r.ForwardVsys)
		case resolve.PBFDiscard:
			note = fmt.Sprintf("pbf rule %s may drop this packet", r.Name)
		}
		if note != "" {
			h.Notes = append(h.Notes, note)
			out.Fidelity, out.Detail = simulate.Inferred, note
		} else {
			out.Detail = "pbf rule " + r.Name + " leaves the packet to routing"
		}
		break // the first match wins
	}
	return out, nil
}

// pbfFrom reports whether a PBF rule's source zone or interface fits the ingress.
// An unknown ingress fits anything: the rule cannot be ruled out.
func pbfFrom(r resolve.PBFRule, in Port) bool {
	if slices.Contains(r.From, "any") {
		return true
	}
	if r.FromKind == "interface" {
		return in.Interface == "" || slices.Contains(r.From, in.Interface)
	}
	return in.Zone == "" || slices.Contains(r.From, in.Zone)
}

// nat names the first NAT rule of the hop's vsys that could translate this packet,
// and marks the hop Inferred after an earlier hop could have.
func nat(_ context.Context, s *state) (simulate.Outcome, error) {
	if s.done {
		return ended, nil
	}
	h := s.hop()
	out := simulate.Outcome{Fidelity: simulate.Exact, Detail: "no NAT rule could match"}
	if s.translated != "" {
		h.Notes = append(h.Notes, "nat on "+s.translated+" may change the addresses this hop sees")
		out.Fidelity = simulate.Inferred
	}
	hp, ok := s.policy(h)
	if !ok {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.NotEvaluated("NAT"))
		out.Detail = "no configuration for " + h.Device + " " + orUnknown(h.Vsys)
		return out, nil
	}
	if hp.cfg.VersionGap() != "" {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.Inferred)
	}
	rules := hp.target.NATRules()
	src, dst := s.sides(hp, resolve.NAT, func(int) (bool, bool) { return false, false })
	for i, r := range rules {
		if r.Disabled || r.NATType != "ipv4" || !src.Contains(uint32(i)) || !dst.Contains(uint32(i)) || !natZones(r, h) {
			continue
		}
		var what []string
		if r.SourceTranslation != "" {
			what = append(what, "the source")
		}
		if r.DestinationTranslation != "" {
			what = append(what, "the destination")
		}
		if len(what) > 0 {
			note := fmt.Sprintf("nat rule %s may change %s", r.Name, joinAnd(what))
			h.Notes = append(h.Notes, note)
			out.Fidelity, out.Detail = simulate.Inferred, note
			s.translated = h.Device
		}
		break // the first match wins
	}
	// A bi-directional static rule also translates traffic sent to its translated
	// address back to the original ("NAT Policy Rule", Translated Packet tab).
	for _, r := range rules {
		if !r.Disabled && r.BiDirectional && s.holds(hp, r.StaticAddress, s.dst) {
			note := fmt.Sprintf("nat rule %s may change the destination (bi-directional)", r.Name)
			h.Notes = append(h.Notes, note)
			out.Fidelity, out.Detail = simulate.Inferred, note
			s.translated = h.Device
		}
	}
	return out, nil
}

// natZones reports whether a NAT rule's zones and egress interface fit the hop.
// Its to zone is the egress zone of the route lookup for the pre-NAT destination.
func natZones(r resolve.NATRule, h *Hop) bool {
	fits := func(members []string, v string) bool {
		return v == "" || slices.Contains(members, "any") || slices.Contains(members, v)
	}
	return fits(r.Fields["from"], h.In.Zone) && fits(r.Fields["to"], h.Out.Zone) &&
		(r.ToInterface == "any" || h.Out.Interface == "" || r.ToInterface == h.Out.Interface)
}

// sides returns the rules whose source and whose destination could hold the
// flow's addresses, with negated sides inverted. An unknown source holds anything.
func (s *state) sides(hp hopPolicy, rb resolve.Rulebase, negated func(int) (bool, bool)) (*roaring.Bitmap, *roaring.Bitmap) {
	idx, err := index.ForRulebase(hp.cfg, hp.scope, rb)
	all := roaring.New()
	if err != nil {
		return all, all
	}
	n := len(idx.Rules())
	all.AddRange(0, uint64(n))
	side := func(f index.Field, a netip.Addr, neg func(int) bool) *roaring.Bitmap {
		if !a.IsValid() {
			return all.Clone()
		}
		b, _ := idx.Candidates(f, a.String())
		out := b.Clone()
		for i := range n {
			if neg(i) {
				if b.Contains(uint32(i)) {
					out.Remove(uint32(i))
				} else {
					out.Add(uint32(i))
				}
			}
		}
		return out
	}
	src := side(index.Source, s.src, func(i int) bool { ns, _ := negated(i); return ns })
	dst := side(index.Destination, s.dst, func(i int) bool { _, nd := negated(i); return nd })
	return src, dst
}

// holds reports whether an address or address object's value holds a.
func (s *state) holds(hp hopPolicy, value string, a netip.Addr) bool {
	vals := []string{value}
	if objs, err := resolve.ObjectsInScope(hp.cfg, hp.scope, "address"); err == nil {
		for _, o := range objs {
			if o.Name == value {
				vals = append(vals, o.Value)
			}
		}
	}
	for _, v := range vals {
		for _, p := range index.PrefixesOf(v) {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

func joinAnd(parts []string) string { return strings.Join(parts, " and ") }
