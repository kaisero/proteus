package routing

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/okaiser/panos-analyst/resolve"
	"github.com/okaiser/panos-analyst/simulate"
	"github.com/okaiser/panos-analyst/simulate/policy"
)

// Policy-based forwarding and NAT are detected, not simulated (spec §17 R10): a
// rule that could match the flow at this hop is named in a note and makes the hop
// Inferred, and the path still follows the forwarding table. PAN-OS evaluates PBF
// before the route lookup and NAT after it, on the pre-NAT addresses with the
// egress zone from the route lookup (KB "Packet Flow Sequence in PAN-OS").

// policy loads the hop's configuration; false when there is none to read.
func (s *state) policy(h *Hop) (policy.Vsys, bool) {
	return policy.Load(s.env.Load, h.Device, h.Vsys)
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
		h.Notes = append(h.Notes, fmt.Sprintf("schema: PBF and NAT checked with the %s digest", v.Config.DigestVersion()))
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
	v, ok := s.policy(h)
	if !ok {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.NotEvaluated("NAT"))
		out.Detail = "no configuration for " + h.Device + " " + orUnknown(h.Vsys)
		return out, nil
	}
	if v.Config.VersionGap() != "" {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.Inferred)
	}
	rules := v.Target.NATRules()
	src, dst := v.Sides(resolve.NAT, s.src, s.dst, func(int) (bool, bool) { return false, false })
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
		if !r.Disabled && r.BiDirectional && v.Holds(r.StaticAddress, s.dst) {
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

func joinAnd(parts []string) string { return strings.Join(parts, " and ") }
