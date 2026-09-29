// Package rulebase matches a flow's addresses against one vsys's PBF and NAT
// rulebases through the rulebase's own index, and checks policy-based forwarding.
// The routing and NAT simulations share it (spec §17 R10, §18 D4).
package rulebase

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// Vsys is one vsys's configuration, loaded once for every rulebase check.
type Vsys struct {
	Config *config.Config
	Target *resolve.Target
	Scope  config.Scope
}

// Load reads a device's vsys through a simulation's loader; false when there is
// no configuration to read.
func Load(load func(device, vsys string) (simulate.Target, error), device, vsys string) (Vsys, bool) {
	if load == nil || vsys == "" {
		return Vsys{}, false
	}
	t, err := load(device, vsys)
	if err != nil || t.Config == nil {
		return Vsys{}, false
	}
	tgs, _ := resolve.Targets(t.Config)
	for _, tg := range tgs {
		if tg.Scope().Name == vsys {
			return Vsys{Config: t.Config, Target: tg, Scope: tg.Scope()}, true
		}
	}
	return Vsys{}, false
}

// Sides returns the rules, by position in the rulebase, whose source and whose
// destination could hold the flow's addresses, negated sides inverted. An invalid
// address holds anything. When the index cannot be built, no rule is returned.
func (v Vsys) Sides(rb resolve.Rulebase, src, dst netip.Addr, negated func(int) (bool, bool)) (*roaring.Bitmap, *roaring.Bitmap) {
	idx, err := index.ForRulebase(v.Config, v.Scope, rb)
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
	s := side(index.Source, src, func(i int) bool { ns, _ := negated(i); return ns })
	d := side(index.Destination, dst, func(i int) bool { _, nd := negated(i); return nd })
	return s, d
}

// Holds reports whether an address, or an address object's value, holds a.
func (v Vsys) Holds(value string, a netip.Addr) bool {
	vals := []string{value}
	if objs, err := resolve.ObjectsInScope(v.Config, v.Scope, "address"); err == nil {
		for _, o := range objs {
			if o.Name == value {
				vals = append(vals, o.Value)
			}
		}
	}
	for _, val := range vals {
		for _, p := range index.PrefixesOf(val) {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}

// PBF returns the first PBF rule that could take the flow arriving on in, and
// what it would do: "" for no-pbf, which leaves the packet to routing. ok is false
// when no rule could match. A disabled rule never matches.
func (v Vsys) PBF(src, dst netip.Addr, in simulate.Port) (rule resolve.PBFRule, note string, ok bool) {
	rules := v.Target.PBFRules()
	s, d := v.Sides(resolve.PBF, src, dst, func(i int) (bool, bool) { return rules[i].NegateSource, rules[i].NegateDestination })
	for i, r := range rules {
		if r.Disabled || !s.Contains(uint32(i)) || !d.Contains(uint32(i)) || !FromFits(r, in) {
			continue
		}
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
		return r, note, true
	}
	return resolve.PBFRule{}, "", false
}

// FromFits reports whether a PBF rule's source zone or interface fits the
// ingress. An unknown ingress fits anything: the rule cannot be ruled out.
func FromFits(r resolve.PBFRule, in simulate.Port) bool {
	if slices.Contains(r.From, "any") {
		return true
	}
	if r.FromKind == "interface" {
		return in.Interface == "" || slices.Contains(r.From, in.Interface)
	}
	return in.Zone == "" || slices.Contains(r.From, in.Zone)
}
