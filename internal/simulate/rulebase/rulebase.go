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
	"github.com/okaiser/proteus/internal/reason"
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
	tgs := resolve.Targets(t.Config)
	for _, tg := range tgs {
		if tg.Scope().Name == vsys {
			return Vsys{Config: t.Config, Target: tg, Scope: tg.Scope()}, true
		}
	}
	return Vsys{}, false
}

// Sides returns the rules, by position in the rulebase, whose source and whose
// destination could hold the flow's addresses, negated sides inverted. An invalid
// address holds anything.
//
// Values the index recognised but could not evaluate come back as unresolved: a
// rule reached only through one of them can be missing from its side. A schema
// version gap is left out; the callers note it themselves. An index that cannot be
// built returns no rule and says so as an unresolved entry, because a silent "no
// rule" would be a wrong answer that looks complete.
func (v Vsys) Sides(rb resolve.Rulebase, src, dst netip.Addr, negated func(int) (bool, bool)) (
	s, d *roaring.Bitmap, unresolved []index.Unresolved,
) {
	idx, err := index.ForRulebase(v.Config, v.Scope, rb)
	if err != nil {
		why := reason.New("gap.load-failed", fmt.Sprintf("the %s rules of %s were not checked: %v", rb, v.Scope.Name, err))
		return roaring.New(), roaring.New(), []index.Unresolved{index.NewUnresolved(v.Scope.Name, "", why)}
	}
	n := len(idx.Rules())
	all := roaring.New()
	all.AddRange(0, uint64(len(idx.Rules())))
	side := func(f index.Field, a netip.Addr, neg func(int) bool) *roaring.Bitmap {
		if !a.IsValid() {
			return all.Clone()
		}
		b, rep := idx.Candidates(f, a.String())
		unresolved = append(unresolved, withoutGap(rep.Unresolved)...)
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
	s = side(index.Source, src, func(i int) bool { ns, _ := negated(i); return ns })
	d = side(index.Destination, dst, func(i int) bool { _, nd := negated(i); return nd })
	return s, d, unresolved
}

// withoutGap drops the schema version gap from a report's unresolved values. The
// callers of Sides note a gap themselves, as an inferred answer rather than a
// missing one.
func withoutGap(unresolved []index.Unresolved) []index.Unresolved {
	var out []index.Unresolved
	for _, u := range unresolved {
		if u.Code != "gap.version" {
			out = append(out, u)
		}
	}
	return out
}

// Holds reports whether an address, or an address object's value, holds a.
func (v Vsys) Holds(value string, a netip.Addr) bool {
	vals := []string{value}
	for _, o := range resolve.ObjectsInScope(v.Config, v.Scope, "address") {
		if o.Name == value {
			vals = append(vals, o.Value)
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

// Certainty is what unresolved values do to an answer about a rulebase: exact when
// there are none, else under-match, because a rule reached only through one of them
// may be missing.
func Certainty(rb resolve.Rulebase, unresolved []index.Unresolved) simulate.Fidelity {
	if len(unresolved) == 0 {
		return simulate.Exact
	}
	return simulate.UnderMatch(reason.New("gap.object-unresolved",
		fmt.Sprintf("a %s rule reached only through an unresolved value may be missing", rb)))
}

// PBFMatch is the result of checking a flow against a vsys's PBF rules.
type PBFMatch struct {
	// Rule is the first rule that could take the flow; Found says whether there is one.
	Rule  resolve.PBFRule
	Found bool
	// Note says what the rule would do; the zero reason for no-pbf, which leaves
	// the packet to routing.
	Note reason.Reason
	// Unresolved lists values the rules name that could not be evaluated. A rule
	// reached only through one of them may be missing.
	Unresolved []index.Unresolved
}

// PBF returns the first PBF rule that could take the flow arriving on in, and what
// it would do. A disabled rule never matches.
func (v Vsys) PBF(src, dst netip.Addr, in simulate.Port) PBFMatch {
	rules := v.Target.PBFRules()
	s, d, un := v.Sides(resolve.PBF, src, dst, func(i int) (bool, bool) {
		return rules[i].NegateSource, rules[i].NegateDestination
	})
	m := PBFMatch{Unresolved: un}
	for i, r := range rules {
		if r.Disabled || !s.Contains(uint32(i)) || !d.Contains(uint32(i)) || !FromFits(r, in) {
			continue
		}
		switch r.ActionKind {
		case resolve.PBFForward:
			note := fmt.Sprintf("pbf rule %s may forward this packet to %s", r.Name, r.EgressInterface)
			if r.NextHop != "" {
				note += " via " + r.NextHop
			}
			m.Note = reason.New("path.pbf", note)
		case resolve.PBFForwardToVsys:
			m.Note = reason.New("path.pbf", fmt.Sprintf("pbf rule %s may forward this packet to %s", r.Name, r.ForwardVsys))
		case resolve.PBFDiscard:
			m.Note = reason.New("path.pbf", fmt.Sprintf("pbf rule %s may drop this packet", r.Name))
		}
		m.Rule, m.Found = r, true
		return m
	}
	return m
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
