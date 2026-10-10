// Package rulebase matches a flow's addresses against one vsys's PBF and NAT
// rulebases through the rulebase's own index, and checks policy-based forwarding.
// The routing and NAT simulations share it (spec §17 R10, §18 D4).
package rulebase

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

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
	// Indexes is the loaded target's index provider.
	Indexes func(resolve.Rulebase) (*index.Index, error)
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
			return Vsys{Config: t.Config, Target: tg, Scope: tg.Scope(), Indexes: t.Indexes}, true
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
	idx, err := v.index(rb)
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

// index returns the vsys's index of a rulebase from the loader's provider. A target
// without one is a loader's mistake, reported like a failed build rather than
// built here: the loader's owner keeps the indexes.
func (v Vsys) index(rb resolve.Rulebase) (*index.Index, error) {
	if v.Indexes == nil {
		return nil, errors.New("no index provider")
	}
	idx, err := v.Indexes(rb)
	if err != nil {
		return nil, err
	}
	// A provider of another vsys would answer with that vsys's rules.
	if idx.Scope() != v.Scope {
		return nil, fmt.Errorf("the index provider gives %s, not %s", idx.Scope(), v.Scope)
	}
	return idx, nil
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
	// the packet to routing only on a sure match. When a forward or discard rule
	// only may match, because it names an application or a user, which are not
	// evaluated, or a service the answer cannot judge on this flow, the note ends
	// with ", if it matches: " and why.
	Note reason.Reason
	// Passed are the no-pbf rules before Rule that only may match. Only a sure
	// no-pbf match ends the scan, so the scan went on past them.
	Passed []PBFPassed
	// Unresolved lists values the rules name that could not be evaluated. A rule
	// reached only through one of them may be missing.
	Unresolved []index.Unresolved
}

// PBFPassed is a no-pbf rule the scan went past because it only may match.
type PBFPassed struct {
	Rule   string
	Doubts []reason.Reason
}

// String says which rule and why it only may match.
func (p PBFPassed) String() string {
	return fmt.Sprintf("no-pbf rule %s may match (%s)", p.Rule, texts(p.Doubts))
}

// PassedText is the passed no-pbf rules as a suffix to a stage's detail; empty
// when there are none.
func PassedText(ps []PBFPassed) string {
	var out strings.Builder
	for _, p := range ps {
		out.WriteString("; " + p.String())
	}
	return out.String()
}

func texts(rs []reason.Reason) string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Text)
	}
	return strings.Join(out, "; ")
}

// PBF returns the first PBF rule that could take the flow arriving on in, and what
// it would do. A disabled rule never matches. proto and port are the flow's
// protocol and destination port; a port of 0 means none was given.
//
// A rule matches on its from, addresses and service. A rule that names an
// application or a user, or a service the answer cannot judge, only may match.
// Such a forward or discard rule still ends the scan: it can redirect the packet,
// so the path is undecided. Such a no-pbf rule does not: only a sure no-pbf
// match leaves the packet to routing. As observed on fw02, PAN-OS 12.2.3 (L3): a
// no-pbf rule with service tcp/22 above a forward rule with service any took
// tcp/22; tcp/443 and udp/22 went on to the forward rule.
func (v Vsys) PBF(src, dst netip.Addr, proto string, port uint16, in simulate.Port) PBFMatch {
	rules := v.Target.PBFRules()
	s, d, un := v.Sides(resolve.PBF, src, dst, func(i int) (bool, bool) {
		return rules[i].NegateSource, rules[i].NegateDestination
	})
	m := PBFMatch{Unresolved: un}
	svc := v.pbfServices(rules, proto, port)
	m.Unresolved = append(m.Unresolved, svc.unresolved...)
	defaults := pbfDefaults(v.Config)
	for i, r := range rules {
		if r.Disabled || !s.Contains(uint32(i)) || !d.Contains(uint32(i)) || !FromFits(r, in) {
			continue
		}
		fields := withDefaults(r.Fields, defaults)
		doubts, fits := svc.judge(i, fields["service"])
		if !fits {
			continue
		}
		doubts = append(doubts, notEvaluated(fields)...)
		if r.ActionKind == resolve.PBFNoPBF && len(doubts) > 0 {
			m.Passed = append(m.Passed, PBFPassed{Rule: r.Name, Doubts: doubts})
			continue
		}
		var note string
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
			if len(doubts) > 0 {
				note += ", if it matches: " + texts(doubts)
			}
			m.Note = reason.New("path.pbf", note)
		}
		m.Rule, m.Found = r, true
		return m
	}
	return m
}

// pbfFields are the PBF rule fields the check reads.
var pbfFields = []string{"service", "application", "source-user"}

// pbfDefaults reads, from the schema digest, the member a PBF rule field holds when
// the configuration leaves it out (R1). The 11.2.0 digest gives "any" for all
// three, at /config/devices/entry/vsys/entry/rulebase/pbf/rules/entry/<field>/member.
func pbfDefaults(cfg *config.Config) map[string]string {
	entry := cfg.Digest() // the config element
	for _, seg := range []string{"devices", "entry", "vsys", "entry", "rulebase", "pbf", "rules", "entry"} {
		entry = entry.Child(seg)
	}
	out := map[string]string{}
	for _, f := range pbfFields {
		if d := entry.Child(f).Child("member"); d != nil && d.Default != "" {
			out[f] = d.Default
		}
	}
	return out
}

// withDefaults is a rule's fields with each field it leaves out at its schema
// default. A field without a default stays absent.
func withDefaults(fields map[string][]string, defaults map[string]string) map[string][]string {
	out := make(map[string][]string, len(fields)+len(defaults))
	maps.Copy(out, fields)
	for f, d := range defaults {
		if len(out[f]) == 0 {
			out[f] = []string{d}
		}
	}
	return out
}

// notEvaluated is why a rule only may match for the dimensions a PBF check does not
// evaluate: the application and the source user (todo item 22).
func notEvaluated(fields map[string][]string) []reason.Reason {
	var out []reason.Reason
	if names(fields["application"]) {
		out = append(out, reason.New("doubt.application", "the rule names an application, which is not evaluated"))
	}
	if names(fields["source-user"]) {
		out = append(out, reason.New("doubt.not-evaluated.user", "the rule names a source user, which is not evaluated"))
	}
	return out
}

// names reports whether a field names something other than any.
func names(values []string) bool {
	for _, v := range values {
		if v != "any" {
			return true
		}
	}
	return false
}

// pbfServiceMatch is the flow's service matched against a PBF rulebase.
type pbfServiceMatch struct {
	term       string          // "tcp/443"; empty when the flow has no port
	hits       *roaring.Bitmap // rules whose service carries the flow
	defined    map[string]bool // the service names the configuration defines
	unresolved []index.Unresolved
}

// pbfServices matches the flow's protocol and port against the PBF rules' services
// through the PBF index, as the security check does through its own.
func (v Vsys) pbfServices(rules []resolve.PBFRule, proto string, port uint16) pbfServiceMatch {
	out := pbfServiceMatch{hits: roaring.New()}
	term, ok := ServiceTerm(proto, port)
	if !ok || len(rules) == 0 {
		return out
	}
	idx, err := v.index(resolve.PBF)
	if err != nil {
		return out // Sides has said so; no rule passes it
	}
	b, rep := idx.Candidates(index.Service, term)
	out.term, out.hits, out.unresolved = term, b, withoutGap(rep.Unresolved)
	out.defined = Defined(v.Config, v.Scope, resolve.PBF, "service")
	return out
}

// judge says whether rule i's service values can carry the flow, and if only
// perhaps, why. No values means the schema gave no default to fall back on.
func (m pbfServiceMatch) judge(i int, values []string) ([]reason.Reason, bool) {
	switch {
	case len(values) == 0:
		return []reason.Reason{reason.New("doubt.service-absent", "the rule names no service")}, true
	case !names(values):
		return nil, true
	case m.term == "":
		return []reason.Reason{reason.New("doubt.service-no-port", "the rule names a service, and the flow has no port")}, true
	case m.hits.Contains(uint32(i)): //nolint:gosec // a rule position cannot reach 2^32; a rulebase is capped far below that
		return nil, true
	case slices.Contains(values, "application-default"):
		return []reason.Reason{reason.New("doubt.service-application-default",
			"the rule uses service application-default, whose ports depend on the application")}, true
	case Undecidable(values, m.defined):
		return []reason.Reason{reason.New("doubt.service-predefined",
			"the rule names a service the configuration does not define, such as a predefined one")}, true
	}
	return nil, false
}

// ServiceTerm is the flow's protocol and destination port as a service query,
// "tcp/443". False when there is no port, or the protocol has none.
func ServiceTerm(proto string, port uint16) (string, bool) {
	proto = strings.ToLower(proto)
	if port == 0 || (proto != "tcp" && proto != "udp" && proto != "sctp") {
		return "", false
	}
	return fmt.Sprintf("%s/%d", proto, port), true
}

// Defined returns the names a configuration defines for the kinds a rulebase's
// field may name, so a value outside them is predefined or unknown here.
func Defined(cfg *config.Config, sc config.Scope, rb resolve.Rulebase, field string) map[string]bool {
	out := map[string]bool{}
	for _, kind := range cfg.FieldKinds("rulebase/" + rb.String() + "/rules")[field] {
		for _, o := range resolve.ObjectsInScope(cfg, sc, kind) {
			out[o.Name] = true
		}
	}
	return out
}

// Undecidable reports whether a field names a value the configuration cannot
// judge: one of the keywords, or a name it does not define. "any" can always be
// judged.
func Undecidable(values []string, defined map[string]bool, keywords ...string) bool {
	for _, v := range values {
		if v == "any" {
			continue
		}
		if slices.Contains(keywords, v) || !defined[v] {
			return true
		}
	}
	return false
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
