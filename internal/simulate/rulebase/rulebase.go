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

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
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

// Side is the rules one side of a rulebase could hold an address in.
type Side struct {
	// Rules holds the rules whose side holds the address by what the
	// configuration states, negated sides inverted.
	Rules *roaring.Bitmap
	// May holds, by rule position, the rules the side only may hold, and why:
	// they name an external list, a region or a dynamic address group, which
	// can hold the address without the configuration saying so.
	May map[uint32][]reason.Reason
}

// Holds reports whether the side holds rule i, for sure or only perhaps.
func (s Side) Holds(i uint32) bool {
	_, may := s.May[i]
	return may || s.Rules.Contains(i)
}

// Sides returns the rules, by position in the rulebase, whose source and whose
// destination could hold the flow's addresses, negated sides inverted, and on
// each side the rules it only may hold. An invalid address holds anything.
//
// Values the index recognised but could not evaluate come back as unresolved: a
// rule reached only through one of them can be missing from its side. An index
// that cannot be built returns no rule and says so as an unresolved entry, because
// a silent "no rule" would be a wrong answer that looks complete.
func (v Vsys) Sides(rb resolve.Rulebase, src, dst netip.Addr, negated func(int) (bool, bool)) (
	s, d Side, unresolved []index.Unresolved,
) {
	idx, err := v.index(rb)
	if err != nil {
		why := reason.New("gap.load-failed", fmt.Sprintf("the %s rules of %s were not checked: %v", rb, v.Scope.Name, err))
		return Side{Rules: roaring.New()}, Side{Rules: roaring.New()}, []index.Unresolved{index.NewUnresolved(v.Scope.Name, "", why)}
	}
	view := idx.With(index.Providers{})
	n := len(idx.Rules())
	all := roaring.New()
	all.AddRange(0, uint64(len(idx.Rules())))
	one := func(f index.Field, a netip.Addr, neg func(int) bool) Side {
		if !a.IsValid() {
			return Side{Rules: all.Clone()}
		}
		b, rep := idx.Candidates(f, a.String())
		unresolved = append(unresolved, rep.Unresolved...)
		out := Side{Rules: b.Clone()}
		for i := range n {
			if neg(i) {
				if b.Contains(uint32(i)) {
					out.Rules.Remove(uint32(i))
				} else {
					out.Rules.Add(uint32(i))
				}
			}
		}
		// A rule that names an external list, a region or a dynamic group
		// may hold the address without the configuration saying so. Unless
		// a stated value already decides it, it only may hold it, negated or
		// not, as in the security check (spec E23).
		opaque, why := view.Opaque(f)
		opaque.AndNot(b)
		for it := opaque.Iterator(); it.HasNext(); {
			if out.May == nil {
				out.May = map[uint32][]reason.Reason{}
			}
			bit := it.Next()
			out.May[bit] = simulate.Reasons(why[bit]).Prefixed(f.String() + ": ")
		}
		return out
	}
	s = one(index.Source, src, func(i int) bool { ns, _ := negated(i); return ns })
	d = one(index.Destination, dst, func(i int) bool { _, nd := negated(i); return nd })
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

// Addresses maps the name of each address object the vsys sees to its value.
// Reading the objects costs a walk of the configuration, so a caller reads them
// once per question and asks Holds of the map.
type Addresses map[string]string

// Addresses returns the address objects the vsys sees. An address group of the
// same name in a nearer scope hides an address (L10).
func (v Vsys) Addresses() Addresses {
	objs := resolve.ObjectsOfKindsInScope(v.Config, v.Scope, "address", "address-group")["address"]
	out := make(Addresses, len(objs))
	for _, o := range objs {
		out[o.Name] = o.Value
	}
	return out
}

// Holds reports whether an address, or the value of the address object of that
// name, holds a.
func (m Addresses) Holds(value string, a netip.Addr) bool {
	vals := []string{value}
	if v, ok := m[value]; ok {
		vals = append(vals, v)
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
	// only may match, because it names an application or a user or has a
	// schedule, which are not evaluated, a service the answer cannot judge on
	// this flow, or an external list, a region or a dynamic group as source or
	// destination, the note ends with ", if it matches: " and why.
	Note reason.Reason
	// Doubts are why Rule only may match, each with its code; none for a sure
	// match.
	Doubts []reason.Reason
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
// application or a user, has a schedule, names a service the answer cannot
// judge, or an external list, a region or a dynamic group the configuration
// does not place the address in, only may match.
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
		bit := uint32(i) //nolint:gosec // a rule position cannot reach 2^32; a rulebase is capped far below that
		if r.Disabled || !s.Holds(bit) || !d.Holds(bit) || !FromFits(r, in) {
			continue
		}
		fields := withDefaults(r.Fields, defaults)
		why, fits := svc.judge(i, fields["service"])
		if !fits {
			continue
		}
		doubts := slices.Concat(s.May[bit], d.May[bit], why, notEvaluated(fields, r.Schedule))
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
		m.Rule, m.Found, m.Doubts = r, true, doubts
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
// evaluate: the application, the source user and the schedule. PBF builds its
// view without providers, so it keeps the user doubt, as it keeps the
// application doubt (spec 2026-10-16 D5, spec 2026-10-17 §5.3).
func notEvaluated(fields map[string][]string, schedule string) []reason.Reason {
	var out []reason.Reason
	if names(fields["application"]) {
		out = append(out, reason.New("doubt.application", "the rule names an application, which is not evaluated"))
	}
	if names(fields["source-user"]) {
		out = append(out, reason.New("doubt.not-evaluated.user", "the rule names a source user, which is not evaluated"))
	}
	if schedule != "" {
		out = append(out, reason.New("doubt.schedule", fmt.Sprintf("schedule not evaluated (%s)", schedule)))
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
	cfg        *config.Config
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
	out.term, out.hits, out.unresolved = term, b, rep.Unresolved
	out.defined, out.cfg = Defined(v.Config, v.Scope, resolve.PBF, "service"), v.Config
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
		return []reason.Reason{UndefinedService(m.cfg,
			"the rule names a service the configuration does not define, such as a predefined one")}, true
	}
	return nil, false
}

// protocolNames are the IANA protocol numbers of the protocols a service names,
// which the command line takes as a flow's protocol.
var protocolNames = map[string]string{"6": "tcp", "17": "udp", "132": "sctp"}

// Protocol is a flow's protocol by name, lower case: 6, 17 and 132 read as tcp,
// udp and sctp, so a protocol given by number compares as the name a service
// uses.
func Protocol(p string) string {
	p = strings.ToLower(p)
	if n, ok := protocolNames[p]; ok {
		return n
	}
	return p
}

// ServiceTerm is the flow's protocol and destination port as a service query,
// "tcp/443". False when there is no port, or the protocol has none.
func ServiceTerm(proto string, port uint16) (string, bool) {
	proto = Protocol(proto)
	if port == 0 || (proto != "tcp" && proto != "udp" && proto != "sctp") {
		return "", false
	}
	return fmt.Sprintf("%s/%d", proto, port), true
}

// Defined returns the names a configuration defines for the kinds a rulebase's
// field may name, so a value outside them is predefined or unknown here.
//
// A static group counts only when every member does, through nested groups: a
// group that holds service-https in a snapshot without the predefined services
// cannot rule out a flow its other members miss. A member on a cycle adds
// nothing, so a group that holds only a cycle, or nothing, does not count.
func Defined(cfg *config.Config, sc config.Scope, rb resolve.Rulebase, field string) map[string]bool {
	out := map[string]bool{}
	members := map[string][]string{} // each static group's members
	for _, kind := range cfg.FieldKinds("rulebase/" + rb.String() + "/rules")[field] {
		group := isGroupKind(cfg, kind)
		// A name resolves by scope first, kind second: a namesake of
		// another kind in a nearer scope hides this one (L9).
		for _, o := range resolve.ObjectsOfKindsInScope(cfg, sc, resolve.Namesakes(kind)...)[kind] {
			if !group || o.Dynamic {
				out[o.Name] = true
				continue
			}
			members[o.Name] = []string{}
			for m := range strings.SplitSeq(o.Value, ", ") {
				if m = strings.TrimSpace(m); m != "" {
					members[o.Name] = append(members[o.Name], m)
				}
			}
		}
	}
	// A group holds a defined object when one of its groups, at any depth,
	// names one, and misses a member when one of them names a value that is
	// neither an object nor a group. Each spreads from the groups that name
	// it to every group holding them; a group is taken once, so a cycle ends.
	holders := map[string][]string{}
	var holds, misses []string
	for g, ms := range members {
		for _, m := range ms {
			_, isGroup := members[m]
			switch {
			case isGroup:
				holders[m] = append(holders[m], g)
			case out[m]:
				holds = append(holds, g)
			default:
				misses = append(misses, g)
			}
		}
	}
	spread := func(from []string) map[string]bool {
		seen := map[string]bool{}
		for len(from) > 0 {
			g := from[len(from)-1]
			from = from[:len(from)-1]
			if !seen[g] {
				seen[g] = true
				from = append(from, holders[g]...)
			}
		}
		return seen
	}
	held, missing := spread(holds), spread(misses)
	for g := range members {
		if held[g] && !missing[g] {
			out[g] = true
		}
	}
	return out
}

// isGroupKind reports whether a kind is a group kind: its member list can name
// the kind itself, as the schema says (R1). A service group and an address
// group are; a custom URL category, whose list holds URLs, is not.
func isGroupKind(cfg *config.Config, kind string) bool {
	for _, kinds := range cfg.FieldKinds("/" + kind) {
		if slices.Contains(kinds, kind) {
			return true
		}
	}
	return false
}

// UndefinedService is the doubt of a rule that names a service no scope defines,
// with text saying what. A configuration without the device's predefined services
// does not hold service-http and service-https. The device answers them to a show
// command (as observed on fw02, PAN-OS 12.2.3, L4), so a fetch stores them when
// the device returns them, and the text says so. The snapshot may predate that
// fetch, or the device may have refused it; the text holds for both.
func UndefinedService(cfg *config.Config, text string) reason.Reason {
	if cfg == nil || cfg.Predefined() == nil {
		text += "; the snapshot holds no predefined services; a fetch with this release stores them when the device returns them"
	}
	return reason.New("doubt.service-predefined", text)
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

// ZoneRefusal is a given zone a scope does not define (C15), and the zones it
// does define. Choice is the refusal for a front end; Text names it in words
// neither the command line nor a tool uses, for a hole.
type ZoneRefusal struct {
	Choice *simulate.ChoiceError
	Text   string
}

// UndefinedZones refuses the first of the given from and to zones the scope
// does not define; nil when it defines both, or a zone is not given. The
// refusal names the zone as the command line gives it (--from-zone) and as a
// tool does (from_zone), and lists the scope's zones, so the caller can pick
// one. Its kind is simulate.ChoiceZone.
func UndefinedZones(cfg *config.Config, sc config.Scope, from, to string) *ZoneRefusal {
	zones := resolve.ZoneNames(cfg, sc)
	known := "it defines no zone"
	if len(zones) > 0 {
		known = "its zones: " + strings.Join(zones, ", ")
	}
	for _, g := range []struct{ flag, field, side, zone string }{
		{"--from-zone", "from_zone", "the from zone", from}, {"--to-zone", "to_zone", "the to zone", to},
	} {
		if g.zone == "" || slices.Contains(zones, g.zone) {
			continue
		}
		what := fmt.Sprintf("%s is not a zone of %s (%s)", g.zone, sc.Name, known)
		return &ZoneRefusal{
			Choice: &simulate.ChoiceError{Kind: simulate.ChoiceZone, Question: g.flag + " " + what, ToolText: g.field + " " + what},
			Text:   g.side + " " + what,
		}
	}
	return nil
}
