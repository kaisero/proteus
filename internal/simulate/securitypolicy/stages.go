package securitypolicy

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// steps is the security-policy pipeline. Each matching dimension narrows the
// running candidate set, so the count after every stage falls.
var steps = []simulate.Step[state]{
	{Name: "Resolve the source", Slug: "resolve-source", Do: resolveSource},
	{Name: "Resolve the destination", Slug: "resolve-destination", Do: resolveDestination},
	{Name: "Derive the zones", Slug: "derive-zones", Do: deriveZones},
	{Name: "Match the service", Slug: "match-service", Do: matchService},
	{Name: "Match the URL category", Slug: "match-url", Do: matchURL},
	{Name: "Drop disabled rules", Slug: "drop-disabled", Do: dropDisabled},
	{Name: "Order by evaluation", Slug: "order", Do: order},
	{Name: "Take the first match", Slug: "first-match", Do: firstMatch},
}

func resolveSource(_ context.Context, s *state) (simulate.Outcome, error) {
	b, out := s.side(index.Source, s.in.Flow.Source, func(r resolve.Rule) bool { return r.NegateSource })
	s.cand = b
	out.Candidates = s.cand
	return out, nil
}

func resolveDestination(_ context.Context, s *state) (simulate.Outcome, error) {
	b, out := s.side(index.Destination, s.in.Flow.Destination, func(r resolve.Rule) bool { return r.NegateDestination })
	s.cand.And(b)
	out.Candidates = s.cand
	return out, nil
}

// side resolves one endpoint in one field: the FQDN against FQDN objects, every
// address against everything, and negated rules inverted.
func (s *state) side(f index.Field, ep simulate.Endpoint, negated func(resolve.Rule) bool) (*roaring.Bitmap, simulate.Outcome) {
	b, byFQDN, byAddr := roaring.New(), roaring.New(), roaring.New()
	var out simulate.Outcome
	var hits []string
	if ep.Name != "" {
		// The name reaches rules only through FQDN objects, and a field of any.
		// An object merely named like the FQDN holds an address the
		// configuration states, so the addresses below decide it.
		_, rep := s.view.Candidates(f, ep.Name)
		b.Or(s.idx.RulesWithAny(f))
		for _, h := range rep.Hits {
			hits = append(hits, fmt.Sprintf("%s (%s) via %s", h.Name, h.Kind, h.Via))
			// Only an address object whose value is the name is an FQDN object.
			if h.Kind == "address" && strings.EqualFold(h.Via, ep.Name) {
				byFQDN.Or(s.idx.RulesReaching(f, h.Name))
			}
		}
		b.Or(byFQDN)
		// An FQDN nothing defines is expected; only a real gap, such as a version
		// gap, counts as unresolved.
		for _, u := range rep.Unresolved {
			if u.Value != ep.Name || len(ep.Addrs) == 0 {
				out.Unresolved = append(out.Unresolved, u)
			}
		}
	}
	for _, a := range ep.Addrs {
		ab, rep := s.view.Candidates(f, a.String())
		b.Or(ab)
		byAddr.Or(ab)
		for _, h := range rep.Hits {
			hits = append(hits, fmt.Sprintf("%s (%s) via %s", h.Name, h.Kind, h.Via))
		}
		out.Unresolved = append(out.Unresolved, rep.Unresolved...)
	}
	// A rule naming an external list, a region or a dynamic group may hold the
	// address without the configuration saying so (spec E23). Unless a known path
	// already decides it, it stays a candidate, negated or not, with a doubt.
	opaque, why := s.view.Opaque(f)
	opaque.AndNot(b)
	// A negated rule matches every address except those it lists.
	neg := roaring.New()
	for i, r := range s.rules {
		if negated(r) {
			neg.Add(uint32(i))
		}
	}
	// A rule an FQDN object reaches and no address does matched only through
	// that object. The firewall resolves that object itself and refreshes it
	// (default every 30 minutes), and policy matches the packet's addresses, so
	// the rule holds the flow only if the firewall's answer agrees with this
	// machine's. Source: PAN-OS admin guide, "Use FQDN Objects" (spec 2026-10-09
	// §3.8, R9). A field of any matches every address and is no FQDN match.
	// A negated rule excluded only through such an object may match on the
	// firewall, so it stays a candidate with the same doubt.
	byFQDN.AndNot(byAddr)
	byFQDN.AndNot(s.idx.RulesWithAny(f))
	fqdnOnly := roaring.AndNot(byFQDN, neg)
	fqdnNegated := roaring.And(byFQDN, neg)
	if !neg.IsEmpty() {
		inverted := roaring.AndNot(neg, b)
		b.AndNot(neg)
		b.Or(inverted)
	}
	b.Or(fqdnNegated)
	b.Or(opaque)
	if s.opaque == nil {
		s.opaque = map[string]map[uint32][]reason.Reason{}
	}
	s.opaque[f.String()] = map[uint32][]reason.Reason{}
	for it := opaque.Iterator(); it.HasNext(); {
		bit := it.Next()
		s.opaque[f.String()][bit] = why[bit]
	}
	if s.fqdn == nil {
		s.fqdn = map[string]fqdnMatch{}
	}
	s.fqdn[f.String()] = fqdnMatch{name: ep.Name, rules: fqdnOnly, negated: fqdnNegated}

	switch {
	case ep.Name != "" && len(ep.Addrs) == 0:
		out.Fidelity = simulate.UnderMatch(reason.New("gap.fqdn-no-address",
			fmt.Sprintf("%s resolved to no address, so only FQDN objects of that name were matched", ep.Name)))
	case ep.Resolved:
		out.Fidelity = simulate.Inferred
	default:
		out.Fidelity = simulate.Exact
	}
	out.Unresolved = s.withoutGap(&out.Fidelity, dedupe(out.Unresolved))
	for _, u := range out.Unresolved {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(u.Why()))
	}
	out.Detail = fmt.Sprintf("%s: %d hits, %d negated rules", ep, len(hits), neg.GetCardinality())
	if !opaque.IsEmpty() {
		out.Detail += fmt.Sprintf(", %d kept naming addresses the configuration does not hold", opaque.GetCardinality())
		out.Debug = append(out.Debug, "kept, in doubt: "+names(s.rules, opaque))
	}
	if ep.Resolved {
		out.Detail += fmt.Sprintf("; %s resolved by this machine's DNS to %v, which may answer differently from the firewall's", ep.Name, ep.Addrs)
	}
	out.Debug = append(out.Debug, hits...)
	out.Debug = append(out.Debug, "left: "+names(s.rules, b))
	return b, out
}

// deriveZones narrows by from and to zone. Given zones are exact. Derived ones come
// from where the stored forwarding table or the configuration places each address.
// A source zone is the zone of the interface a packet arrives on, which a table only
// predicts under symmetric routing, so a derived zone is Inferred. Source: PAN-OS
// documentation, "Packet Flow Sequence in PAN-OS": ingress zone from the ingress
// interface, egress zone from the route lookup.
func deriveZones(_ context.Context, s *state) (simulate.Outcome, error) {
	f := s.in.Flow
	z := &s.verdict.Zones
	if f.FromZone != "" {
		fb, _ := s.view.Candidates(index.FromZone, f.FromZone)
		tb, _ := s.view.Candidates(index.ToZone, f.ToZone)
		z.From, z.To, z.Source = []string{f.FromZone}, []string{f.ToZone}, "given"
		detail := fmt.Sprintf("from %s, to %s, as given", f.FromZone, f.ToZone)
		out := simulate.Outcome{Fidelity: simulate.Exact}
		s.known = s.defined(f.FromZone) && s.defined(f.ToZone)
		if s.known {
			s.cand.And(s.byRuleType(fb, tb, f.FromZone == f.ToZone))
		} else {
			kept := s.narrowZones(fb, tb)
			if !kept.IsEmpty() {
				out.Fidelity = simulate.OverMatchBecause(reason.New("zone.undefined",
					"a given zone is not defined in the vsys, so rule-type could not compare from and to for: "+names(s.rules, kept)))
			}
		}
		// A given zone wins; the engine only says when it derives another (§18 N10).
		if nz := s.postNATZones([]string{f.FromZone}); len(nz.zones) > 0 && !slices.Contains(nz.zones, f.ToZone) {
			detail += "; note: NAT would give " + nz.describe()
			z.Detail = "NAT would give " + nz.describe()
		}
		out.Detail, out.Candidates = detail, s.cand
		out.Debug = []string{"left: " + names(s.rules, s.cand)}
		return out, nil
	}
	z.Source = "configuration"
	if s.target.Providers.Zones != nil {
		z.Source = "forwarding table"
	}
	fromB, from, fromVia := s.zonesOf(index.FromZone, f.Source, true)
	toB, to, toVia := s.zonesOf(index.ToZone, f.Destination, false)
	var details []string
	out := simulate.Outcome{Fidelity: simulate.Inferred}
	// Security policy matches the post-NAT destination zone (spec §18 F5, N10).
	nz := s.postNATZones(from)
	switch {
	case nz.skipped != "":
		out.Debug = append(out.Debug, nz.skipped)
	case len(nz.zones) > 0:
		to, toB = nz.zones, roaring.New()
		for _, zn := range nz.zones {
			zb, _ := s.view.Candidates(index.ToZone, zn)
			toB.Or(zb)
		}
		toVia = append(toVia, nz.describe())
		details = append(details, nz.describe())
		z.Source += ", after NAT rule " + strings.Join(nz.rules, ", ")
	}
	if len(nz.doubts) > 0 {
		// One code for the summary; the NAT doubts keep their own codes.
		why := nz.doubts.Prefixed("the NAT rule is not certain: ").Joined()
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(reason.New("doubt.nat-rule", why.Text)))
	}
	z.From, z.To = from, to
	// Derived zones are never single and known, so whether from equals to is open:
	// an intrazone or interzone rule whose zones fit stays a candidate.
	kept := s.narrowZones(fromB, toB)
	if fromB != nil {
		details = append(details, "from "+strings.Join(from, ", "))
	}
	if toB != nil {
		details = append(details, "to "+strings.Join(to, ", "))
	}
	if !kept.IsEmpty() {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(reason.New("zone.derived",
			"the zones are derived, so rule-type could not compare from and to for: "+names(s.rules, kept))))
	}
	switch {
	case fromB == nil && toB == nil:
		// Nothing was derived, so nothing is inferred: zones were simply not
		// evaluated.
		out.Fidelity = simulate.NotEvaluated("zones")
		z.Source = "not evaluated"
		details = append(details, "no zone found for either side")
	case fromB == nil:
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.NotEvaluated("source zone"))
		details = append(details, "no source zone: the source is placed by no route but a default")
	case toB == nil:
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.NotEvaluated("destination zone"))
		details = append(details, "no destination zone found")
	}
	if len(from) > 1 || len(to) > 1 {
		details = append(details, "several candidate zones, all used")
	}
	z.Detail = strings.Join(append(fromVia, toVia...), "; ")
	out.Detail = strings.Join(details, "; ") + " (" + z.Source + ")"
	out.Candidates = s.cand
	out.Debug = append(append(fromVia, toVia...), "left: "+names(s.rules, s.cand))
	return out, nil
}

// byRuleType returns the rules whose zones and rule-type match a single, known
// from and to zone. Source: schemas/schema.xml, the rule-type help tips (11.2.0):
// universal "applies to both interzone and intrazone traffic"; intrazone "only
// applies to traffic within one of the specified zones", so the to zone is not
// read; interzone "does not apply to traffic within a zone, even if the same zone
// is in source and destination columns".
func (s *state) byRuleType(from, to *roaring.Bitmap, same bool) *roaring.Bitmap {
	out := roaring.New()
	for i, r := range s.rules {
		id := uint32(i)
		switch r.RuleType {
		case "intrazone":
			if same && from.Contains(id) {
				out.Add(id)
			}
		case "interzone":
			if !same && from.Contains(id) && to.Contains(id) {
				out.Add(id)
			}
		default:
			if from.Contains(id) && to.Contains(id) {
				out.Add(id)
			}
		}
	}
	return out
}

// narrowZones narrows by zone when zone equality is not known. Every rule must
// name the from zone. Universal and interzone rules must name the to zone too: an
// interzone match is a universal match between different zones. An intrazone rule
// does not read its to zone, so it stays when its from zone matches (byRuleType
// cites the source). Whether from equals to is open, so an intrazone or interzone
// rule left is a candidate the zones may not match (spec S12, over-match is the
// safe direction); narrowZones returns them. A nil bitmap does not narrow.
func (s *state) narrowZones(from, to *roaring.Bitmap) *roaring.Bitmap {
	if from != nil {
		s.cand.And(from)
	}
	intra, typed := roaring.New(), roaring.New()
	for i, r := range s.rules {
		switch r.RuleType {
		case "intrazone":
			intra.Add(uint32(i))
			typed.Add(uint32(i))
		case "interzone":
			typed.Add(uint32(i))
		}
	}
	if to != nil {
		intra.And(s.cand)
		s.cand.And(to)
		s.cand.Or(intra)
	}
	typed.And(s.cand)
	return typed
}

// defined reports whether the vsys defines a zone of this name.
func (s *state) defined(zone string) bool {
	for _, z := range resolve.ZonesInScope(s.target.Config, s.idx.Scope()) {
		if z.Name == zone {
			return true
		}
	}
	return false
}

// zonesOf returns the rules whose zone field could match the endpoint's addresses,
// the zones, and where each came from. A nil bitmap means no zone was found, and
// the side must not narrow.
//
// For the source, a placement through a default route is ignored. A default route
// is where a reply would leave, and says nothing about the interface a packet
// arrives on; narrowing on it picked the wrong source zone for five of seven flows
// on a lab firewall, as confidently as a right one. Not narrowing over-matches,
// which is the safe direction (spec S12).
func (s *state) zonesOf(f index.Field, ep simulate.Endpoint, skipDefault bool) (*roaring.Bitmap, []string, []string) {
	seen := map[string]bool{}
	var zones, via []string
	for _, a := range ep.Addrs {
		_, rep := s.view.Candidates(f, a.String())
		for _, h := range rep.Hits {
			if h.Kind != "zone" {
				continue
			}
			if skipDefault && viaDefault(h.Via) {
				via = append(via, fmt.Sprintf("%s: %s via %s ignored: a default route does not say where a packet arrives", a, h.Name, h.Via))
				continue
			}
			via = append(via, fmt.Sprintf("%s: %s via %s", a, h.Name, h.Via))
			if !seen[h.Name] {
				seen[h.Name] = true
				zones = append(zones, h.Name)
			}
		}
	}
	if len(zones) == 0 {
		return nil, nil, via
	}
	slices.Sort(zones)
	b := roaring.New()
	for _, z := range zones {
		zb, _ := s.view.Candidates(f, z)
		b.Or(zb)
	}
	return b, zones, via
}

// viaDefault reports whether a zone placement came through a default route: the
// placement's last field is the route or prefix that decided it.
func viaDefault(via string) bool {
	fs := strings.Fields(via)
	if len(fs) == 0 {
		return false
	}
	p, err := netip.ParsePrefix(fs[len(fs)-1])
	return err == nil && p.Bits() == 0
}

// matchService narrows by port. Rules naming application-default, or a service the
// configuration does not define such as service-https, cannot be evaluated from a
// configuration; they stay, and the stage says so.
func matchService(_ context.Context, s *state) (simulate.Outcome, error) {
	f := s.in.Flow
	proto := strings.ToLower(f.Protocol)
	if f.DestPort == 0 || (proto != "tcp" && proto != "udp" && proto != "sctp") {
		return simulate.Outcome{Fidelity: simulate.NotEvaluated("service"), Detail: "no port given"}, nil
	}
	term := fmt.Sprintf("%s/%d", proto, f.DestPort)
	b, rep := s.view.Candidates(index.Service, term)
	kept := s.unevaluable("service", "application-default")
	b.Or(kept)
	s.cand.And(b)
	out := simulate.Outcome{Fidelity: simulate.Exact, Detail: term, Candidates: s.cand}
	out.Unresolved = s.withoutGap(&out.Fidelity, rep.Unresolved)
	if still := roaring.And(kept, s.cand); !still.IsEmpty() {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(reason.New("doubt.service-kept",
			"kept rules whose service is application-default, predefined or absent: "+names(s.rules, still))))
	}
	for _, u := range out.Unresolved {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(u.Why()))
	}
	out.Debug = []string{"left: " + names(s.rules, s.cand)}
	return out, nil
}

// matchURL narrows by URL category. A rule naming a category the configuration does
// not define, a PAN-DB category, stays: its membership is in the content database.
func matchURL(_ context.Context, s *state) (simulate.Outcome, error) {
	url := s.in.Flow.URL
	if url == "" {
		if s.anyNames("category") {
			return simulate.Outcome{Fidelity: simulate.NotEvaluated("url category"), Detail: "no URL given"}, nil
		}
		return simulate.Outcome{Fidelity: simulate.Exact, Detail: "no candidate names a URL category"}, nil
	}
	b, rep := s.view.Candidates(index.Category, url)
	kept := s.unevaluable("category")
	b.Or(kept)
	// A rule without a category matches every URL, as "any" does.
	b.Or(s.withoutField("category"))
	s.cand.And(b)
	out := simulate.Outcome{Fidelity: simulate.Exact, Detail: url, Candidates: s.cand}
	out.Unresolved = s.withoutGap(&out.Fidelity, rep.Unresolved)
	for _, h := range rep.Hits {
		out.Debug = append(out.Debug, fmt.Sprintf("%s (%s) via %s", h.Name, h.Kind, h.Via))
	}
	if still := roaring.And(kept, s.cand); !still.IsEmpty() {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(reason.New("doubt.category-undefined",
			"kept rules naming a category the configuration does not define, such as a PAN-DB category: "+names(s.rules, still))))
	}
	for _, u := range out.Unresolved {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(u.Why()))
	}
	out.Debug = append(out.Debug, "left: "+names(s.rules, s.cand))
	return out, nil
}

// withoutField returns the rules that name nothing in a field.
func (s *state) withoutField(field string) *roaring.Bitmap {
	out := roaring.New()
	for i, r := range s.rules {
		if len(r.Fields[field]) == 0 {
			out.Add(uint32(i))
		}
	}
	return out
}

// unevaluable returns the rules whose field names a value the configuration does
// not define, one of the given keywords, or nothing at all: a rule a configuration
// exports without the field cannot be judged on it, so it is kept, not dropped.
func (s *state) unevaluable(field string, keywords ...string) *roaring.Bitmap {
	defined := definedIn(s.target.Config, s.idx.Scope(), field)
	out := roaring.New()
	for i, r := range s.rules {
		if len(r.Fields[field]) == 0 && field != "category" {
			out.Add(uint32(i))
			continue
		}
		for _, v := range r.Fields[field] {
			if v == "any" {
				continue
			}
			if slices.Contains(keywords, v) || !defined[v] {
				out.Add(uint32(i))
				break
			}
		}
	}
	return out
}

// anyNames reports whether a current candidate names something in a field other
// than any.
func (s *state) anyNames(field string) bool {
	for it := s.cand.Iterator(); it.HasNext(); {
		for _, v := range s.rules[it.Next()].Fields[field] {
			if v != "any" {
				return true
			}
		}
	}
	return false
}

func dropDisabled(_ context.Context, s *state) (simulate.Outcome, error) {
	disabled := roaring.And(s.cand, s.idx.Disabled())
	s.cand.AndNot(disabled)
	return simulate.Outcome{
		Fidelity: simulate.Exact, Detail: fmt.Sprintf("%d disabled", disabled.GetCardinality()),
		Candidates: s.cand, Debug: []string{"dropped: " + names(s.rules, disabled)},
	}, nil
}

// order lists the candidates in evaluation order: a rule's bit is its position.
func order(_ context.Context, s *state) (simulate.Outcome, error) {
	s.verdict.Candidates = nil
	for it := s.cand.Iterator(); it.HasNext(); {
		s.verdict.Candidates = append(s.verdict.Candidates, s.rules[it.Next()])
	}
	s.verdict.Doubts = s.doubts()
	return simulate.Outcome{Fidelity: simulate.Exact, Detail: fmt.Sprintf("%d in order", len(s.verdict.Candidates))}, nil
}

// firstMatch decides the flow (spec §4.7, E20). The first candidate without a
// doubt decides; with none, a default rule does. Earlier candidates in doubt leave
// it undecided, unless they all carry the deciding action: whichever of them the
// device takes, the flow meets that action, and the answer is an overmatch.
//
// The default rules are the tail of the evaluation order, so they belong to this
// stage rather than to one of their own: a separate stage would only ever narrow
// nothing.
func firstMatch(_ context.Context, s *state) (simulate.Outcome, error) {
	cands := s.verdict.Candidates
	doubted := map[int]Doubt{} // the first doubt of each candidate, by position
	for _, d := range s.verdict.Doubts {
		if _, ok := doubted[d.Position]; !ok {
			doubted[d.Position] = d
		}
	}
	at := slices.IndexFunc(cands, func(r resolve.Rule) bool { _, ok := doubted[r.Position]; return !ok })
	upto, before := cands, cands
	if at >= 0 {
		upto, before = cands[:at+1], cands[:at]
	}
	out := simulate.Outcome{Fidelity: simulate.Exact}
	if skipped := notEvaluated(upto); len(skipped) > 0 {
		out.Fidelity = simulate.NotEvaluated(skipped...)
	}
	var action string
	switch {
	case at >= 0:
		r := cands[at]
		s.verdict.Rule = &r
		action = r.Action
		out.Detail = fmt.Sprintf("%s (%s), position %d", r.Name, r.Action, r.Position)
	default:
		lead := "no enabled rule matches"
		if len(cands) > 0 {
			lead = "every candidate is in doubt"
		}
		d, err := s.defaultRule()
		if err.Text != "" {
			out.Detail = lead + "; " + err.Text
			s.verdict.Undecided = simulate.Reasons{err}
			out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(err))
			return out, nil
		}
		s.verdict.Default, s.verdict.DefaultAction, s.verdict.DefaultSource = d.Name, d.Action, d.Source
		action = d.Action
		out.Detail = fmt.Sprintf("%s; default rule %s (%s), %s", lead, d.Name, d.Action, d.Source)
	}
	for _, r := range before {
		if r.Action != action {
			// The undecided reason is the doubt's, named with its rule: each of
			// the doubt's parts keeps its code.
			d := doubted[r.Position]
			why := d.Reasons.Prefixed(fmt.Sprintf("%s (%s) at position %d may match first: ", r.Name, r.Action, r.Position))
			s.verdict.Undecided = why
			out.Detail += "; undecided: " + why.Text()
			out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(why...))
			return out, nil
		}
	}
	if len(before) > 0 {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(reason.New("doubt.same-action",
			"earlier candidates in doubt share the action "+action+": "+listNames(before))))
	}
	return out, nil
}

// notEvaluated names the matching dimensions no stage evaluates that a candidate
// at or before the decision sets: only those can change which rule decides.
func notEvaluated(upto []resolve.Rule) []string {
	var out []string
	for _, c := range []struct{ field, dim string }{{"application", "application"}, {"source-user", "user"}} {
		for _, r := range upto {
			if len(notAny(r.Fields[c.field])) > 0 {
				out = append(out, c.dim)
				break
			}
		}
	}
	return out
}

// listNames lists rules by name.
func listNames(rs []resolve.Rule) string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Name
	}
	return strings.Join(out, ", ")
}

// builtInDefaults are the actions of the default security rules when the
// configuration does not override them. Source: PAN-OS admin guide, "Security
// Policy Rule Types" and "Default Security Policy Rules": intrazone-default allows,
// interzone-default denies. Hand-modelled (R8): the schema declares allow for both.
var builtInDefaults = map[string]string{"intrazone-default": "allow", "interzone-default": "deny"}

// validActions are the security rule actions a default rule may carry. allow lets
// the flow pass; the others stop it (spec §4.6).
var validActions = []string{"allow", "deny", "drop", "reset-client", "reset-server", "reset-both"}

// defaultRule picks the default rule that decides a flow no other rule matches,
// and its action. The empty reason means it decided; otherwise the reason says why
// the answer is incomplete.
//
// PAN-OS evaluates the default rules after every other rule; intrazone-default
// takes traffic within one zone and interzone-default traffic between zones.
// Source: PAN-OS admin guide, "Default Security Policy Rules".
func (s *state) defaultRule() (resolve.DefaultRule, reason.Reason) {
	if !s.known {
		return resolve.DefaultRule{}, reason.New("default.zones-unknown", "the default rule depends on the zones")
	}
	name := "interzone-default"
	if s.in.Flow.FromZone == s.in.Flow.ToZone {
		name = "intrazone-default"
	}
	d := resolve.DefaultRule{Name: name, Action: builtInDefaults[name], Source: "built-in"}
	var stored []resolve.DefaultRule
	found := false
	for _, tg := range resolve.Targets(s.target.Config) {
		if tg.Scope() != s.idx.Scope() {
			continue
		}
		found = true
		for _, e := range tg.DefaultRules() {
			if e.Name == name {
				// An entry without an action keeps the built-in one (spec §4.6).
				if e.Action == "" {
					e.Action = d.Action
				}
				stored = append(stored, e)
			}
		}
	}
	if !found {
		// Without the vsys its overrides are unknown; the built-in action would be
		// a guess.
		return resolve.DefaultRule{}, reason.New("default.vsys-missing",
			fmt.Sprintf("the configuration has no %s, so its default rules are not known", s.idx.Scope()))
	}
	// Precedence between a local and a pushed override is not verified on a
	// device (spec E24): one source decides alone; two must agree, and then the
	// answer names the first, local.
	for i, e := range stored {
		switch {
		case i == 0:
			d = e
		case e.Action != d.Action:
			return resolve.DefaultRule{}, reason.New("default.precedence-unverified", "local and pushed default rules disagree; precedence not verified")
		}
	}
	if !slices.Contains(validActions, d.Action) {
		return resolve.DefaultRule{}, reason.New("default.invalid-action",
			fmt.Sprintf("%s has the action %q, which is not a security rule action", name, d.Action))
	}
	return d, reason.Reason{}
}

// withoutGap drops the version gap from a lookup's unresolved entries and lowers
// the fidelity to inferred instead (spec E25): the configuration was read with
// the nearest older schema, so an answer may miss what the newer version added,
// as routing's version gap does. The gap stays in the run's notes. Every lookup
// reports it, with no kind; any other entry stays unresolved.
func (s *state) withoutGap(f *simulate.Fidelity, us []index.Unresolved) []index.Unresolved {
	var out []index.Unresolved
	for _, u := range us {
		if u.Code == "gap.version" {
			*f = simulate.Weakest(*f, simulate.Inferred)
			continue
		}
		out = append(out, u)
	}
	return out
}

// names lists the rules in a set, for the log.
func names(rules []resolve.Rule, b *roaring.Bitmap) string {
	if b.IsEmpty() {
		return "none"
	}
	var out []string
	for it := b.Iterator(); it.HasNext(); {
		out = append(out, rules[it.Next()].Name)
	}
	return strings.Join(out, ", ")
}

func dedupe(in []index.Unresolved) []index.Unresolved {
	seen := map[index.Unresolved]bool{}
	var out []index.Unresolved
	for _, u := range in {
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}
