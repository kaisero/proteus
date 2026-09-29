package securitypolicy

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/resolve"
	"github.com/okaiser/panos-analyst/simulate"
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
	b := roaring.New()
	var out simulate.Outcome
	var hits []string
	if ep.Name != "" {
		nb, rep := s.view.Candidates(f, ep.Name)
		b.Or(nb)
		for _, h := range rep.Hits {
			hits = append(hits, fmt.Sprintf("%s (%s) via %s", h.Name, h.Kind, h.Via))
		}
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
		for _, h := range rep.Hits {
			hits = append(hits, fmt.Sprintf("%s (%s) via %s", h.Name, h.Kind, h.Via))
		}
		out.Unresolved = append(out.Unresolved, rep.Unresolved...)
	}
	// A negated rule matches every address except those it lists.
	neg := roaring.New()
	for i, r := range s.rules {
		if negated(r) {
			neg.Add(uint32(i))
		}
	}
	if !neg.IsEmpty() {
		inverted := roaring.AndNot(neg, b)
		b.AndNot(neg)
		b.Or(inverted)
	}

	switch {
	case ep.Name != "" && len(ep.Addrs) == 0:
		out.Fidelity = simulate.UnderMatch(fmt.Sprintf("%s resolved to no address, so only FQDN objects of that name were matched", ep.Name))
	case ep.Resolved:
		out.Fidelity = simulate.Inferred
	default:
		out.Fidelity = simulate.Exact
	}
	for _, u := range dedupe(out.Unresolved) {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(u.Reason))
	}
	out.Unresolved = dedupe(out.Unresolved)
	out.Detail = fmt.Sprintf("%s: %d hits, %d negated rules", ep, len(hits), neg.GetCardinality())
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
		s.cand.And(fb)
		s.cand.And(tb)
		z.From, z.To, z.Source = []string{f.FromZone}, []string{f.ToZone}, "given"
		return simulate.Outcome{
			Fidelity: simulate.Exact, Detail: fmt.Sprintf("from %s, to %s, as given", f.FromZone, f.ToZone),
			Candidates: s.cand, Debug: []string{"left: " + names(s.rules, s.cand)},
		}, nil
	}
	z.Source = "configuration"
	if s.target.Providers.Zones != nil {
		z.Source = "forwarding table"
	}
	fromB, from, fromVia := s.zonesOf(index.FromZone, f.Source)
	toB, to, toVia := s.zonesOf(index.ToZone, f.Destination)
	z.From, z.To = from, to
	var details []string
	out := simulate.Outcome{Fidelity: simulate.Inferred}
	if fromB != nil {
		s.cand.And(fromB)
		details = append(details, "from "+strings.Join(from, ", "))
	}
	if toB != nil {
		s.cand.And(toB)
		details = append(details, "to "+strings.Join(to, ", "))
	}
	switch {
	case fromB == nil && toB == nil:
		// Nothing was derived, so nothing is inferred: zones were simply not
		// evaluated.
		out.Fidelity = simulate.NotEvaluated("zones")
		z.Source = "not evaluated"
		details = append(details, "no zone found for either side")
	case fromB == nil || toB == nil:
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.NotEvaluated("zones"))
		details = append(details, "a side with no zone was not narrowed")
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

// zonesOf returns the rules whose zone field could match the endpoint's addresses,
// the zones, and where each came from. A nil bitmap means no zone was found, and
// the side must not narrow.
func (s *state) zonesOf(f index.Field, ep simulate.Endpoint) (*roaring.Bitmap, []string, []string) {
	b := roaring.New()
	seen := map[string]bool{}
	var zones, via []string
	for _, a := range ep.Addrs {
		ab, rep := s.view.Candidates(f, a.String())
		found := false
		for _, h := range rep.Hits {
			if h.Kind != "zone" {
				continue
			}
			found = true
			via = append(via, fmt.Sprintf("%s: %s via %s", a, h.Name, h.Via))
			if !seen[h.Name] {
				seen[h.Name] = true
				zones = append(zones, h.Name)
			}
		}
		if found {
			b.Or(ab)
		}
	}
	if len(zones) == 0 {
		return nil, nil, via
	}
	sort.Strings(zones)
	return b, zones, via
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
	out := simulate.Outcome{Fidelity: simulate.Exact, Detail: term, Candidates: s.cand, Unresolved: rep.Unresolved}
	if still := roaring.And(kept, s.cand); !still.IsEmpty() {
		out.Fidelity = simulate.OverMatchBecause("kept rules whose service is application-default or predefined: " + names(s.rules, still))
	}
	for _, u := range rep.Unresolved {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(u.Reason))
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
	s.cand.And(b)
	out := simulate.Outcome{Fidelity: simulate.Exact, Detail: url, Candidates: s.cand, Unresolved: rep.Unresolved}
	for _, h := range rep.Hits {
		out.Debug = append(out.Debug, fmt.Sprintf("%s (%s) via %s", h.Name, h.Kind, h.Via))
	}
	if still := roaring.And(kept, s.cand); !still.IsEmpty() {
		out.Fidelity = simulate.OverMatchBecause("kept rules naming a category the configuration does not define, such as a PAN-DB category: " + names(s.rules, still))
	}
	for _, u := range rep.Unresolved {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(u.Reason))
	}
	out.Debug = append(out.Debug, "left: "+names(s.rules, s.cand))
	return out, nil
}

// unevaluable returns the rules whose field names a value the configuration does
// not define, or one of the given keywords.
func (s *state) unevaluable(field string, keywords ...string) *roaring.Bitmap {
	defined := definedIn(s.target.Config, s.target.Index.Scope(), field)
	out := roaring.New()
	for i, r := range s.rules {
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
	disabled := roaring.And(s.cand, s.target.Index.Disabled())
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
	return simulate.Outcome{Fidelity: simulate.Exact, Detail: fmt.Sprintf("%d in order", len(s.verdict.Candidates))}, nil
}

// firstMatch takes the lowest position. Application is never evaluated, so the
// device may still decline this rule and take a later one.
func firstMatch(_ context.Context, s *state) (simulate.Outcome, error) {
	skipped := []string{"application"}
	if s.in.Flow.User != "" {
		skipped = append(skipped, "user")
	}
	out := simulate.Outcome{Fidelity: simulate.NotEvaluated(skipped...)}
	if len(s.verdict.Candidates) == 0 {
		out.Detail = "no enabled rule matches"
		return out, nil
	}
	r := s.verdict.Candidates[0]
	s.verdict.Rule = &r
	out.Detail = fmt.Sprintf("%s (%s), position %d", r.Name, r.Action, r.Position)
	return out, nil
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
