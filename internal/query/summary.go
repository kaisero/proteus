package query

import (
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// The summary forms (spec 2026-10-09 §3.5). A summary keeps the verdict, the
// answer, the deciding point, the fidelity, the reasons and the needs, and of a
// path each hop's device, vsys, snapshot, zones, route and policy verdict. It
// drops candidates, stage tables and a hop's interfaces and lookups. The
// envelope's holes, unresolved entries and notes stay as they are. Empty lists
// print [] as in the full form (U5).

// Detail names the two forms of an envelope.
const (
	DetailFull    = "full"
	DetailSummary = "summary"
)

// PathSummary is a path answer in summary.
type PathSummary struct {
	Answer      string            `json:"answer"`
	Needs       []Need            `json:"needs,omitzero"`
	Mode        string            `json:"mode"`
	Verdict     string            `json:"verdict"`
	At          *Point            `json:"at"`
	Fidelity    simulate.Fidelity `json:"fidelity"`
	Source      simulate.Endpoint `json:"source"`
	Destination simulate.Endpoint `json:"destination"`
	Outcome     routing.Outcome   `json:"outcome"`
	End         string            `json:"end"`
	EndCode     reason.Code       `json:"end_code"`
	Hidden      []string          `json:"hidden,omitempty"`
	Hops        []HopSummary      `json:"hops"`
}

// HopSummary is one hop in summary: where, which zones, which route, and on a
// path the doubts and each check's verdict.
type HopSummary struct {
	Index    int              `json:"index,omitempty"`
	Device   string           `json:"device"`
	Vsys     string           `json:"vsys"`
	Snapshot string           `json:"snapshot,omitempty"`
	FromZone string           `json:"from_zone"`
	ToZone   string           `json:"to_zone"`
	Route    string           `json:"route"`
	Doubts   simulate.Reasons `json:"doubts,omitempty"`
	Checks   []CheckSummary   `json:"checks,omitempty"`
}

// CheckSummary is one check of a hop: its verdict, the deciding rule and why.
type CheckSummary struct {
	Name    string           `json:"name"`
	Verdict string           `json:"verdict"`
	Rule    string           `json:"rule"`
	Reasons simulate.Reasons `json:"reasons"`
}

// hopSummary is a routing hop's place, zones and route.
func hopSummary(h routing.Hop) HopSummary {
	return HopSummary{
		Device: h.Device, Vsys: h.Vsys, Snapshot: h.SnapshotID, FromZone: h.Flow.FromZone, ToZone: h.Flow.ToZone,
		Route: routeOf(h),
	}
}

// routeOf is a hop's first route: its destination and next hop, or its
// interface when it has no next hop; "" when no route matched.
func routeOf(h routing.Hop) string {
	if len(h.Lookups) == 0 || len(h.Lookups[0].Match.NextHops) == 0 {
		return ""
	}
	m := h.Lookups[0].Match
	via := m.First().NextHop
	if via == "" || via == "0.0.0.0" {
		via = m.First().Interface
	}
	return m.Destination.String() + " via " + via
}

// Summary is the path answer in summary.
func (r PathResult) Summary() PathSummary {
	out := PathSummary{
		Answer: r.Answer, Needs: r.Needs, Mode: r.Mode, Verdict: r.Verdict, At: r.At, Fidelity: r.Fidelity,
		Source: r.Source, Destination: r.Destination, Outcome: r.Outcome, End: r.End, EndCode: r.EndCode,
		Hidden: r.Hidden, Hops: []HopSummary{},
	}
	for _, h := range r.Hops {
		s := hopSummary(h.Hop)
		s.Index, s.Doubts, s.Checks = h.Index, h.Doubts, []CheckSummary{}
		for _, c := range h.Checks {
			s.Checks = append(s.Checks, CheckSummary{Name: c.Name, Verdict: c.Security.Verdict, Rule: c.Security.Rule, Reasons: c.Security.Reasons})
		}
		out.Hops = append(out.Hops, s)
	}
	return out
}

// SecuritySummary is simulate policy on a file in summary.
type SecuritySummary struct {
	Answer        string                        `json:"answer"`
	Needs         []Need                        `json:"needs,omitzero"`
	Verdict       string                        `json:"verdict"`
	Reasons       simulate.Reasons              `json:"reasons"`
	Rule          string                        `json:"rule"`
	DefaultAction string                        `json:"default_action"`
	Fidelity      simulate.Fidelity             `json:"fidelity"`
	Doubts        []securitypolicy.Doubt        `json:"doubts"`
	Zones         securitypolicy.ZoneDerivation `json:"zones"`
	Relevance     securitypolicy.Relevance      `json:"relevance"`
	Target        Target                        `json:"target"`
}

// Summary is the file answer in summary.
func (r SecurityResult) Summary() SecuritySummary {
	return SecuritySummary{
		Answer: r.Answer, Needs: r.Needs, Verdict: r.Verdict, Reasons: r.Reasons, Rule: r.Rule,
		DefaultAction: r.DefaultAction, Fidelity: r.Fidelity, Doubts: r.Doubts, Zones: r.Zones,
		Relevance: r.Relevance, Target: r.Target,
	}
}

// RoutingSummary is simulate routing in summary.
type RoutingSummary struct {
	Answer      string            `json:"answer"`
	Needs       []Need            `json:"needs,omitzero"`
	Fidelity    simulate.Fidelity `json:"fidelity"`
	Source      simulate.Endpoint `json:"source"`
	Destination simulate.Endpoint `json:"destination"`
	Outcome     routing.Outcome   `json:"outcome"`
	End         string            `json:"end"`
	EndCode     reason.Code       `json:"end_code"`
	Hidden      []string          `json:"hidden,omitempty"`
	Hops        []HopSummary      `json:"hops"`
}

// Summary is the routing answer in summary.
func (r RoutingResult) Summary() RoutingSummary {
	out := RoutingSummary{
		Answer: r.Answer, Needs: r.Needs, Fidelity: r.Fidelity, Source: r.Source, Destination: r.Destination,
		Outcome: r.Outcome, End: r.End, EndCode: r.EndCode, Hidden: r.Hidden, Hops: []HopSummary{},
	}
	for _, h := range r.Hops {
		out.Hops = append(out.Hops, hopSummary(h))
	}
	return out
}

// NATSummary is simulate nat in summary: the rule, the translations and the
// packet after them.
type NATSummary struct {
	Answer      string            `json:"answer"`
	Needs       []Need            `json:"needs,omitzero"`
	Rule        string            `json:"rule"`
	Dropped     string            `json:"dropped,omitempty"`
	Fidelity    simulate.Fidelity `json:"fidelity"`
	Doubts      []nat.Doubt       `json:"doubts"`
	Source      *nat.Translation  `json:"source,omitempty"`
	Destination *nat.Translation  `json:"destination,omitempty"`
	Flow        simulate.Flow     `json:"flow"`
}

// Summary is the NAT answer in summary.
func (r NATResult) Summary() NATSummary {
	out := NATSummary{
		Answer: r.Answer, Needs: r.Needs, Dropped: r.Dropped, Fidelity: r.Fidelity, Doubts: r.Doubts,
		Source: r.Source, Destination: r.Destination, Flow: r.Flow,
	}
	if r.Rule != nil {
		out.Rule = r.Rule.Name
	}
	if out.Doubts == nil {
		out.Doubts = []nat.Doubt{}
	}
	return out
}

// FindingSummary is one search finding in summary: where, what, and the field
// that names it.
type FindingSummary struct {
	Answer string `json:"answer"`
	Target
	Stage string `json:"stage"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Field string `json:"field,omitempty"`
	Scope string `json:"scope"`
}

// Summary is the finding in summary.
func (f Finding) Summary() FindingSummary {
	return FindingSummary{
		Answer: f.Answer, Target: f.Target, Stage: string(f.Stage), Kind: f.Kind, Name: f.Name, Field: f.Field, Scope: f.Scope,
	}
}

// LookupSummary is one card found, without the card.
type LookupSummary struct {
	Answer string `json:"answer"`
	Target
	Scope string `json:"scope"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
}

// Summary is the lookup result in summary.
func (r LookupResult) Summary() LookupSummary {
	return LookupSummary{Answer: r.Answer, Target: r.Target, Scope: r.Scope, Kind: r.Card.Kind, Name: r.Card.Name}
}

// DiffSummary is one scope's changes, counted.
type DiffSummary struct {
	Answer  string `json:"answer"`
	Device  string `json:"device"`
	From    string `json:"from"`
	To      string `json:"to"`
	Scope   string `json:"scope"`
	Added   int    `json:"added"`
	Removed int    `json:"removed"`
	Changed int    `json:"changed"`
}

// Summary is the scope's diff in summary.
func (r DiffResult) Summary() DiffSummary {
	out := DiffSummary{Answer: r.Answer, Device: r.Device, From: r.From, To: r.To, Scope: r.Scope}
	out.Added, out.Removed, out.Changed = countChanges(r.Changes)
	return out
}
