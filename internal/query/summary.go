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
	Answer      string            `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Needs       []Need            `json:"needs,omitzero" jsonschema:"present when the result is held back: the inputs a second call can give to change it; empty when none helps"`
	Mode        string            `json:"mode" jsonschema:"path: the flow is checked on every firewall it crosses"`
	Verdict     string            `json:"verdict" jsonschema:"allowed, denied, undecided or another path verdict; undecided means the answer cannot say"`
	At          *Point            `json:"at" jsonschema:"where the verdict was decided or became undecided; null when no check decided"`
	Fidelity    simulate.Fidelity `json:"fidelity" jsonschema:"how certain the result is: exact, overmatch, inferred or undermatch, with the reasons; never report undermatch or inferred as a firm answer"`
	Source      simulate.Endpoint `json:"source" jsonschema:"the source endpoint as simulated"`
	Destination simulate.Endpoint `json:"destination" jsonschema:"the destination endpoint as simulated"`
	Outcome     routing.Outcome   `json:"outcome" jsonschema:"how the path ended"`
	End         string            `json:"end" jsonschema:"where and why the path ended, in words"`
	EndCode     reason.Code       `json:"end_code" jsonschema:"the reason code of the path end"`
	Hidden      []string          `json:"hidden,omitempty" jsonschema:"firewalls the path crossed that the inventory does not hold"`
	Hops        []PathHopSummary  `json:"hops" jsonschema:"the firewalls the path crossed, in order"`
}

// HopSummary is one routing hop in summary: where, which zones, which route.
type HopSummary struct {
	Device   string `json:"device" jsonschema:"the device name"`
	Vsys     string `json:"vsys" jsonschema:"the vsys name"`
	Snapshot string `json:"snapshot,omitempty" jsonschema:"the snapshot ID"`
	FromZone string `json:"from_zone" jsonschema:"the ingress zone"`
	ToZone   string `json:"to_zone" jsonschema:"the egress zone"`
	Route    string `json:"route" jsonschema:"the route taken: prefix via next hop or interface; empty when none matched"`
}

// PathHopSummary is one hop of a path in summary: the routing hop, its doubts
// and each check's verdict. Empty lists print [] as in the full hop (U5).
type PathHopSummary struct {
	Index int `json:"index" jsonschema:"the hop's place on the path"`
	HopSummary
	Doubts simulate.Reasons `json:"doubts" jsonschema:"doubts on the hop, each with its code"`
	Checks []CheckSummary   `json:"checks" jsonschema:"each check's verdict"`
}

// CheckSummary is one check of a hop: its verdict, the deciding rule and why.
type CheckSummary struct {
	Name    string           `json:"name" jsonschema:"the check: security"`
	Verdict string           `json:"verdict" jsonschema:"pass, stop, undecided or not-evaluated"`
	Rule    string           `json:"rule" jsonschema:"the deciding rule"`
	Reasons simulate.Reasons `json:"reasons" jsonschema:"why, each reason with its code"`
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
		Hidden: r.Hidden, Hops: []PathHopSummary{},
	}
	for _, h := range r.Hops {
		s := PathHopSummary{Index: h.Index, HopSummary: hopSummary(h.Hop), Doubts: nonNilReasons(h.Doubts), Checks: []CheckSummary{}}
		for _, c := range h.Checks {
			s.Checks = append(s.Checks, CheckSummary{Name: c.Name, Verdict: c.Security.Verdict, Rule: c.Security.Rule, Reasons: nonNilReasons(c.Security.Reasons)})
		}
		out.Hops = append(out.Hops, s)
	}
	return out
}

// SecuritySummary is simulate policy on a file in summary.
type SecuritySummary struct {
	Answer        string                        `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Needs         []Need                        `json:"needs,omitzero" jsonschema:"present when the result is held back: the inputs a second call can give to change it; empty when none helps"`
	Verdict       string                        `json:"verdict" jsonschema:"pass, stop or undecided; undecided means the answer cannot say"`
	Reasons       simulate.Reasons              `json:"reasons" jsonschema:"why, each reason with its code"`
	Rule          string                        `json:"rule" jsonschema:"the rule that decides; empty when none does"`
	DefaultAction string                        `json:"default_action" jsonschema:"the default rule's action"`
	Fidelity      simulate.Fidelity             `json:"fidelity" jsonschema:"how certain the result is: exact, overmatch, inferred or undermatch, with the reasons; never report undermatch or inferred as a firm answer"`
	Doubts        []securitypolicy.Doubt        `json:"doubts" jsonschema:"rules that may match first, with the reasons the answer cannot rule them out"`
	Zones         securitypolicy.ZoneDerivation `json:"zones" jsonschema:"the zones used and where they came from"`
	Relevance     securitypolicy.Relevance      `json:"relevance" jsonschema:"whether the device routes either endpoint by more than a default route"`
	Target        Target                        `json:"target" jsonschema:"the device, vsys and snapshot the result came from"`
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
	Answer      string            `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Needs       []Need            `json:"needs,omitzero" jsonschema:"present when the result is held back: the inputs a second call can give to change it; empty when none helps"`
	Fidelity    simulate.Fidelity `json:"fidelity" jsonschema:"how certain the result is: exact, overmatch, inferred or undermatch, with the reasons; never report undermatch or inferred as a firm answer"`
	Source      simulate.Endpoint `json:"source" jsonschema:"the source endpoint as simulated"`
	Destination simulate.Endpoint `json:"destination" jsonschema:"the destination endpoint as simulated"`
	Outcome     routing.Outcome   `json:"outcome" jsonschema:"how the path ended"`
	End         string            `json:"end" jsonschema:"where and why the path ended, in words"`
	EndCode     reason.Code       `json:"end_code" jsonschema:"the reason code of the path end"`
	Hidden      []string          `json:"hidden,omitempty" jsonschema:"firewalls the path crossed that the inventory does not hold"`
	Hops        []HopSummary      `json:"hops" jsonschema:"the firewalls the path crossed, in order"`
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
	Answer      string            `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Needs       []Need            `json:"needs,omitzero" jsonschema:"present when the result is held back: the inputs a second call can give to change it; empty when none helps"`
	Rule        string            `json:"rule" jsonschema:"the NAT rule that matches; empty when none does"`
	Dropped     string            `json:"dropped,omitempty" jsonschema:"why the packet is dropped, if it is"`
	Fidelity    simulate.Fidelity `json:"fidelity" jsonschema:"how certain the result is: exact, overmatch, inferred or undermatch, with the reasons; never report undermatch or inferred as a firm answer"`
	Doubts      []nat.Doubt       `json:"doubts" jsonschema:"NAT rules that may match instead, with the reasons"`
	Source      *nat.Translation  `json:"source,omitempty" jsonschema:"the source translation; absent when none"`
	Destination *nat.Translation  `json:"destination,omitempty" jsonschema:"the destination translation; absent when none"`
	Flow        simulate.Flow     `json:"flow" jsonschema:"the packet after translation"`
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
	Answer string `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Target
	Stage string `json:"stage" jsonschema:"how the value was found: object, group, reference or literal"`
	Kind  string `json:"kind" jsonschema:"the kind of the element found"`
	Name  string `json:"name" jsonschema:"the element found"`
	Field string `json:"field,omitempty" jsonschema:"the rule field it was found in"`
	Scope string `json:"scope" jsonschema:"the configuration scope the result came from"`
}

// Summary is the finding in summary.
func (f Finding) Summary() FindingSummary {
	return FindingSummary{
		Answer: f.Answer, Target: f.Target, Stage: string(f.Stage), Kind: f.Kind, Name: f.Name, Field: f.Field, Scope: f.Scope,
	}
}

// LookupSummary is one card found, without the card.
type LookupSummary struct {
	Answer string `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Target
	Scope string `json:"scope" jsonschema:"the configuration scope the result came from"`
	Kind  string `json:"kind" jsonschema:"the kind of the element"`
	Name  string `json:"name" jsonschema:"the element name"`
}

// Summary is the lookup result in summary.
func (r LookupResult) Summary() LookupSummary {
	return LookupSummary{Answer: r.Answer, Target: r.Target, Scope: r.Scope, Kind: r.Card.Kind, Name: r.Card.Name}
}

// DiffSummary is one scope's changes, counted.
type DiffSummary struct {
	Answer  string `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Device  string `json:"device" jsonschema:"the device name"`
	From    string `json:"from" jsonschema:"the older snapshot ID"`
	To      string `json:"to" jsonschema:"the newer snapshot ID"`
	Scope   string `json:"scope" jsonschema:"the configuration scope the result came from"`
	Added   int    `json:"added" jsonschema:"elements added"`
	Removed int    `json:"removed" jsonschema:"elements removed"`
	Changed int    `json:"changed" jsonschema:"elements changed"`
}

// Summary is the scope's diff in summary. It counts every change of the
// scope, those a limit left out included, as the answer does.
func (r DiffResult) Summary() DiffSummary {
	out := DiffSummary{Answer: r.Answer, Device: r.Device, From: r.From, To: r.To, Scope: r.Scope}
	all := r.Changes
	if r.whole != nil {
		all = r.whole
	}
	out.Added, out.Removed, out.Changed = countChanges(all)
	return out
}
