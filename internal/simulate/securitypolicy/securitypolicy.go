// Package securitypolicy is the first simulation: which security rule one flow
// would hit on one device and vsys. It runs as named stages that narrow a candidate
// set, each declaring how certain it is (spec §11.4, §11.6).
//
// The flow's source and destination are an address or an FQDN; it can carry a port,
// a URL and zones. Zones are derived from the stored forwarding table, or from the
// configuration, when not given. The application is evaluated with the device's
// App-ID content data (spec 2026-10-16 §4): the explicit candidates first, then
// the allow rules that imply it, as observed on the lab VM, PAN-OS 12.1.9
// (I1-I8, S9), and on fw02, PAN-OS 12.2.3 (I9). The flow's application matches
// without regard to case (P14). Without a flow application or without the data,
// a rule that names an application stays in doubt. The user is not evaluated.
package securitypolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/rulebase"
)

// Kind is the registry key and the command name.
const Kind = "policy"

// Simulation is the security-policy simulation.
type Simulation struct{}

var _ simulate.Simulation = Simulation{}

// Kind implements simulate.Simulation.
func (Simulation) Kind() string { return Kind }

// Describe implements simulate.Simulation.
func (Simulation) Describe() string {
	return "which security rule one flow would hit, by address or FQDN, port, URL and zone"
}

// Stages implements simulate.Simulation.
func (Simulation) Stages() []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Slug
	}
	return out
}

// Verdict is the output of a run.
type Verdict struct {
	Rule *resolve.Rule `json:"rule"` // first match; nil when none
	// Undecided says why no rule or default rule decides the flow, empty when one
	// does (spec §4.7): a stage that may miss matches, or candidates in doubt. Rule
	// or Default may still be set: the first certain match. A composite reason
	// keeps its parts, each with its code; its text joins them.
	Undecided simulate.Reasons `json:"undecided,omitempty"`
	// Default is the default rule that decides when no rule matches, empty when
	// none decides; DefaultAction is its action, and DefaultSource where the action
	// came from: built-in, local or pushed.
	Default       string         `json:"default"`
	DefaultAction string         `json:"default_action"`
	DefaultSource string         `json:"default_source"`
	Candidates    []resolve.Rule `json:"candidates"`
	// Doubts names the candidates that set a matching field no stage evaluates, in
	// rule order (spec §4.7).
	Doubts    []Doubt        `json:"doubts"`
	Zones     ZoneDerivation `json:"zones"`
	Relevance Relevance      `json:"relevance"`
	// Implicit is set when Rule matches the flow's application only through
	// the implicit use of the rule's applications (spec 2026-10-16 I1).
	Implicit *Implicit `json:"implicit,omitempty"`
	// AppData is whether the target had App-ID content data. The needs read
	// it: only with data does an application decide a doubt (C8).
	AppData bool `json:"-"`
}

// Outcome is what a decided flow meets: it passes, or it stops.
type Outcome string

// The outcomes of a security check (spec §4.7).
const (
	Pass      Outcome = "pass"
	Stop      Outcome = "stop"
	Undecided Outcome = "undecided"
)

// Decision is the verdict's outcome and why. allow passes; deny, drop and the
// reset actions stop (spec §4.6, PAN-OS admin guide, "Security Policy Actions").
// Any other action, or no deciding rule, is undecided.
//
// The reason of a decided flow is a verdict: the rule or default rule that
// decides (spec §12 C9). An undecided flow's reason can have several parts.
func (v Verdict) Decision() (Outcome, simulate.Reasons) {
	if len(v.Undecided) > 0 {
		return Undecided, v.Undecided
	}
	what, action := fmt.Sprintf("default rule %s (%s), %s", v.Default, v.DefaultAction, v.DefaultSource), v.DefaultAction
	code, invalid := reason.Code("verdict.default"), reason.Code("default.invalid-action")
	switch {
	case v.Rule != nil:
		what, action = fmt.Sprintf("rule %s (%s)", v.Rule.Name, v.Rule.Action), v.Rule.Action
		code, invalid = "verdict.rule", "doubt.invalid-action"
	case v.Default == "":
		return Undecided, simulate.Reasons{reason.New("default.none", "no rule decides")}
	}
	switch {
	case action == "allow":
		return Pass, simulate.Reasons{reason.New(code, what)}
	case slices.Contains(validActions, action):
		return Stop, simulate.Reasons{reason.New(code, what)}
	}
	return Undecided, simulate.Reasons{reason.New(invalid, what+" is not a security rule action")}
}

// ZoneDerivation says which zones were used and where they came from.
type ZoneDerivation struct {
	From   []string `json:"from"`
	To     []string `json:"to"`
	Source string   `json:"source"` // given, forwarding table, configuration, not evaluated
	Detail string   `json:"detail,omitempty"`
}

// Relevance is whether the device routes either endpoint by something more
// specific than a default route (spec S14). It orders an estate's answers in M5.
type Relevance struct {
	Known    bool
	Relevant bool
	Reason   reason.Reason // a verdict when known (spec §12 C9)
}

// MarshalJSON writes {"known", "relevant", "code", "text"}: the reason with
// its context (spec 2026-10-09 §3.2).
func (r Relevance) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Known    bool        `json:"known"`
		Relevant bool        `json:"relevant"`
		Code     reason.Code `json:"code"`
		Text     string      `json:"text"`
	}{r.Known, r.Relevant, r.Reason.Code, r.Reason.Text})
}

// state is what the stages share.
type state struct {
	env    *simulate.Env
	in     simulate.Input
	target simulate.Target
	idx    *index.Index // the target's security index, from its provider
	view   *index.View
	rules  []resolve.Rule
	cand   *roaring.Bitmap
	// known is whether the flow's zones are single and known: given, or derived
	// with one zone on each side, and defined in the vsys. Only then do
	// rule-type and the default rules decide (spec §4.6, C5, C16). from and to
	// are that pair; the flow's own zones are empty when they are derived.
	known    bool
	from, to string
	// ruleTypeOpen holds the intrazone and interzone rules derived zones could
	// not judge: several zones, or none, on a side. Each candidate in it has a
	// zone.derived doubt.
	ruleTypeOpen *roaring.Bitmap
	// opaque holds, per address field, the candidates kept because they name
	// addresses the configuration does not hold, and why, by rule position.
	opaque map[string]map[uint32][]reason.Reason
	// fqdn holds, per address field, the candidates that matched the flow's
	// FQDN only through an FQDN object, by rule position (spec 2026-10-09 §3.8).
	fqdn map[string]fqdnMatch
	// serviceHits holds the rules whose service holds the flow's port through
	// an object the configuration defines, or any; nil without a port.
	serviceHits *roaring.Bitmap
	// apps is the target's App-ID content data, nil without it. flowApp is
	// the flow's application, and flowErr a value of its custom entry that
	// cannot be read. evaluated is whether match-application evaluated the
	// application: a flow application and data.
	apps      *appid.Data
	flowApp   appid.App
	flowErr   error
	evaluated bool
	// explicit, implicit and kept are the candidates of the two passes (spec
	// 2026-10-16 §4.3): the rules whose set holds the flow's application, the
	// allow rules whose applications imply it, and the rules kept for a name
	// the data and the configuration lack. implied names, per implicit rule,
	// its applications that imply the flow's; appDoubts gives each kept rule
	// its reasons.
	explicit, implicit, kept *roaring.Bitmap
	implied                  map[uint32][]string
	appDoubts                map[uint32][]reason.Reason
	// notes are the run's own notes, after the target's.
	notes   simulate.Reasons
	verdict Verdict
}

// fqdnMatch is the rules an FQDN reached only through an FQDN object, and the
// negated rules it excluded only through one.
type fqdnMatch struct {
	name    string
	rules   *roaring.Bitmap
	negated *roaring.Bitmap
}

// Run implements simulate.Simulation.
func (Simulation) Run(ctx context.Context, env *simulate.Env, in simulate.Input) (simulate.Run, error) {
	run := simulate.Run{Kind: Kind, Device: in.Device, Vsys: in.Vsys, Input: in}
	t, err := env.Load(in.Device, in.Vsys)
	if err != nil {
		return run, fmt.Errorf("%s: %s/%s: %w", Kind, in.Device, in.Vsys, err)
	}
	// A copy: the run appends its own notes, and the target is shared.
	run.Notes = slices.Clone(t.Notes)
	idx, err := t.Index(resolve.Security, in.Vsys)
	if err != nil {
		return run, fmt.Errorf("%s: %s/%s: %w", Kind, in.Device, in.Vsys, err)
	}
	// A given zone the vsys does not define is a question the check cannot
	// take (C15): the caller is told the vsys's zones.
	if r := rulebase.UndefinedZones(t.Config, idx.Scope(), in.Flow.FromZone, in.Flow.ToZone); r != nil {
		return run, r.Choice
	}
	s := &state{env: env, in: in, target: t, idx: idx, view: idx.With(t.Providers), rules: idx.Rules(), apps: t.Providers.Apps}
	s.verdict.AppData = s.apps != nil
	// With data, the flow's application is checked and made canonical before
	// the stages (spec 2026-10-16 P10, P14, P15).
	if s.apps != nil && in.Flow.Application != "" {
		a, refusal := flowApplication(t.Config, idx.Scope(), s.apps, in.Flow.Application)
		if refusal != nil {
			return run, refusal
		}
		s.flowApp, s.flowErr = a.App, a.Err
		s.in.Flow.Application = a.App.Name
		run.Input.Flow.Application = a.App.Name
	}
	s.verdict.Relevance = relevance(t.Providers.Zones, in.Flow)
	stages, err := simulate.Execute(ctx, Kind, s, steps, false, env.Log)
	run.Stages = stages
	run.Fidelity = simulate.Overall(stages)
	if u := undermatched(stages); err == nil && len(u) > 0 {
		s.verdict.Undecided = u
	}
	run.Notes = append(run.Notes, s.notes...)
	run.Output = s.verdict
	return run, err
}

// undermatched is the reason of the first stage that may be missing matches, or
// empty when none is. Such a stage may have dropped the rule the device would hit,
// so no rule after it decides the flow: the tree's first question (spec §4.7), so
// its reason wins over a doubt first-match found. Only the undermatch reasons
// count: an overmatch reason of the same stage says nothing about what is
// missing. Several reasons stay parts, each with its code.
func undermatched(stages []simulate.Stage) simulate.Reasons {
	for _, st := range stages {
		if f := st.Fidelity; f.Level() == "undermatch" {
			return f.UnderMatchReasons()
		}
	}
	return nil
}

// relevance reads the forwarding table's placements of both endpoints.
func relevance(zl index.ZoneLocator, f simulate.Flow) Relevance {
	if zl == nil {
		return Relevance{Reason: reason.New("gap.fib-missing", "no stored forwarding table")}
	}
	for _, ep := range []simulate.Endpoint{f.Source, f.Destination} {
		for _, a := range ep.Addrs {
			for _, p := range zl.ZonesOf(a) {
				if !isDefault(p.Route) {
					return Relevance{
						Known: true, Relevant: true,
						Reason: reason.New("verdict.relevant-route", fmt.Sprintf("%s via %s covers %s", p.Route, p.Router, a)),
					}
				}
			}
		}
	}
	return Relevance{Known: true, Reason: reason.New("verdict.not-relevant", "only a default route covers either endpoint")}
}

func isDefault(route string) bool {
	p, err := netip.ParsePrefix(route)
	return err == nil && p.Bits() == 0
}
