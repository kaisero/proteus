// Package securitypolicy is the first simulation: which security rule one flow
// would hit on one device and vsys. It runs as named stages that narrow a candidate
// set, each declaring how certain it is (spec §11.4, §11.6).
//
// The flow's source and destination are an address or an FQDN; it can carry a port,
// a URL and zones. Zones are derived from the stored forwarding table, or from the
// configuration, when not given. Application and user are not evaluated.
package securitypolicy

import (
	"context"
	"encoding/json"
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
	// or Default may still be set: the first certain match.
	Undecided reason.Reason `json:"undecided,omitzero"`
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
// decides (spec §12 C9).
func (v Verdict) Decision() (Outcome, reason.Reason) {
	if v.Undecided.Text != "" {
		return Undecided, v.Undecided
	}
	what, action := fmt.Sprintf("default rule %s (%s), %s", v.Default, v.DefaultAction, v.DefaultSource), v.DefaultAction
	code, invalid := reason.Code("verdict.default"), reason.Code("default.invalid-action")
	switch {
	case v.Rule != nil:
		what, action = fmt.Sprintf("rule %s (%s)", v.Rule.Name, v.Rule.Action), v.Rule.Action
		code, invalid = "verdict.rule", "verdict.invalid-action"
	case v.Default == "":
		return Undecided, reason.New("default.none", "no rule decides")
	}
	switch {
	case action == "allow":
		return Pass, reason.New(code, what)
	case slices.Contains(validActions, action):
		return Stop, reason.New(code, what)
	}
	return Undecided, reason.New(invalid, what+" is not a security rule action")
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

// MarshalJSON writes {"known", "relevant", "reason"}, the reason as its text, as
// format 1 does.
func (r Relevance) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Known    bool   `json:"known"`
		Relevant bool   `json:"relevant"`
		Reason   string `json:"reason"`
	}{r.Known, r.Relevant, r.Reason.Text})
}

// state is what the stages share.
type state struct {
	env    *simulate.Env
	in     simulate.Input
	target simulate.Target
	view   *index.View
	rules  []resolve.Rule
	cand   *roaring.Bitmap
	// known is whether the flow's zones are single and known: given, one name
	// each, and defined in the vsys. Only then do rule-type and the default rules
	// decide (spec §4.6).
	known bool
	// opaque holds, per address field, the candidates kept because they name
	// addresses the configuration does not hold, and why, by rule position.
	opaque  map[string]map[uint32][]reason.Reason
	verdict Verdict
}

// Run implements simulate.Simulation.
func (Simulation) Run(ctx context.Context, env *simulate.Env, in simulate.Input) (simulate.Run, error) {
	run := simulate.Run{Kind: Kind, Device: in.Device, Vsys: in.Vsys, Input: in}
	t, err := env.Load(in.Device, in.Vsys)
	if err != nil {
		return run, fmt.Errorf("%s: %s/%s: %w", Kind, in.Device, in.Vsys, err)
	}
	run.Notes = t.Notes
	s := &state{env: env, in: in, target: t, view: t.Index.With(t.Providers), rules: t.Index.Rules()}
	s.verdict.Relevance = relevance(t.Providers.Zones, in.Flow)
	stages, err := simulate.Execute(ctx, Kind, s, steps, false, env.Log)
	run.Stages = stages
	run.Fidelity = simulate.Overall(stages)
	if u := undermatched(stages); err == nil && u.Text != "" {
		s.verdict.Undecided = u
	}
	run.Output = s.verdict
	return run, err
}

// undermatched is the reason of the first stage that may be missing matches, or
// empty when none is. Such a stage may have dropped the rule the device would hit,
// so no rule after it decides the flow: the tree's first question (spec §4.7), so
// its reason wins over a doubt first-match found. Only the undermatch reasons
// count: an overmatch reason of the same stage says nothing about what is
// missing. A version gap does not count: withoutGap has already made it inferred
// (E25). Several reasons read as one, with the first one's code.
func undermatched(stages []simulate.Stage) reason.Reason {
	for _, st := range stages {
		if f := st.Fidelity; f.Level() == "undermatch" {
			return f.UnderMatchReasons().Joined()
		}
	}
	return reason.Reason{}
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

// definedIn returns the names a configuration defines for the kinds a rule field
// may name, so a value outside them is known to be predefined or unknown here.
func definedIn(cfg *config.Config, sc config.Scope, field string) map[string]bool {
	out := map[string]bool{}
	for _, kind := range cfg.FieldKinds("rulebase/security/rules")[field] {
		objs := resolve.ObjectsInScope(cfg, sc, kind)
		for _, o := range objs {
			out[o.Name] = true
		}
	}
	return out
}
