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
	"fmt"
	"net/netip"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
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
	Known    bool   `json:"known"`
	Relevant bool   `json:"relevant"`
	Reason   string `json:"reason"`
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
	known   bool
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
	run.Output = s.verdict
	return run, err
}

// relevance reads the forwarding table's placements of both endpoints.
func relevance(zl index.ZoneLocator, f simulate.Flow) Relevance {
	if zl == nil {
		return Relevance{Reason: "no stored forwarding table"}
	}
	for _, ep := range []simulate.Endpoint{f.Source, f.Destination} {
		for _, a := range ep.Addrs {
			for _, p := range zl.ZonesOf(a) {
				if !isDefault(p.Route) {
					return Relevance{
						Known: true, Relevant: true,
						Reason: fmt.Sprintf("%s via %s covers %s", p.Route, p.Router, a),
					}
				}
			}
		}
	}
	return Relevance{Known: true, Reason: "only a default route covers either endpoint"}
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
