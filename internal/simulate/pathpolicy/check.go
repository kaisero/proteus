package pathpolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// Security is the security policy check: which rule, or default rule, the hop's
// vsys applies to the hop's flow, in the zones routing gave it (spec E4).
type Security struct{}

var _ Check = Security{}

// Name implements Check.
func (Security) Name() string { return checkSecurity }

// decisionStages are the stages whose fidelity a hop's security answer takes: the
// addresses, the zones, the user and the decision (spec §4.7, "Check
// fidelity"). The service and URL stages say only which candidates were kept;
// the decision already accounts for those in doubt. match-user is inferred
// when the user is: no identified user, a user in doubt, or one from an email
// (spec 2026-10-17 §5.3, §5.4, PD12).
var decisionStages = []string{"resolve-source", "resolve-destination", "derive-zones", "match-user", "first-match"}

// Evaluate implements Check. It runs securitypolicy on the hop's device and vsys
// with the hop's zones given, so they are single and known when the vsys defines
// them, and each endpoint trimmed to the address routing traced (spec §3.3, §4.4).
func (Security) Evaluate(ctx context.Context, env *simulate.Env, h routing.Hop, flow simulate.Flow) (CheckResult, error) {
	out := CheckResult{Name: checkSecurity}
	if h.Vsys == "" || flow.FromZone == "" || flow.ToZone == "" {
		// Without both zones securitypolicy would derive them; the path gives the
		// zones, or the hop has none to check (spec §4.4).
		code := reason.Code("zone.missing")
		if h.Vsys == "" {
			code = "zone.vsys-unknown"
		}
		out.Verdict, out.Reason, out.Fidelity = NotEvaluated, simulate.Reasons{reason.New(code, "the hop's vsys or zones are not known")}, simulate.Exact
		return out, nil
	}
	_, miss := load(env, h)
	if miss != nil {
		out.Verdict, out.Reason, out.Fidelity = Undecided, simulate.Reasons{miss.Why()}, simulate.UnderMatch(miss.Why())
		return out, &simulate.UnavailableError{Missing: []simulate.Missing{*miss}}
	}
	// Routing applied the hop's NAT, in the router it traced, and gave the
	// hop's zones: routing's NAT is the authority. Without the network, the
	// check does not run NAT a second time, in a router it would guess, only
	// to note a zone the given one wins over (spec §18 N10).
	local := *env
	local.Network = nil
	run, err := securitypolicy.Simulation{}.Run(ctx, &local, simulate.Input{Device: h.Device, Vsys: h.Vsys, Flow: flow.FirstAddresses()})
	if c, ok := errors.AsType[*simulate.ChoiceError](err); ok && c.Kind == simulate.ChoiceZone {
		// A zone the hop's vsys does not define: the check cannot take it, and
		// the hop's zone doubt leaves the hop undecided (spec §4.4).
		why := reason.New("zone.undefined", fmt.Sprintf("a zone of the hop is not defined in %s", h.Vsys))
		out.Verdict, out.Reason, out.Fidelity = NotEvaluated, simulate.Reasons{why}, simulate.Exact
		return out, nil
	}
	if c, ok := errors.AsType[*simulate.ChoiceError](err); ok && c.Kind == simulate.ChoiceApplication {
		// The hop's content data lacks the flow's application, or names a
		// container (spec 2026-10-16 P10). The hops of one path can have
		// different content versions, so the hop is undecided and the path
		// goes on (§4.1, D13).
		why := reason.New("doubt.application-unknown", h.Device+": "+c.Question)
		out.Verdict, out.Reason, out.Fidelity = Undecided, simulate.Reasons{why}, simulate.UnderMatch(why)
		return out, nil
	}
	if err != nil {
		return out, err
	}
	v := run.Output.(securitypolicy.Verdict)
	v.Zones.Source = "path"
	out.Security, out.Stages, out.Notes = &v, run.Stages, run.Notes

	var fs []simulate.Fidelity
	for _, st := range run.Stages {
		if slices.Contains(decisionStages, st.Slug) || st.Fidelity.Level() == "undermatch" {
			fs = append(fs, st.Fidelity)
		}
	}
	out.Fidelity = simulate.Weakest(fs...)

	o, why := v.Decision()
	out.Reason = why
	switch o {
	case securitypolicy.Pass:
		out.Verdict = Pass
	case securitypolicy.Stop:
		out.Verdict = Stop
	default:
		out.Verdict = Undecided
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.UnderMatch(why...))
	}
	if out.Verdict != Undecided {
		out.Rule = v.Default
		if v.Rule != nil {
			out.Rule = v.Rule.Name
		}
	}
	return out, nil
}
