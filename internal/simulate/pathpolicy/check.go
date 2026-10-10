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
// addresses, the zones, and the decision (spec §4.7, "Check fidelity"). The
// service and URL stages say only which candidates were kept; the decision
// already accounts for those in doubt.
var decisionStages = []string{"resolve-source", "resolve-destination", "derive-zones", "first-match"}

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
	t, miss := load(env, h)
	if miss != nil {
		out.Verdict, out.Reason, out.Fidelity = Undecided, simulate.Reasons{miss.Why()}, simulate.UnderMatch(miss.Why())
		return out, &simulate.UnavailableError{Missing: []simulate.Missing{*miss}}
	}
	// Routing already applied the hop's NAT and gave its zones. Without the
	// network, the check does not run NAT a second time only to note a zone
	// the given one wins over (spec §18 N10).
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
	if gap := t.Config.VersionGap(); gap != "" {
		// Read with the nearest older schema: inferred, not undecided (spec E25).
		fs = append(fs, simulate.Inferred)
		if !slices.ContainsFunc(out.Notes, func(n reason.Reason) bool { return n.Code == "gap.version" }) {
			out.Notes = append(out.Notes, reason.New("gap.version", gap))
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
