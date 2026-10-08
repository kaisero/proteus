// Package pathpolicy answers whether a flow passes every firewall on its path. It
// runs routing once, then evaluates each hop's checks on the hop's flow and zones,
// and folds the hops into one verdict: allowed, denied or undecided (spec
// 2026-10-07 §4, §5).
//
// It is a function package, not a registered simulation kind: Run returns a
// Result and routing's stages. Every device's data reaches it through
// simulate.Env, so it does no I/O.
package pathpolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// HopVerdict is what one check concludes on one hop.
type HopVerdict string

// The verdicts of a check on a hop (spec §4.2).
const (
	Pass         HopVerdict = "pass"          // the flow continues
	Stop         HopVerdict = "stop"          // a decided deny or drop
	Undecided    HopVerdict = "undecided"     // the check cannot decide
	NotEvaluated HopVerdict = "not-evaluated" // the check does not run on this hop
)

// Check evaluates one rulebase on one hop.
type Check interface {
	Name() string // "security"
	// Evaluate checks the flow on the hop. An *simulate.UnavailableError says the
	// hop's data cannot be read: Run records it as a hole and keeps the result,
	// which must say undecided. Any other error stops the run.
	Evaluate(ctx context.Context, env *simulate.Env, h routing.Hop, flow simulate.Flow) (CheckResult, error)
}

// CheckResult is one check on one hop.
type CheckResult struct {
	Name     string
	Verdict  HopVerdict
	Reason   string // why it passes, stops, is undecided, or is not evaluated
	Rule     string // the deciding rule's name, or the default rule's name; empty when undecided
	Fidelity simulate.Fidelity
	Security *securitypolicy.Verdict // the security check's typed output
	Stages   []simulate.Stage
	Notes    []string // the notes of the target the check read, such as a version gap
}

// Hop is one routing hop with its checks, in list order.
type Hop struct {
	Index   int // 1-based
	Routing routing.Hop
	// Doubts say why the path or the zones leave the hop undecided, whatever its
	// checks conclude (spec §4.4, §4.5). The checks still run, so the answer shows
	// what the hop would decide.
	Doubts    []string
	Checks    []CheckResult
	AfterDeny bool
}

// Verdict is the overall answer.
type Verdict string

// The overall verdicts (spec E6).
const (
	VerdictAllowed   Verdict = "allowed"
	VerdictDenied    Verdict = "denied"
	VerdictUndecided Verdict = "undecided"
)

// Point is where the verdict was decided, or where it became undecided.
type Point struct {
	Hop    int    // index of the hop; for a routing end, the last hop
	Check  string // "security" or "routing"
	Rule   string
	Reason string
}

// Result is a path mode answer.
type Result struct {
	Verdict  Verdict
	At       *Point       // nil when allowed
	Path     routing.Path // placement, outcome, end, hidden, notes
	Hops     []Hop
	Fidelity simulate.Fidelity // weakest of routing stages and checks up to At
	Holes    []simulate.Missing
	Notes    []string
}

// The checks' names, and the routing pseudo-check a Point names.
const (
	checkSecurity = "security"
	checkRouting  = "routing"
)

// Checks are the checks Run evaluates on every hop, in list order.
func Checks() []Check { return []Check{Security{}} }

// Run answers a flow along its path. The input is routing's: the flow, and the
// "device" and "router" params for a given start. A routing ChoiceError or
// UnavailableError returns unchanged; the stages returned are routing's, and each
// check keeps its own in its CheckResult (spec §4.3).
func Run(ctx context.Context, env *simulate.Env, in simulate.Input) (Result, []simulate.Stage, error) {
	return run(ctx, env, in, Checks())
}

func run(ctx context.Context, env *simulate.Env, in simulate.Input, checks []Check) (Result, []simulate.Stage, error) {
	if env.Load == nil {
		return Result{}, nil, errors.New("pathpolicy: no configuration to read")
	}
	rr, err := routing.Simulation{}.Run(ctx, env, in)
	if err != nil {
		return Result{}, rr.Stages, err
	}
	p := rr.Output.(routing.Path)
	res := Result{Path: p}
	for i, rh := range p.Hops {
		h := Hop{Index: i + 1, Routing: rh}
		var caps []simulate.Fidelity
		h.Doubts, caps = pathDoubts(p, h.Index, rr.Stages)
		if p.Outcome == routing.Dropped && h.Index == len(p.Hops) {
			// Routing dropped the packet before security policy: PAN-OS looks the
			// route up first (KB "Packet Flow Sequence in PAN-OS", spec §4.8).
			for _, c := range checks {
				h.Checks = append(h.Checks, CheckResult{
					Name: c.Name(), Verdict: NotEvaluated, Reason: "dropped by routing before security policy", Fidelity: simulate.Exact,
				})
			}
			res.Hops = append(res.Hops, h)
			continue
		}
		zd, miss := zoneDoubts(env, rh)
		h.Doubts = append(h.Doubts, zd...)
		res.Holes = addHoles(res.Holes, miss...)
		for _, c := range checks {
			r, err := c.Evaluate(ctx, env, rh, rh.Flow)
			if u, ok := errors.AsType[*simulate.UnavailableError](err); ok {
				res.Holes = addHoles(res.Holes, u.Missing...)
			} else if err != nil {
				return res, rr.Stages, err
			}
			r.Fidelity = simulate.Weakest(append([]simulate.Fidelity{r.Fidelity}, caps...)...)
			h.Checks = append(h.Checks, r)
		}
		res.Hops = append(res.Hops, h)
	}
	fold(&res, rr.Fidelity)
	return res, rr.Stages, nil
}

// addHoles adds missing data once per device and reason.
func addHoles(holes []simulate.Missing, ms ...simulate.Missing) []simulate.Missing {
	for _, m := range ms {
		if !slices.Contains(holes, m) {
			holes = append(holes, m)
		}
	}
	return holes
}

// pathDoubts reads the routing facts that leave hop n undecided, and the caps
// they put on its checks' fidelity (spec §4.5, E21). The hop's PBF list names at
// most the first rule that can redirect the flow, so an empty one does not prove
// that none applies: an undermatch PBF stage leaves the hop undecided too.
func pathDoubts(p routing.Path, n int, stages []simulate.Stage) ([]string, []simulate.Fidelity) {
	h := p.Hops[n-1]
	var doubts []string
	var caps []simulate.Fidelity
	if len(h.ECMP) > 0 {
		doubts = append(doubts, fmt.Sprintf("ECMP: %d other next hops not followed", len(h.ECMP)))
	}
	for _, r := range h.PBF {
		doubts = append(doubts, fmt.Sprintf("PBF rule %s can redirect the flow", r))
	}
	if f, ok := stageFidelity(stages, n, "pbf"); ok && f.Level() == "undermatch" {
		doubts = append(doubts, f.Reasons()...)
	}
	if f, ok := stageFidelity(stages, n, "nat"); ok {
		switch f.Level() {
		case "undermatch":
			doubts = append(doubts, f.Reasons()...)
		case "inferred":
			caps = append(caps, simulate.Inferred)
		}
	}
	if n == 1 && p.StartVia.IsValid() {
		if p.StartVia.Bits() == 0 {
			doubts = append(doubts, "the ingress is a guess from a default route")
		} else {
			caps = append(caps, simulate.Inferred)
		}
	}
	return doubts, caps
}

// stageFidelity is the fidelity of hop n's routing stage of that name.
func stageFidelity(stages []simulate.Stage, n int, name string) (simulate.Fidelity, bool) {
	slug := fmt.Sprintf("hop%d/%s", n, name)
	for _, st := range stages {
		if st.Slug == slug {
			return st.Fidelity, true
		}
	}
	return simulate.Fidelity{}, false
}

// zoneDoubts checks the hop's zones before its checks run (spec §4.4): both must
// be named and defined in the hop's vsys, and neither may be routing's
// placeholder. A configuration that cannot be read is a hole.
func zoneDoubts(env *simulate.Env, h routing.Hop) ([]string, []simulate.Missing) {
	switch {
	case h.Vsys == "":
		return []string{"vsys unknown"}, nil
	case h.ZonePlaceholder:
		return []string{"the zone names are placeholders: no external zone joins these vsys in the configuration"}, nil
	}
	var out []string
	if h.Flow.FromZone == "" {
		out = append(out, "routing found no ingress zone")
	}
	if h.Flow.ToZone == "" {
		out = append(out, "routing found no egress zone")
	}
	if len(out) > 0 {
		return out, nil
	}
	t, miss := load(env, h)
	if miss != nil {
		return []string{miss.Reason}, []simulate.Missing{*miss}
	}
	defined := map[string]bool{}
	for _, z := range resolve.ZonesInScope(t.Config, config.Scope{Sort: config.ScopeVsys, Name: h.Vsys}) {
		defined[z.Name] = true
	}
	for _, z := range []string{h.Flow.FromZone, h.Flow.ToZone} {
		why := fmt.Sprintf("zone %s is not defined in %s", z, h.Vsys)
		if !defined[z] && !slices.Contains(out, why) {
			out = append(out, why)
		}
	}
	return out, nil
}

// load reads the hop's target, or says why it cannot.
func load(env *simulate.Env, h routing.Hop) (simulate.Target, *simulate.Missing) {
	t, err := env.Load(h.Device, h.Vsys)
	if err == nil && (t.Config == nil || t.Index == nil) {
		err = errors.New("no configuration")
	}
	if err != nil {
		return t, &simulate.Missing{Device: h.Device, Reason: fmt.Sprintf("the configuration of %s %s cannot be read: %v", h.Device, h.Vsys, err)}
	}
	return t, nil
}
