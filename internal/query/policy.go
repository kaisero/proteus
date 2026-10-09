package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
	"github.com/okaiser/proteus/internal/simulate/topology"
)

// policyCommand is simulate policy's command name.
const policyCommand = "simulate " + securitypolicy.Kind

// oneConfig is the way to the single-configuration check that a path mode
// usage error names.
const oneConfig = "use --file <path> --vsys <name> for one configuration"

// PolicyInput is simulate policy along the flow's path (spec 2026-10-07 §3).
type PolicyInput struct {
	Flow FlowInput `json:"flow"`
	// Device is the firewall the path starts on; "" places the start by the
	// source. Router picks its logical router.
	Device string `json:"device,omitempty"`
	Router string `json:"router,omitempty"`
	// At reads each device's newest snapshot at or before this time.
	At string `json:"at,omitempty"`
	// Vsys and Label select for one configuration; path mode refuses them,
	// because it checks every firewall and vsys on the path.
	Vsys  []string `json:"vsys,omitempty"`
	Label []string `json:"label,omitempty"`
	// Simulated is the flow as simulated, its endpoints resolved. The query
	// sets it on the envelope's input; it is ignored on the way in.
	Simulated simulate.Flow `json:"-"`
}

// Validate holds path mode's input rules (spec 2026-10-07 §3.1): a flag the mode
// does not take names it, and the flow's ports must parse.
func (in PolicyInput) Validate() *UsageError {
	for _, f := range []struct {
		given      bool
		flag, what string
	}{{len(in.Vsys) > 0, "vsys", "selects a vsys"}, {len(in.Label) > 0, "label", "selects devices"}} {
		if f.given {
			return usage(fmt.Sprintf("--%s %s, but path mode checks every firewall and vsys on the path; %s", f.flag, f.what, oneConfig),
				fmt.Sprintf("%s %s, but path mode checks every firewall and vsys on the path", f.flag, f.what))
		}
	}
	for _, f := range []struct {
		given       bool
		flag, field string
	}{{in.Flow.FromZone != "", "from-zone", "from_zone"}, {in.Flow.ToZone != "", "to-zone", "to_zone"}} {
		if f.given {
			return usage(fmt.Sprintf("--%s: the path gives the zones; %s", f.flag, oneConfig), f.field+": the path gives the zones")
		}
	}
	if in.Router != "" && in.Device == "" {
		return usage("--router needs --device", "router needs device")
	}
	_, u := in.Flow.flow()
	return u
}

// PolicyFileInput is simulate policy on one configuration file: one vsys, its
// zones given or derived from the configuration.
type PolicyFileInput struct {
	Flow FlowInput `json:"flow"`
	// Selection names the file and its vsys. The store's selectors are refused.
	Selection Selection `json:"selection"`
	// Router is refused: a file has no path to start.
	Router string `json:"router,omitempty"`
	// Simulated is the flow as simulated; see PolicyInput.
	Simulated simulate.Flow `json:"-"`
}

// Validate holds the file mode's input rules: no store selector, no router, both
// zones or neither, and ports that parse.
func (in PolicyFileInput) Validate() *UsageError {
	sel := in.Selection
	if sel.File == "" {
		return usage("give a configuration file with --file", "give file")
	}
	if u := sel.validateFile(); u != nil {
		return u
	}
	if in.Router != "" {
		return usage("--router picks the start router of --device; --file has no path", "router picks the start router of device; file has no path")
	}
	if (in.Flow.FromZone == "") != (in.Flow.ToZone == "") {
		return usage("--from-zone and --to-zone go together", "from_zone and to_zone go together")
	}
	_, u := in.Flow.flow()
	return u
}

// Policy is simulate policy in path mode: routing's path, the security check on
// every hop, one verdict. A start only the user can choose is a
// *simulate.ChoiceError; the path's holes come back with no result.
func Policy(ctx context.Context, env Env, in PolicyInput) (Envelope[PolicyInput, PathResult], error) {
	var none Envelope[PolicyInput, PathResult]
	if u := in.Validate(); u != nil {
		return none, u
	}
	flow, _ := in.Flow.flow()
	if env.Inventory == nil {
		return none, errNoInventory
	}
	if in.Device != "" {
		if _, err := env.Inventory.Select([]string{in.Device}, nil); err != nil {
			return none, usageOf(err, err.Error(), "")
		}
	}
	var err error
	if flow.Source, err = pathEndpoint(ctx, env, in.Flow.Source, in.Flow.NoDNS); err != nil {
		return none, err
	}
	if flow.Destination, err = pathEndpoint(ctx, env, in.Flow.Destination, in.Flow.NoDNS); err != nil {
		return none, err
	}
	es, err := openEstate(env, in.At)
	if err != nil {
		return none, err
	}
	users, err := env.users()
	if err != nil {
		return none, err
	}
	sim := es.simEnv(env)
	sim.Load = storeLoader(es.st, es.when, es.network, users)
	if in.Flow.NoDNS {
		sim.Resolve = nil // NAT does not resolve a translated FQDN either
	}
	start := in.Device
	if start == "" {
		start = "placed by the source " + flow.Source.String()
	}
	env.Log.Infof(runlog.TagStep, "policy path %s -> %s, start %s", flow.Source, flow.Destination, start)
	res, stages, err := pathpolicy.Run(ctx, sim, simulate.Input{Flow: flow, Params: map[string]string{"device": in.Device, "router": in.Router}})
	in.Simulated = flow
	e := envelope[PolicyInput, PathResult](policyCommand, in)
	if u, ok := errors.AsType[*simulate.UnavailableError](err); ok {
		e.Holes = holesOf(u.Missing)
		return e, nil
	}
	if err != nil {
		return none, err
	}
	if res.At != nil {
		env.Log.Infof(runlog.TagStep, "path verdict: %s at hop %d (%s)", res.Verdict, res.At.Hop, res.At.Check)
	} else {
		env.Log.Infof(runlog.TagStep, "path verdict: %s", res.Verdict)
	}
	e.Results = []PathResult{pathResultOf(res, stages)}
	e.Holes = holesOf(res.Holes)
	e.Unresolved = pathUnresolved(res, stages)
	e.Notes = pathNotes(res)
	return e, nil
}

// PolicyFile is simulate policy on one configuration file. A selection that
// resolves to nothing but holes answers with them and no result.
func PolicyFile(ctx context.Context, env Env, in PolicyFileInput) (Envelope[PolicyFileInput, SecurityResult], error) {
	var none Envelope[PolicyFileInput, SecurityResult]
	if u := in.Validate(); u != nil {
		return none, u
	}
	flow, _ := in.Flow.flow()
	// An FQDN that resolves to no address is simulated: FQDN objects still match,
	// and the answer says it may miss rules.
	var err error
	if flow.Source, err = endpoint(ctx, env, in.Flow.Source, in.Flow.NoDNS); err != nil {
		return none, err
	}
	if flow.Destination, err = endpoint(ctx, env, in.Flow.Destination, in.Flow.NoDNS); err != nil {
		return none, err
	}
	in.Simulated = flow
	e := envelope[PolicyFileInput, SecurityResult](policyCommand, in)
	ts, holes, err := Targets(ctx, env, in.Selection)
	if err != nil {
		return none, err
	}
	e.Holes = holes
	switch {
	case len(ts) == 0 && len(holes) > 0:
		return e, nil // the holes say what is missing
	case len(ts) == 0:
		return none, errors.New("the selection has no device and vsys to simulate on")
	case len(ts) > 1:
		return none, usage(fmt.Sprintf("the file has %d vsys; select one with --vsys", len(ts)),
			fmt.Sprintf("the file has %d vsys; select one with vsys", len(ts)))
	}
	t := ts[0]
	sim, err := fileEnv(env, t, in.Flow.NoDNS)
	if err != nil {
		return none, err
	}
	env.Log.Infof(runlog.TagStep, "%s %s -> %s on %s/%s", securitypolicy.Kind, flow.Source, flow.Destination, t.Device, t.Vsys)
	run, err := securitypolicy.Simulation{}.Run(ctx, sim, simulate.Input{Flow: flow, Device: t.Device, Vsys: t.Vsys})
	if err != nil {
		return none, err
	}
	env.Log.Infof(runlog.TagStep, "%s: fidelity %s", securitypolicy.Kind, run.Fidelity)
	v, _ := run.Output.(securitypolicy.Verdict)
	e.Results = []SecurityResult{securityResultOf(run, t, v)}
	e.Targets = ts
	// A version gap is a note, not an unresolved entry: the security check
	// lowers its fidelity to inferred instead (spec E25).
	for _, n := range t.Notes {
		e.Notes = append(e.Notes, NoteOf(t.Device, t.Vsys, n))
	}
	// Every address is matched, so only an alias is worth a note.
	for _, n := range simulate.DNSNotes(flow, false) {
		e.Notes = append(e.Notes, NoteOf(t.Device, t.Vsys, n))
	}
	e.Unresolved = dedupeUnresolved(runUnresolved(run, t.Device, t.Vsys, true))
	return e, nil
}

// fileEnv is the simulation environment for one target read from a file: its
// configuration and the user directory. A file has no stored tables, so zones
// derive from the configuration.
func fileEnv(env Env, t estate.Target, noDNS bool) (*simulate.Env, error) {
	users, err := env.users()
	if err != nil {
		return nil, err
	}
	set := index.NewSet(t.Config)
	sim := &simulate.Env{Log: env.Log, Load: func(string, string) (simulate.Target, error) {
		// Built here, so a failed build is the load's error.
		if _, err := set.Index(t.Scope, resolve.Security); err != nil {
			return simulate.Target{}, err
		}
		return simulate.Target{
			Config: t.Config, Indexes: set.Provider(t.Scope),
			Providers: index.Providers{Users: users}, Notes: t.Notes,
		}, nil
	}, Resolve: env.Resolve}
	if noDNS {
		sim.Resolve = nil
	}
	return sim, nil
}

// pathUnresolved is what leaves a path answer incomplete (spec 2026-10-07 §5.4):
// each undecided hop, after the deny too, with its device, vsys and reason; a
// routing end that leaves the answer undecided; and the stages' unresolved
// entries.
func pathUnresolved(res pathpolicy.Result, stages []simulate.Stage) []Unresolved {
	var un []Unresolved
	for _, h := range res.Hops {
		if why, ok := hopUndecided(h); ok {
			un = append(un, UnresolvedOfParts(h.Routing.Device, h.Routing.Vsys, why)...)
		}
		for _, c := range h.Checks {
			un = append(un, runUnresolved(simulate.Run{Stages: c.Stages}, h.Routing.Device, h.Routing.Vsys, false)...)
		}
	}
	if at := res.At; res.Verdict == pathpolicy.VerdictUndecided && at.Check == "routing" {
		h, _ := PointHop(res)
		un = append(un, UnresolvedOfParts(h.Device, h.Vsys, at.Reason)...)
	}
	var device string
	if len(res.Hops) > 0 {
		device = res.Hops[0].Routing.Device
	}
	un = append(un, runUnresolved(simulate.Run{Stages: stages}, device, "", false)...)
	return dedupeUnresolved(un)
}

// hopUndecided says whether a hop is undecided, and why: the path's or the
// zones' doubts first, then the first undecided check.
func hopUndecided(h pathpolicy.Hop) (simulate.Reasons, bool) {
	if len(h.Doubts) > 0 {
		return h.Doubts[:1:1], true
	}
	for _, c := range h.Checks {
		if c.Verdict == pathpolicy.Undecided {
			return c.Reason, true
		}
	}
	return nil, false
}

// pathNotes are every note the text shows, for the envelope: routing's notes
// on the path and on each hop, each check's target notes, such as a version
// gap, and the answer's own (spec 2026-10-07 §8.2).
func pathNotes(res pathpolicy.Result) []Note {
	var device string
	if len(res.Hops) > 0 {
		device = res.Hops[0].Routing.Device
	}
	var out []Note
	out = append(out, runNotes(device, res.Path.Notes)...)
	for _, h := range res.Hops {
		out = append(out, runNotes(h.Routing.Device, h.Routing.Notes)...)
		for _, c := range h.Checks {
			for _, n := range c.Notes {
				out = append(out, NoteOf(h.Routing.Device, h.Routing.Vsys, n))
			}
		}
	}
	out = append(out, runNotes(device, res.Notes)...)
	// A note is the same when its text and place are: it reads the same
	// twice, so the first code stays.
	seen := map[Note]bool{}
	return slices.DeleteFunc(out, func(n Note) bool {
		k := n
		k.Code = ""
		dup := seen[k]
		seen[k] = true
		return dup
	})
}

// PointHop is the routing hop the verdict's point names; false for a path
// without that hop.
func PointHop(r pathpolicy.Result) (routing.Hop, bool) {
	if r.At == nil || r.At.Hop < 1 || r.At.Hop > len(r.Hops) {
		return routing.Hop{}, false
	}
	return r.Hops[r.At.Hop-1].Routing, true
}

// nonNilReasons is rs, or an empty list for none, so JSON prints [].
func nonNilReasons(rs simulate.Reasons) simulate.Reasons {
	if rs == nil {
		return simulate.Reasons{}
	}
	return rs
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// PathResult is simulate policy's result in path mode: the verdict and where it
// was decided, routing's path fields, and the hops with their checks. Result
// and RunStages are the native answer, for a renderer.
type PathResult struct {
	Mode        string            `json:"mode"`
	Verdict     string            `json:"verdict"`
	At          *Point            `json:"at"`
	Fidelity    simulate.Fidelity `json:"fidelity"`
	Source      simulate.Endpoint `json:"source"`
	Destination simulate.Endpoint `json:"destination"`
	Placed      topology.Placed   `json:"placed"`
	PlacedVia   string            `json:"placed_via,omitempty"`
	StartVia    netip.Prefix      `json:"start_via,omitzero"`
	Outcome     routing.Outcome   `json:"outcome"`
	End         string            `json:"end"`
	EndCode     reason.Code       `json:"end_code"`
	Hidden      []string          `json:"hidden,omitempty"`
	Stages      []Stage           `json:"stages"`
	Hops        []PathHop         `json:"hops"`

	Result    pathpolicy.Result `json:"-"`
	RunStages []simulate.Stage  `json:"-"`
}

// Point is where the verdict was decided, or became undecided, and why: one
// reason, or the parts of a composite one, each with its code.
type Point struct {
	Hop     int              `json:"hop"`
	Check   string           `json:"check"`
	Rule    string           `json:"rule"`
	Reasons simulate.Reasons `json:"reasons"`
}

// PathHop is one hop: routing's keys, with its notes, PBF rules, ECMP next
// hops and placeholder flag present even when empty, then what the path mode
// adds. A field declared here wins over routing.Hop's field of the same key.
type PathHop struct {
	Index int `json:"index"`
	routing.Hop
	Notes           simulate.Reasons      `json:"notes"`
	PBF             []string              `json:"pbf"`
	ECMP            []routing.NotFollowed `json:"ecmp_not_followed"`
	ZonePlaceholder bool                  `json:"zone_placeholder"`
	Doubts          simulate.Reasons      `json:"doubts"`
	AfterDeny       bool                  `json:"after_deny"`
	Checks          Checks                `json:"checks"`
}

// Check is one check's answer under its name.
type Check struct {
	Name     string
	Security Security
}

// Checks is a hop's checks as one JSON object, its keys in check order.
type Checks []Check

// MarshalJSON writes {"security": {...}, ...} in list order; a map would sort
// the keys.
func (cs Checks) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, c := range cs {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(c.Name)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(c.Security)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.Write(v)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// pathResultOf is a path answer's result.
func pathResultOf(r pathpolicy.Result, stages []simulate.Stage) PathResult {
	path := r.Path
	out := PathResult{
		Mode: "path", Verdict: string(r.Verdict), Fidelity: r.Fidelity,
		Source: path.Source, Destination: path.Destination, Placed: path.Placed, PlacedVia: path.PlacedVia,
		StartVia: path.StartVia, Outcome: path.Outcome, End: path.End, EndCode: path.EndCode, Hidden: path.Hidden,
		Stages: SimStages(stages), Hops: []PathHop{}, Result: r, RunStages: stages,
	}
	if at := r.At; at != nil {
		out.At = &Point{Hop: at.Hop, Check: at.Check, Rule: at.Rule, Reasons: at.Reason}
	}
	for _, h := range r.Hops {
		hj := PathHop{
			Index: h.Index, Hop: h.Routing, Notes: nonNilReasons(h.Routing.Notes), PBF: nonNil(h.Routing.PBF),
			ECMP: h.Routing.ECMP, ZonePlaceholder: h.Routing.ZonePlaceholder, Doubts: nonNilReasons(h.Doubts),
			AfterDeny: h.AfterDeny,
		}
		if hj.ECMP == nil {
			hj.ECMP = []routing.NotFollowed{}
		}
		for _, c := range h.Checks {
			hj.Checks = append(hj.Checks, Check{Name: c.Name, Security: securityOf(c.Security, string(c.Verdict), c.Reason, c.Rule, c.Fidelity, c.Stages)})
		}
		out.Hops = append(out.Hops, hj)
	}
	return out
}

// Rule is a rule in a simulation's answer.
type Rule struct {
	Position int    `json:"position"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Layer    string `json:"layer"`
	Scope    string `json:"scope"`
}

func ruleOf(r resolve.Rule) Rule {
	return Rule{r.Position, r.Name, r.Action, r.Layer.String(), r.Scope.String()}
}

// Security is a security check's answer: one type for a file target and for
// each hop of a path (spec 2026-10-07 E14, §8.2).
type Security struct {
	// Verdict is pass, stop, undecided or, on a hop, not-evaluated; Reasons say
	// why (spec 2026-10-07 §4.7): one reason, or a composite one's parts.
	Verdict string           `json:"verdict"`
	Reasons simulate.Reasons `json:"reasons"`
	// Rule is the rule or default rule that decides; empty when undecided.
	Rule string `json:"rule"`
	// Default is the default rule that decides when no rule matches, empty when
	// none does; DefaultSource says where its action came from.
	Default       string            `json:"default"`
	DefaultAction string            `json:"default_action"`
	DefaultSource string            `json:"default_source"`
	Fidelity      simulate.Fidelity `json:"fidelity"`
	FirstMatch    *Rule             `json:"first_match"`
	Candidates    []Rule            `json:"candidates"`
	// Doubts names the candidates that set a matching field no stage evaluates.
	Doubts []securitypolicy.Doubt        `json:"doubts"`
	Zones  securitypolicy.ZoneDerivation `json:"zones"`
	Stages []Stage                       `json:"stages"`
}

// securityOf is a security answer. v is nil when the check did not run.
func securityOf(v *securitypolicy.Verdict, verdict string, why simulate.Reasons, rule string, fid simulate.Fidelity, stages []simulate.Stage) Security {
	out := Security{
		Verdict: verdict, Reasons: nonNilReasons(why), Rule: rule, Fidelity: fid, Stages: SimStages(stages),
		Candidates: []Rule{}, Doubts: []securitypolicy.Doubt{},
	}
	// Zones print [] rather than null, as every list of the block does.
	out.Zones.From, out.Zones.To = []string{}, []string{}
	if v == nil {
		return out
	}
	if v.Rule != nil {
		r := ruleOf(*v.Rule)
		out.FirstMatch = &r
	}
	for _, r := range v.Candidates {
		out.Candidates = append(out.Candidates, ruleOf(r))
	}
	if v.Doubts != nil {
		out.Doubts = v.Doubts
	}
	out.Default, out.DefaultAction, out.DefaultSource = v.Default, v.DefaultAction, v.DefaultSource
	out.Zones = v.Zones
	out.Zones.From, out.Zones.To = nonNil(v.Zones.From), nonNil(v.Zones.To)
	return out
}

// SecurityResult is one device and vsys's simulate policy answer on a file. Run,
// Check and From are the native answer, for a renderer.
type SecurityResult struct {
	Security
	Kind      string                   `json:"kind"`
	Relevance securitypolicy.Relevance `json:"relevance"`
	Target    Target                   `json:"target"`

	Run   simulate.Run           `json:"-"`
	Check securitypolicy.Verdict `json:"-"`
	From  estate.Target          `json:"-"`
}

func securityResultOf(run simulate.Run, t estate.Target, v securitypolicy.Verdict) SecurityResult {
	outcome, why := v.Decision()
	var rule string
	if outcome != securitypolicy.Undecided {
		rule = v.Default
		if v.Rule != nil {
			rule = v.Rule.Name
		}
	}
	return SecurityResult{
		Security: securityOf(&v, string(outcome), why, rule, run.Fidelity, run.Stages),
		Kind:     run.Kind, Target: TargetOf(t), Relevance: v.Relevance,
		Run: run, Check: v, From: t,
	}
}
