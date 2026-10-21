package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/kaisero/proteus/internal/estate"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/runlog"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/pathpolicy"
	"github.com/kaisero/proteus/internal/simulate/routing"
	"github.com/kaisero/proteus/internal/simulate/rulebase"
	"github.com/kaisero/proteus/internal/simulate/securitypolicy"
	"github.com/kaisero/proteus/internal/simulate/topology"
)

// policyCommand is simulate policy's command name.
const policyCommand = "simulate " + securitypolicy.Kind

// oneConfig is the way to the single-configuration check that a path mode
// usage error names.
const oneConfig = "use --file <path> --vsys <name> for one configuration"

// PolicyInput is simulate policy along the flow's path (spec 2026-10-07 §3).
type PolicyInput struct {
	Flow FlowInput `json:"flow" jsonschema:"the flow to check"`
	// Device is the firewall the path starts on; "" places the start by the
	// source. Router picks its logical router.
	Device string `json:"device,omitempty" jsonschema:"the firewall the path starts on; empty places the start by the source"`
	Router string `json:"router,omitempty" jsonschema:"the start's logical router; needs device"`
	// At reads each device's newest snapshot at or before this time.
	At string `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time (RFC 3339 or a date); empty for the latest"`
	// Vsys and Label select for one configuration; path mode refuses them,
	// because it checks every firewall and vsys on the path.
	Vsys  []string `json:"vsys,omitempty" jsonschema:"refused: path mode checks every vsys on the path"`
	Label []string `json:"label,omitempty" jsonschema:"refused: path mode checks every firewall on the path"`
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
	Flow FlowInput `json:"flow" jsonschema:"the flow to check"`
	// Selection names the file and its vsys. The store's selectors are refused.
	Selection Selection `json:"selection" jsonschema:"the configuration file and its vsys"`
	// Router is refused: a file has no path to start.
	Router string `json:"router,omitempty" jsonschema:"the logical router whose forwarding table derives the zones"`
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
	sim := es.simEnv(env)
	sim.Load = storeLoader(es.st, es.when, es.network, flow.Application != "", flow.User != "")
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
	e.Read = es.network.Read()
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
	e.Results[0].Needs = pathNeeds(flow, res)
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
	ts, zoneHoles, u := givenZones(ts, flow)
	if u != nil {
		return none, u
	}
	e.Holes = append(e.Holes, zoneHoles...)
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
	withApps := flow.Application != ""
	sim, err := fileEnv(env, t, in.Flow.NoDNS, withApps, flow.User != "")
	if err != nil {
		return none, err
	}
	env.Log.Infof(runlog.TagStep, "%s %s -> %s on %s/%s", securitypolicy.Kind, flow.Source, flow.Destination, t.Device, t.Vsys)
	// The first address of each endpoint is checked, as path mode checks it
	// (spec 2026-10-07 D1b); a note names the others.
	run, err := securitypolicy.Simulation{}.Run(ctx, sim, simulate.Input{Flow: flow.FirstAddresses(), Device: t.Device, Vsys: t.Vsys})
	if c, ok := errors.AsType[*simulate.ChoiceError](err); ok && c.Kind == simulate.ChoiceApplication {
		// A container or an unknown name: the user names another (spec
		// 2026-10-16 P10, D13). The texts end with the suggestions.
		return none, usageOf(err, c.Question, c.ToolText)
	}
	if err != nil {
		return none, err
	}
	env.Log.Infof(runlog.TagStep, "%s: fidelity %s", securitypolicy.Kind, run.Fidelity)
	v, _ := run.Output.(securitypolicy.Verdict)
	if !withApps {
		// No data is loaded without an application (D11); the needs ask for
		// one only when a file beside could decide it (C8).
		v.AppData = hasAppFile(t)
	}
	e.Results = []SecurityResult{securityResultOf(run, t, v)}
	e.Results[0].Needs = securityNeeds(flow, e.Results[0].Verdict, &v, run.Fidelity)
	e.Targets, e.Read = ts, readOf(ts)
	// The run's notes are the target's and the run's own, such as the
	// application data's.
	for _, n := range run.Notes {
		e.Notes = append(e.Notes, NoteOf(t.Device, t.Vsys, n))
	}
	for _, n := range simulate.DNSNotes(flow, "checked") {
		e.Notes = append(e.Notes, NoteOf(t.Device, t.Vsys, n))
	}
	e.Unresolved = dedupeUnresolved(runUnresolved(run, t.Device, t.Vsys, true))
	return e, nil
}

// givenZones keeps the targets that define the flow's given zones (C15). A
// target without one is a hole; when no target defines them, the question is a
// usage error that names, per vsys, the zone it lacks and the zones it has.
func givenZones(ts []estate.Target, flow simulate.Flow) ([]estate.Target, []estate.Hole, *UsageError) {
	var kept []estate.Target
	var holes []estate.Hole
	var texts, toolTexts []string
	for _, t := range ts {
		r := rulebase.UndefinedZones(t.Config, t.Scope, flow.FromZone, flow.ToZone)
		if r == nil {
			kept = append(kept, t)
			continue
		}
		texts, toolTexts = append(texts, r.Choice.Question), append(toolTexts, r.Choice.ToolText)
		holes = append(holes, estate.NewHole(t.Device, t.Vsys, reason.New("zone.undefined", "not checked: "+r.Text)))
	}
	switch {
	case len(kept) > 0 || len(texts) == 0:
		return kept, holes, nil
	case len(texts) == 1:
		return nil, nil, usage(texts[0], toolTexts[0])
	}
	const lead = "no selected vsys defines the given zones: "
	return nil, nil, usage(lead+strings.Join(texts, "; "), lead+strings.Join(toolTexts, "; "))
}

// fileEnv is the simulation environment for one target read from a file: its
// configuration and its index. A file has no stored tables, so zones derive
// from the configuration. With withApps, the target carries the App-ID
// content data beside the file and the notes of appsOf (spec 2026-10-16 §6).
// With withUser, or a rule of the vsys that names a user, it carries the
// identity data beside the file and the notes of identityFor (spec 2026-10-17
// §4.2, §7).
func fileEnv(env Env, t estate.Target, noDNS, withApps, withUser bool) (*simulate.Env, error) {
	set := index.NewSet(t.Config)
	idx, err := set.Index(t.Scope, resolve.Security)
	if err != nil {
		return nil, err
	}
	var providers index.Providers
	notes := t.Notes
	if withApps {
		var more simulate.Reasons
		providers.Apps, more = appsOf(t)
		notes = append(slices.Clone(notes), more...)
	}
	if withUser || namesUser(idx.Rules()) {
		var more simulate.Reasons
		providers.Users, more = identityFor(t, env.MaxAge, env.now())
		notes = append(slices.Clone(notes), more...)
	}
	sim := &simulate.Env{Log: env.Log, Load: func(string, string) (simulate.Target, error) {
		return simulate.Target{
			Config: t.Config, Indexes: set.Provider(t.Scope),
			Providers: providers, Notes: notes,
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

// nonNil is s, or an empty slice for nil, so JSON prints [] (spec U5).
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// PathResult is simulate policy's result in path mode: the verdict and where it
// was decided, routing's path fields, and the hops with their checks. Result
// and RunStages are the native answer, for a renderer.
type PathResult struct {
	Answer      string            `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Needs       []Need            `json:"needs,omitzero" jsonschema:"present when the result is held back: the inputs a second call can give to change it; empty when none helps"`
	Mode        string            `json:"mode" jsonschema:"path: the flow is checked on every firewall it crosses"`
	Verdict     string            `json:"verdict" jsonschema:"allowed, denied, undecided or another path verdict; undecided means the answer cannot say"`
	At          *Point            `json:"at" jsonschema:"where the verdict was decided or became undecided; null when no check decided"`
	Fidelity    simulate.Fidelity `json:"fidelity" jsonschema:"how certain the result is: exact, overmatch, inferred or undermatch, with the reasons; never report undermatch or inferred as a firm answer"`
	Source      simulate.Endpoint `json:"source" jsonschema:"the source endpoint as simulated"`
	Destination simulate.Endpoint `json:"destination" jsonschema:"the destination endpoint as simulated"`
	Placed      topology.Placed   `json:"placed" jsonschema:"how the path's start was placed"`
	PlacedVia   string            `json:"placed_via,omitempty" jsonschema:"the route or interface that placed the start"`
	StartVia    netip.Prefix      `json:"start_via,omitzero" jsonschema:"the prefix that placed the start"`
	Outcome     routing.Outcome   `json:"outcome" jsonschema:"how the path ended"`
	End         string            `json:"end" jsonschema:"where and why the path ended, in words"`
	EndCode     reason.Code       `json:"end_code" jsonschema:"the reason code of the path end"`
	Hidden      []string          `json:"hidden,omitempty" jsonschema:"firewalls the path crossed that the inventory does not hold"`
	Stages      []Stage           `json:"stages" jsonschema:"the run's stages: what each one did, its fidelity and its candidate count"`
	Hops        []PathHop         `json:"hops" jsonschema:"the firewalls the path crossed, in order"`

	Result    pathpolicy.Result `json:"-"`
	RunStages []simulate.Stage  `json:"-"`
}

// Point is where the verdict was decided, or became undecided, and why: one
// reason, or the parts of a composite one, each with its code.
type Point struct {
	Hop     int              `json:"hop" jsonschema:"the hop index"`
	Check   string           `json:"check" jsonschema:"the check that decided"`
	Rule    string           `json:"rule" jsonschema:"the deciding rule"`
	Reasons simulate.Reasons `json:"reasons" jsonschema:"why, each reason with its code"`
}

// PathHop is one hop: routing's keys, with its notes, PBF rules, ECMP next
// hops and placeholder flag present even when empty, then what the path mode
// adds. A field declared here wins over routing.Hop's field of the same key.
type PathHop struct {
	Index int `json:"index" jsonschema:"the hop's place on the path"`
	routing.Hop
	Notes           simulate.Reasons      `json:"notes" jsonschema:"notes on the hop, each with its code"`
	PBF             []string              `json:"pbf" jsonschema:"policy-based forwarding rules that applied"`
	ECMP            []routing.NotFollowed `json:"ecmp_not_followed" jsonschema:"equal-cost next hops the path did not follow"`
	ZonePlaceholder bool                  `json:"zone_placeholder" jsonschema:"whether the zones are placeholders"`
	Doubts          simulate.Reasons      `json:"doubts" jsonschema:"doubts on the hop, each with its code"`
	AfterDeny       bool                  `json:"after_deny" jsonschema:"whether the hop comes after a deny, checked only to show the rest of the path"`
	Checks          Checks                `json:"checks" jsonschema:"each check's answer under its name, such as security"`
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
		Answer: PathAnswer(r), Mode: "path", Verdict: string(r.Verdict), Fidelity: r.Fidelity,
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
	Position int    `json:"position" jsonschema:"the rule's position in the effective order"`
	Name     string `json:"name" jsonschema:"the rule name"`
	Action   string `json:"action" jsonschema:"the rule's action"`
	Layer    string `json:"layer" jsonschema:"the rulebase layer: pre, local or post"`
	Scope    string `json:"scope" jsonschema:"the scope the rule comes from"`
}

func ruleOf(r resolve.Rule) Rule {
	return Rule{r.Position, r.Name, r.Action, r.Layer.String(), r.Scope.String()}
}

// Security is a security check's answer: one type for a file target and for
// each hop of a path (spec 2026-10-07 E14, §8.2).
type Security struct {
	// Verdict is pass, stop, undecided or, on a hop, not-evaluated; Reasons say
	// why (spec 2026-10-07 §4.7): one reason, or a composite one's parts.
	Verdict string           `json:"verdict" jsonschema:"pass, stop, undecided or, on a hop, not-evaluated"`
	Reasons simulate.Reasons `json:"reasons" jsonschema:"why, each reason with its code"`
	// Rule is the rule or default rule that decides; empty when undecided.
	Rule string `json:"rule" jsonschema:"the rule or default rule that decides; empty when undecided"`
	// Default is the default rule that decides when no rule matches, empty when
	// none does; DefaultSource says where its action came from.
	Default       string            `json:"default" jsonschema:"the default rule that decides when no rule matches; empty when none does"`
	DefaultAction string            `json:"default_action" jsonschema:"the default rule's action"`
	DefaultSource string            `json:"default_source" jsonschema:"where the default action came from: built-in, local or pushed"`
	Fidelity      simulate.Fidelity `json:"fidelity" jsonschema:"how certain the result is: exact, overmatch, inferred or undermatch, with the reasons; never report undermatch or inferred as a firm answer"`
	FirstMatch    *Rule             `json:"first_match" jsonschema:"the first certain match; null when none"`
	// Implicit is set when FirstMatch matches the flow's application only
	// through the implicit use of the rule's applications (spec 2026-10-16 I1).
	Implicit   *securitypolicy.Implicit `json:"implicit,omitempty" jsonschema:"set when the rule matches only through implicit use"`
	Candidates []Rule                   `json:"candidates" jsonschema:"the rules that may match the flow, in order"`
	// Doubts names the candidates that set a matching field no stage evaluates.
	Doubts []securitypolicy.Doubt        `json:"doubts" jsonschema:"rules that may match first, with the reasons the answer cannot rule them out"`
	Zones  securitypolicy.ZoneDerivation `json:"zones" jsonschema:"the zones used and where they came from"`
	// User is set when the target has identity data (spec 2026-10-17 §5.1).
	User   *securitypolicy.FlowUser `json:"user,omitempty" jsonschema:"the flow's user and where it came from: the mapping of the source address or the user given"`
	Stages []Stage                  `json:"stages" jsonschema:"the run's stages: what each one did, its fidelity and its candidate count"`
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
	out.Implicit = v.Implicit
	for _, r := range v.Candidates {
		out.Candidates = append(out.Candidates, ruleOf(r))
	}
	if v.Doubts != nil {
		out.Doubts = v.Doubts
	}
	out.Default, out.DefaultAction, out.DefaultSource = v.Default, v.DefaultAction, v.DefaultSource
	out.Zones = v.Zones
	out.Zones.From, out.Zones.To = nonNil(v.Zones.From), nonNil(v.Zones.To)
	out.User = v.User
	return out
}

// SecurityResult is one device and vsys's simulate policy answer on a file. Run,
// Check and From are the native answer, for a renderer.
type SecurityResult struct {
	Answer string `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Needs  []Need `json:"needs,omitzero" jsonschema:"present when the result is held back: the inputs a second call can give to change it; empty when none helps"`
	Security
	Kind      string                   `json:"kind" jsonschema:"the question kind: policy"`
	Relevance securitypolicy.Relevance `json:"relevance" jsonschema:"whether the device routes either endpoint by more than a default route"`
	Target    Target                   `json:"target" jsonschema:"the device, vsys and snapshot the result came from"`

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
		Answer:   FileAnswer(v),
		Security: securityOf(&v, string(outcome), why, rule, run.Fidelity, run.Stages),
		Kind:     run.Kind, Target: TargetOf(t), Relevance: v.Relevance,
		Run: run, Check: v, From: t,
	}
}
