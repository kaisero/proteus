package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/topology"
)

// policyOptions are simulate policy's flags and arguments.
type policyOptions struct {
	sim      simulate.Simulation
	sel      selection
	fl       flowFlags
	src, dst string
	router   string
	each     bool
}

// policyCmd is simulate policy (spec 2026-10-07 §3). Without --file it answers
// for the estate along the flow's path; --file checks one configuration.
func (a *app) policyCmd(sim simulate.Simulation) *cobra.Command {
	var o policyOptions
	o.sim = sim
	cmd := &cobra.Command{
		Use:   sim.Kind() + " <source> <destination>",
		Short: sim.Describe(),
		Long: "Policy answers whether the estate allows a flow end to end. It traces the path\n" +
			"as simulate routing does, checks the security policy of every firewall and vsys\n" +
			"on it with the zones the path gives, and says allowed, denied or undecided, and\n" +
			"at which hop. The path starts where the source is connected, or where the most\n" +
			"specific route to it leaves; --device names the start instead.\n\n" +
			"--file checks one configuration instead: --vsys picks the vsys, and the zones are\n" +
			"given with --from-zone and --to-zone, or derived from the configuration.\n\n" +
			"Source and destination are an address or an FQDN; an FQDN is resolved with this\n" +
			"machine's DNS unless --no-dns. A path needs an address, so path mode traces the\n" +
			"first IPv4 address an FQDN resolves to.\n\n" +
			"Stages: " + strings.Join(sim.Stages(), ", "),
		Args: args(cobra.ExactArgs(2)),
		RunE: func(c *cobra.Command, argv []string) error {
			o.src, o.dst = argv[0], argv[1]
			path, err := o.pathMode(c)
			if err != nil {
				return err
			}
			if !path {
				return a.emitRun(a.runSimulation(c.Context(), o))
			}
			return a.emitRun(a.runPolicyPath(c.Context(), o))
		},
	}
	f := cmd.Flags()
	f.StringSliceVar(&o.sel.devices, "device", nil, "the firewall the path starts on")
	f.StringVar(&o.router, "router", "", "start in this logical router of --device")
	f.StringVar(&o.sel.at, "at", "", "read each device's newest snapshot at or before this time (id, RFC 3339 or date)")
	f.StringVar(&o.sel.file, "file", "", "check one configuration file instead of the path")
	f.StringSliceVar(&o.sel.vsys, "vsys", nil, "with --file: the vsys to check")
	f.StringArrayVar(&o.sel.labels, "label", nil, "select devices by key=value label (with --each, in a later release)")
	f.BoolVar(&o.each, "each", false, "check every selected firewall on its own (in a later release)")
	o.fl.bindProtocol(cmd)
	o.fl.bindPort(cmd)
	o.fl.bindSourcePort(cmd)
	o.fl.bindZones(cmd)
	o.fl.bindL7(cmd)
	bindWhy(cmd, &o.fl.why)
	bindNoDNS(cmd, &o.fl.noDNS)
	return cmd
}

// oneConfig is the way to the single-configuration check that a path mode
// usage error names.
const oneConfig = "use --file <path> --vsys <name> for one configuration"

// pathMode chooses the mode (spec §3.1): --each first, then --file, else the
// path. A flag the chosen mode does not take is a usage error that names it.
func (o policyOptions) pathMode(c *cobra.Command) (bool, error) {
	given := c.Flags().Changed
	if o.each {
		return false, usageErr("fan-out (--each) arrives in a later release")
	}
	if o.sel.file != "" {
		for _, f := range []string{"device", "label", "at"} {
			if given(f) {
				return false, usageErr("--%s selects from the store; --file reads one configuration", f)
			}
		}
		if given("router") {
			return false, usageErr("--router picks the start router of --device; --file has no path")
		}
		if given("from-zone") != given("to-zone") {
			return false, usageErr("--from-zone and --to-zone go together")
		}
		return false, nil
	}
	for _, f := range [][2]string{{"vsys", "selects a vsys"}, {"label", "selects devices"}} {
		if given(f[0]) {
			return false, usageErr("--%s %s, but path mode checks every firewall and vsys on the path; %s", f[0], f[1], oneConfig)
		}
	}
	for _, f := range []string{"from-zone", "to-zone"} {
		if given(f) {
			return false, usageErr("--%s: the path gives the zones; %s", f, oneConfig)
		}
	}
	if given("router") && len(o.sel.devices) == 0 {
		return false, usageErr("--router needs --device")
	}
	if len(o.sel.devices) > 1 {
		return false, usageErr("path mode starts on one device; --device has %d", len(o.sel.devices))
	}
	return true, nil
}

// device is the start device, or "" to place the start by the source.
func (o policyOptions) device() string {
	if len(o.sel.devices) == 0 {
		return ""
	}
	return o.sel.devices[0]
}

// pathAnswer is simulate policy's answer in path mode: one result, or none when
// the path could not be traced and its holes say why.
type pathAnswer struct {
	o      policyOptions
	flow   simulate.Flow
	res    pathpolicy.Result
	stages []simulate.Stage
	ok     bool
	holes  []estate.Hole
	un     []unresolved
	notes  []note
}

func (a *app) runPolicyPath(ctx context.Context, o policyOptions) (answer, error) {
	flow, err := parseFlow(o.fl)
	if err != nil {
		return nil, err
	}
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	dev := o.device()
	if dev != "" {
		if _, err := s.inv.Select([]string{dev}, nil); err != nil {
			return nil, usageErr("%w", err)
		}
	}
	if flow.Source, err = a.pathEndpoint(ctx, o.src, o.fl.noDNS); err != nil {
		return nil, err
	}
	if flow.Destination, err = a.pathEndpoint(ctx, o.dst, o.fl.noDNS); err != nil {
		return nil, err
	}
	es, err := a.openEstate(s, o.sel.at)
	if err != nil {
		return nil, err
	}
	users, err := a.userSnapshot()
	if err != nil {
		return nil, err
	}
	env := es.env(a)
	env.Load = storeLoader(es.st, es.when, es.network, users)
	if o.fl.noDNS {
		env.Resolve = nil // NAT does not resolve a translated FQDN either
	}
	start := dev
	if start == "" {
		start = "placed by the source " + flow.Source.String()
	}
	a.log.Infof(runlog.TagStep, "policy path %s -> %s, start %s", flow.Source, flow.Destination, start)
	res, stages, err := pathpolicy.Run(ctx, env, simulate.Input{Flow: flow, Params: map[string]string{"device": dev, "router": o.router}})
	ans := pathAnswer{o: o, flow: flow}
	if u, ok := errors.AsType[*simulate.UnavailableError](err); ok {
		for _, m := range u.Missing {
			ans.holes = append(ans.holes, estate.Hole{Device: m.Device, Reason: m.Reason})
		}
		return ans, nil
	}
	if choice, ok := errors.AsType[*simulate.ChoiceError](err); ok {
		// A start only the user can choose: routing's text, and the way forward
		// (spec §3.3).
		if dev == "" && len(choice.Options) > 0 {
			return nil, usageErr("%w; name the start with --device <name>", choice)
		}
		return nil, usageErr("%w", choice)
	}
	if err != nil {
		return nil, err
	}
	ans.res, ans.stages, ans.ok = res, stages, true
	if res.At != nil {
		a.log.Infof(runlog.TagStep, "path verdict: %s at hop %d (%s)", res.Verdict, res.At.Hop, res.At.Check)
	} else {
		a.log.Infof(runlog.TagStep, "path verdict: %s", res.Verdict)
	}
	for _, m := range res.Holes {
		ans.holes = append(ans.holes, estate.Hole{Device: m.Device, Reason: m.Reason})
	}
	ans.un = pathUnresolved(res, stages)
	ans.notes = pathNotes(res)
	return ans, nil
}

// pathEndpoint reads an endpoint for path mode. A path is traced from an
// address, so an FQDN must resolve to an IPv4 one: the first in the resolver's
// order is traced, and moves to the front (spec §3.3).
func (a *app) pathEndpoint(ctx context.Context, s string, noDNS bool) (simulate.Endpoint, error) {
	ep, err := a.endpoint(ctx, s, noDNS)
	if err != nil || ep.Name == "" {
		return ep, err
	}
	for i, ad := range ep.Addrs {
		if ad.Is4() {
			rest := append(append([]netip.Addr{}, ep.Addrs[:i]...), ep.Addrs[i+1:]...)
			ep.Addrs = append([]netip.Addr{ad}, rest...)
			return ep, nil
		}
	}
	return ep, usageErr("path mode needs an address for %s; remove --no-dns or give an address", ep.Name)
}

// pathUnresolved is what leaves a path answer incomplete (spec §5.4): each
// undecided hop, after the deny too, with its device, vsys and reason; a
// routing end that leaves the answer undecided; and the stages' unresolved
// entries.
func pathUnresolved(res pathpolicy.Result, stages []simulate.Stage) []unresolved {
	var un []unresolved
	for _, h := range res.Hops {
		if why, ok := hopUndecided(h); ok {
			un = append(un, unresolved{Device: h.Routing.Device, Vsys: h.Routing.Vsys, Reason: why})
		}
		for _, c := range h.Checks {
			un = append(un, runUnresolved(simulate.Run{Stages: c.Stages}, h.Routing.Device, h.Routing.Vsys, false)...)
		}
	}
	if at := res.At; res.Verdict == pathpolicy.VerdictUndecided && at.Check == "routing" {
		h, _ := pointHop(res)
		un = append(un, unresolved{Device: h.Device, Vsys: h.Vsys, Reason: at.Reason.Text})
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
func hopUndecided(h pathpolicy.Hop) (string, bool) {
	if len(h.Doubts) > 0 {
		return h.Doubts[0].Text, true
	}
	for _, c := range h.Checks {
		if c.Verdict == pathpolicy.Undecided {
			return c.Reason.Text, true
		}
	}
	return "", false
}

func (p pathAnswer) Command() string { return "simulate " + p.o.sim.Kind() }

func (p pathAnswer) Input() any {
	return pathInput{Mode: "path", Flow: p.flow, Device: p.o.device(), Router: p.o.router, At: p.o.sel.at}
}

func (p pathAnswer) Results() any {
	if !p.ok {
		return []pathResult{}
	}
	r, path := p.res, p.res.Path
	out := pathResult{
		Mode: "path", Verdict: string(r.Verdict), Fidelity: r.Fidelity,
		Source: path.Source, Destination: path.Destination, Placed: path.Placed, PlacedVia: path.PlacedVia,
		StartVia: path.StartVia, Outcome: path.Outcome, End: path.End, Hidden: path.Hidden,
		Stages: simStages(p.stages), Hops: []pathHopJSON{},
	}
	if at := r.At; at != nil {
		out.At = &pointJSON{Hop: at.Hop, Check: at.Check, Rule: at.Rule, Reason: at.Reason.Text}
	}
	for _, h := range r.Hops {
		hj := pathHopJSON{
			Index: h.Index, Hop: h.Routing, Notes: nonNil(h.Routing.Notes.Texts()), PBF: nonNil(h.Routing.PBF),
			ECMP: h.Routing.ECMP, ZonePlaceholder: h.Routing.ZonePlaceholder, Doubts: nonNil(h.Doubts.Texts()),
			AfterDeny: h.AfterDeny,
		}
		if hj.ECMP == nil {
			hj.ECMP = []routing.NotFollowed{}
		}
		for _, c := range h.Checks {
			hj.Checks = append(hj.Checks, checkJSON{name: c.Name, block: securityOf(c.Security, string(c.Verdict), c.Reason.Text, c.Rule, c.Fidelity, c.Stages)})
		}
		out.Hops = append(out.Hops, hj)
	}
	return []pathResult{out}
}

func (p pathAnswer) Qualifiers() qualifiers {
	return qualifiers{Holes: p.holes, Unresolved: p.un, Notes: p.notes}
}

// pathNotes are every note the text shows, for the envelope: routing's notes
// on the path and on each hop, each check's target notes, such as a version
// gap, and the answer's own (spec §8.2).
func pathNotes(res pathpolicy.Result) []note {
	var device string
	if len(res.Hops) > 0 {
		device = res.Hops[0].Routing.Device
	}
	var out []note
	out = append(out, runNotes(device, res.Path.Notes.Texts())...)
	for _, h := range res.Hops {
		out = append(out, runNotes(h.Routing.Device, h.Routing.Notes.Texts())...)
		for _, c := range h.Checks {
			for _, n := range c.Notes {
				out = append(out, note{Device: h.Routing.Device, Vsys: h.Routing.Vsys, Note: n})
			}
		}
	}
	out = append(out, runNotes(device, res.Notes.Texts())...)
	seen := map[note]bool{}
	return slices.DeleteFunc(out, func(n note) bool {
		dup := seen[n]
		seen[n] = true
		return dup
	})
}

func (p pathAnswer) Text(t *textOut) error {
	if p.ok {
		p.text(t)
	}
	printQualifiers(t, p.Qualifiers())
	return t.err
}

// text is the path answer (spec §8.1): the verdict line and the notes the
// routing boxes do not show, then the path with a policy row per hop and, with
// --why, each hop's security check.
func (p pathAnswer) text(t *textOut) {
	r := p.res
	fmt.Fprintln(t, verdictLine(t.pal, r))
	for _, h := range r.Hops {
		for _, c := range h.Checks {
			for _, n := range c.Notes {
				fmt.Fprintf(t, "  %s\n", noteStyle(t.pal, n)(fmt.Sprintf("note: %s / %s: %s", h.Routing.Device, h.Routing.Vsys, n)))
			}
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(t, "  %s\n", noteStyle(t.pal, n.Text)("note: "+n.Text))
	}
	fmt.Fprintln(t)
	title := fmt.Sprintf("simulate policy %s -> %s %s", sourceText(r.Path), r.Path.Destination, p.flow.Protocol)
	if p.flow.DestPort != 0 {
		title += fmt.Sprintf("/%d", p.flow.DestPort)
	}
	renderPath(t, title, simulate.Run{Fidelity: r.Fidelity, Stages: p.stages}, r.Path, t.now, p.o.fl.why,
		func(i int) [][2]string { return policyRows(r.Hops[i]) })
	if !p.o.fl.why {
		return
	}
	for _, h := range r.Hops {
		for _, c := range h.Checks {
			fmt.Fprintf(t, "\nhop %d: %s / %s, %s %s", h.Index, h.Routing.Device, h.Routing.Vsys, c.Name, c.Verdict)
			if c.Reason.Text != "" {
				fmt.Fprintf(t, ": %s", c.Reason.Text)
			}
			fmt.Fprintf(t, "\n")
			if c.Security != nil {
				printCandidates(t, *c.Security, true)
				printStageTable(t, c.Stages)
			}
		}
	}
}

// policyRows are a hop's extra box rows: what each check concluded, then why
// the path or the zones leave the hop undecided.
func policyRows(h pathpolicy.Hop) [][2]string {
	var rows [][2]string
	for _, c := range h.Checks {
		var s string
		switch c.Verdict {
		case pathpolicy.Pass, pathpolicy.Stop:
			s = fmt.Sprintf("%s (%s)", c.Rule, checkAction(c))
		case pathpolicy.Undecided:
			s = "undecided: " + c.Reason.Text
		default:
			s = "not evaluated: " + c.Reason.Text
		}
		if h.AfterDeny {
			s += " (after the deny)"
		}
		label := c.Name
		if c.Name == "security" {
			label = "policy"
		}
		rows = append(rows, [2]string{label, s})
	}
	for _, d := range h.Doubts {
		rows = append(rows, [2]string{"doubt", d.Text})
	}
	return rows
}

// verdictLine is the answer's first line, coloured by the verdict (spec §8.1).
func verdictLine(pal palette, r pathpolicy.Result) string {
	if r.At == nil {
		return pal.ok(string(r.Verdict))
	}
	h, ok := pointHop(r)
	at := fmt.Sprintf("%s at hop %d: ", r.Verdict, r.At.Hop)
	switch {
	case !ok:
		return pal.warn(at + r.At.Reason.Text)
	case r.Verdict == pathpolicy.VerdictUndecided:
		return pal.warn(at + fmt.Sprintf("%s / %s, %s", h.Device, h.Vsys, r.At.Reason.Text))
	case r.At.Check == "routing":
		// The address the hop looked up: after a destination NAT, the
		// translated one.
		dst := h.Flow.Destination
		if h.PostNAT != nil {
			dst = h.PostNAT.Destination
		}
		return pal.bad(at + fmt.Sprintf("no route to %s on %s", dst, h.Device))
	}
	var action string
	for _, c := range r.Hops[r.At.Hop-1].Checks {
		if c.Name == r.At.Check {
			action = checkAction(c)
		}
	}
	return pal.bad(at + fmt.Sprintf("%s / %s, rule %s (%s)", h.Device, h.Vsys, r.At.Rule, action))
}

// pointHop is the routing hop the verdict's point names; false for a path
// without that hop.
func pointHop(r pathpolicy.Result) (routing.Hop, bool) {
	if r.At == nil || r.At.Hop < 1 || r.At.Hop > len(r.Hops) {
		return routing.Hop{}, false
	}
	return r.Hops[r.At.Hop-1].Routing, true
}

// checkAction is the action of the rule, or default rule, that decided a
// check.
func checkAction(c pathpolicy.CheckResult) string {
	switch v := c.Security; {
	case v == nil:
		return ""
	case v.Rule != nil:
		return v.Rule.Action
	}
	return c.Security.DefaultAction
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// pathInput is the input block in path mode (spec §8.2).
type pathInput struct {
	Mode   string        `json:"mode"`
	Flow   simulate.Flow `json:"flow"`
	Device string        `json:"device"`
	Router string        `json:"router"`
	At     string        `json:"at"`
}

// pathResult is simulate policy's result in path mode: the verdict and where it
// was decided, routing's path fields, and the hops with their checks.
type pathResult struct {
	Mode        string            `json:"mode"`
	Verdict     string            `json:"verdict"`
	At          *pointJSON        `json:"at"`
	Fidelity    simulate.Fidelity `json:"fidelity"`
	Source      simulate.Endpoint `json:"source"`
	Destination simulate.Endpoint `json:"destination"`
	Placed      topology.Placed   `json:"placed"`
	PlacedVia   string            `json:"placed_via,omitempty"`
	StartVia    netip.Prefix      `json:"start_via,omitzero"`
	Outcome     routing.Outcome   `json:"outcome"`
	End         string            `json:"end"`
	Hidden      []string          `json:"hidden,omitempty"`
	Stages      []stageJSON       `json:"stages"`
	Hops        []pathHopJSON     `json:"hops"`
}

// pointJSON is where the verdict was decided, or became undecided.
type pointJSON struct {
	Hop    int    `json:"hop"`
	Check  string `json:"check"`
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// pathHopJSON is one hop: routing's keys, with its notes, PBF rules, ECMP next
// hops and placeholder flag present even when empty, then what the path mode
// adds. A field declared here wins over routing.Hop's field of the same key.
type pathHopJSON struct {
	Index int `json:"index"`
	routing.Hop
	Notes           []string              `json:"notes"`
	PBF             []string              `json:"pbf"`
	ECMP            []routing.NotFollowed `json:"ecmp_not_followed"`
	ZonePlaceholder bool                  `json:"zone_placeholder"`
	Doubts          []string              `json:"doubts"`
	AfterDeny       bool                  `json:"after_deny"`
	Checks          checksJSON            `json:"checks"`
}

// checkJSON is one check's answer under its name.
type checkJSON struct {
	name  string
	block securityJSON
}

// checksJSON is a hop's checks as one JSON object, its keys in check order.
type checksJSON []checkJSON

// MarshalJSON writes {"security": {...}, ...} in list order; a map would sort
// the keys.
func (cs checksJSON) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, c := range cs {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(c.name)
		if err != nil {
			return nil, err
		}
		v, err := json.Marshal(c.block)
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
