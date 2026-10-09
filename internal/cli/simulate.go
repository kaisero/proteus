package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// flowFlags are the flow of spec §11.3 as flags (spec §15 C12).
type flowFlags struct {
	protocol, port, application, user, url string
	sourcePort                             int
	fromZone, toZone                       string
	why, noDNS                             bool
}

// kindCommands builds each registered simulation kind's command: each kind's
// flags differ, so each has a builder of its own.
var kindCommands = map[string]func(*app, simulate.Simulation) *cobra.Command{
	securitypolicy.Kind: (*app).policyCmd,
	routing.Kind:        (*app).routingCmd,
	nat.Kind:            (*app).natCmd,
}

// simulateCmds returns one subcommand per registered simulation kind.
func (a *app) simulateCmds() []*cobra.Command {
	var out []*cobra.Command
	for _, kind := range estate.Kinds() {
		out = append(out, kindCommands[kind](a, estate.Simulations[kind]))
	}
	return out
}

// policyAnswer is simulate policy's answer: one result when a target could be read,
// none when the selection resolved to nothing but holes.
type policyAnswer struct {
	o       policyOptions
	flow    simulate.Flow
	run     simulate.Run
	target  *estate.Target // nil when no target could be read
	verdict securitypolicy.Verdict
	holes   []estate.Hole
	un      []unresolved
	notes   []note
}

// runSimulation is simulate policy on one configuration file (--file): one
// target, its zones given or derived from the configuration.
func (a *app) runSimulation(ctx context.Context, o policyOptions) (answer, error) {
	flow, err := parseFlow(o.fl)
	if err != nil {
		return nil, err
	}
	s, err := a.settings(false)
	if err != nil {
		return nil, err
	}
	// An FQDN that resolves to no address is simulated: FQDN objects still match,
	// and the answer says it may miss rules.
	if flow.Source, err = a.endpoint(ctx, o.src, o.fl.noDNS); err != nil {
		return nil, err
	}
	if flow.Destination, err = a.endpoint(ctx, o.dst, o.fl.noDNS); err != nil {
		return nil, err
	}
	ans := policyAnswer{o: o, flow: flow}
	ts, holes, err := a.targets(ctx, o.sel, s)
	if err != nil {
		return nil, err
	}
	ans.holes = holes
	switch {
	case len(ts) == 0 && len(holes) > 0:
		return ans, nil // the holes say what is missing
	case len(ts) == 0:
		return nil, errors.New("the selection has no device and vsys to simulate on")
	case len(ts) > 1:
		return nil, usageErr("the file has %d vsys; select one with --vsys", len(ts))
	}
	t := ts[0]
	env, err := a.policyEnv(t, o.fl.noDNS)
	if err != nil {
		return nil, err
	}
	a.log.Infof(runlog.TagStep, "%s %s -> %s on %s/%s", o.sim.Kind(), flow.Source, flow.Destination, t.Device, t.Vsys)
	run, err := o.sim.Run(ctx, env, simulate.Input{Flow: flow, Device: t.Device, Vsys: t.Vsys})
	if err != nil {
		return nil, err
	}
	a.log.Infof(runlog.TagStep, "%s: fidelity %s", o.sim.Kind(), run.Fidelity)
	ans.run, ans.target = run, &t
	ans.verdict, _ = run.Output.(securitypolicy.Verdict)
	ans.notes = policyNotes(t)
	ans.un = dedupeUnresolved(runUnresolved(run, t.Device, t.Vsys, true))
	return ans, nil
}

func (p policyAnswer) Command() string { return "simulate " + p.o.sim.Kind() }
func (p policyAnswer) Input() any      { return policyInput{Flow: p.flow, Selection: p.o.sel.input()} }

func (p policyAnswer) Results() any {
	if p.target == nil {
		return []policyResult{}
	}
	return []policyResult{runJSON(p.run, *p.target, p.verdict)}
}

func (p policyAnswer) Qualifiers() qualifiers {
	return qualifiers{Holes: p.holes, Unresolved: p.un, Notes: p.notes}
}

func (p policyAnswer) Text(t *textOut) error {
	if p.target == nil {
		printQualifiers(t, p.Qualifiers())
		fmt.Fprintln(t, "no device and vsys to simulate on")
		return t.err
	}
	printRun(t, p.run, *p.target, p.verdict, p.flow, p.o.fl.why)
	printQualifiers(t, p.Qualifiers())
	// Behind candidates in doubt, the first match is only the first certain one.
	lead := "first match:"
	if p.verdict.Undecided.Text != "" {
		lead = "first certain match:"
	}
	switch v := p.verdict; {
	case v.Rule != nil:
		fmt.Fprintf(t, "%s %s (%s)\n", lead, t.pal.accent(v.Rule.Name), v.Rule.Action)
	case v.Default != "":
		fmt.Fprintf(t, "%s %s (%s), default rule (%s)\n", lead, t.pal.accent(v.Default), v.DefaultAction, v.DefaultSource)
	case len(v.Candidates) == 0:
		fmt.Fprintln(t, "no enabled rule matches")
	}
	if v := p.verdict; v.Undecided.Text != "" {
		fmt.Fprintf(t, "%s %s\n", t.pal.warn("undecided:"), v.Undecided.Text)
	}
	return t.err
}

// policyNotes are a target's notes. A version gap is one of them, not an
// unresolved entry: the security check lowers its fidelity to inferred instead
// (spec E25).
func policyNotes(t estate.Target) []note {
	var out []note
	for _, n := range t.Notes {
		out = append(out, noteOf(t.Device, t.Vsys, n))
	}
	return out
}

// policyEnv is the simulation environment for one target read from a file: its
// configuration and the user provider. A file has no stored tables, so zones
// derive from the configuration.
func (a *app) policyEnv(t estate.Target, noDNS bool) (*simulate.Env, error) {
	users, err := a.userSnapshot()
	if err != nil {
		return nil, err
	}
	set := index.NewSet(t.Config)
	env := &simulate.Env{Log: a.log, Load: func(string, string) (simulate.Target, error) {
		// Built here, so a failed build is the load's error.
		if _, err := set.Index(t.Scope, resolve.Security); err != nil {
			return simulate.Target{}, err
		}
		return simulate.Target{
			Config: t.Config, Indexes: set.Provider(t.Scope),
			Providers: index.Providers{Users: users}, Notes: t.Notes,
		}, nil
	}, Resolve: a.lookup}
	if noDNS {
		env.Resolve = nil
	}
	return env, nil
}

// parseFlow reads the flow flags. --port takes 443 or tcp/443.
func parseFlow(fl flowFlags) (simulate.Flow, error) {
	f := simulate.Flow{
		Protocol: strings.ToLower(fl.protocol), Application: fl.application, User: fl.user,
		URL: fl.url, FromZone: fl.fromZone, ToZone: fl.toZone,
	}
	if fl.sourcePort < 0 || fl.sourcePort > 65535 {
		return f, usageErr("--source-port %d is not a port", fl.sourcePort)
	}
	f.SourcePort = uint16(fl.sourcePort) //nolint:gosec // G115: range checked above
	if fl.port == "" {
		return f, nil
	}
	port := fl.port
	if proto, p, ok := strings.Cut(fl.port, "/"); ok {
		f.Protocol, port = strings.ToLower(proto), p
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return f, usageErr("--port %q: want 443 or tcp/443", fl.port)
	}
	f.DestPort = uint16(n)
	return f, nil
}

// endpoint reads a source or destination: an address, or an FQDN resolved with
// this machine's DNS. A network is not an endpoint.
func (a *app) endpoint(ctx context.Context, s string, noDNS bool) (simulate.Endpoint, error) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return simulate.Addr(addr), nil
	}
	if len(index.PrefixesOf(s)) > 0 {
		return simulate.Endpoint{}, usageErr("%q is a network, not an endpoint; simulate one address", s)
	}
	if !strings.Contains(s, ".") {
		return simulate.Endpoint{}, usageErr("%q is neither an address nor an FQDN", s)
	}
	ep := simulate.Endpoint{Name: strings.ToLower(s)}
	if noDNS {
		a.log.Infof(runlog.TagRun, "dns: %s not resolved (--no-dns)", ep.Name)
		return ep, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := a.lookup(ctx, ep.Name)
	if err != nil {
		a.log.Warnf(runlog.TagRun, "dns: %s: %v", ep.Name, err)
		return ep, nil
	}
	for _, ad := range addrs {
		ep.Addrs = append(ep.Addrs, ad.Unmap())
	}
	ep.Resolved = len(ep.Addrs) > 0
	a.log.Infof(runlog.TagRun, "dns: %s -> %v", ep.Name, ep.Addrs)
	return ep, nil
}

// lookupDNS resolves a name with this machine's resolver.
func lookupDNS(ctx context.Context, name string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", name)
}

func printRun(w *textOut, run simulate.Run, t estate.Target, v securitypolicy.Verdict, flow simulate.Flow, why bool) {
	fmt.Fprintf(w, "%s -> %s %s", flow.Source, flow.Destination, flow.Protocol)
	if flow.DestPort != 0 {
		fmt.Fprintf(w, "/%d", flow.DestPort)
	}
	if flow.URL != "" {
		fmt.Fprintf(w, " %s", flow.URL)
	}
	fmt.Fprintf(w, "\n%s\n", w.pal.head(header(t, w.now)))
	printNotes(w, t)
	for _, n := range t.Notes {
		if n.Code == "gap.version" {
			fmt.Fprintf(w, "  %s\n", noteStyle(w.pal, n)("note: "+n.Text))
		}
	}
	for _, ep := range []simulate.Endpoint{flow.Source, flow.Destination} {
		if ep.Name != "" {
			fmt.Fprintf(w, "  dns        %s -> %v\n", ep.Name, ep.Addrs)
		}
	}
	zones := "not evaluated"
	if v.Zones.Source != "not evaluated" && (len(v.Zones.From) > 0 || len(v.Zones.To) > 0) {
		zones = fmt.Sprintf("from %s, to %s (%s)", orAny(v.Zones.From), orAny(v.Zones.To), v.Zones.Source)
	}
	fmt.Fprintf(w, "  zones      %s\n", zones)
	switch {
	case !v.Relevance.Known:
		fmt.Fprintf(w, "  relevance  unknown: %s\n", v.Relevance.Reason.Text)
	case v.Relevance.Relevant:
		fmt.Fprintf(w, "  relevant   %s\n", v.Relevance.Reason.Text)
	default:
		fmt.Fprintf(w, "  relevance  not relevant: %s\n", v.Relevance.Reason.Text)
	}
	fmt.Fprintf(w, "  fidelity   %s\n", run.Fidelity)
	if why {
		printStageTable(w, run.Stages)
	}
	printCandidates(w, v, why)
}

// printStageTable lists a security run's stages: level, candidates left, detail.
func printStageTable(w *textOut, stages []simulate.Stage) {
	var tb table
	for _, st := range stages {
		lvl := st.Fidelity.Level()
		tb.row(plain(st.Slug), cell{text: lvl, style: fidelityStyle(w.pal, lvl)},
			plain(fmt.Sprintf("%d", st.State.Candidates)), plain(st.Detail))
	}
	_ = tb.write(w, "  ", 1)
}

// printCandidates lists a verdict's candidates in rule order; with why, each
// one's doubts and then the default rule that follows them.
func printCandidates(w *textOut, v securitypolicy.Verdict, why bool) {
	var tb table
	for _, r := range v.Candidates {
		action := cell{text: r.Action, style: w.pal.bad}
		if r.Action == "allow" {
			action.style = w.pal.ok
		}
		tb.row(plain(fmt.Sprintf("%d.", r.Position)), plain(r.Name), action, plain(fmt.Sprintf("[%s %s]", r.Layer, r.Scope)))
		if !why {
			continue
		}
		for _, d := range v.Doubts {
			if d.Position == r.Position {
				tb.row(plain(""), cell{text: "doubt: " + d.Text(), style: w.pal.warn})
			}
		}
	}
	// The default rules follow the last candidate in evaluation order (spec §4.6).
	if why && v.Default != "" {
		action := cell{text: v.DefaultAction, style: w.pal.bad}
		if v.DefaultAction == "allow" {
			action.style = w.pal.ok
		}
		tb.row(plain("-"), plain(v.Default), action, plain(fmt.Sprintf("[default %s]", v.DefaultSource)))
	}
	_ = tb.write(w, "  ", 1)
}

// fidelityStyle is the palette role for a fidelity level: exact is ok, overmatch
// is warn, undermatch is bad. Inferred and undeclared print plain (nil).
func fidelityStyle(pal palette, level string) func(string) string {
	switch level {
	case "exact":
		return pal.ok
	case "overmatch":
		return pal.warn
	case "undermatch":
		return pal.bad
	}
	return nil
}

// styledLevel is a fidelity level styled by fidelityStyle, or the level itself
// when no role applies.
func styledLevel(pal palette, level string) string {
	if f := fidelityStyle(pal, level); f != nil {
		return f(level)
	}
	return level
}

func orAny(zs []string) string {
	if len(zs) == 0 {
		return "any"
	}
	return strings.Join(zs, "/")
}

// ruleJSON is a rule in a simulation's JSON output.
type ruleJSON struct {
	Position int    `json:"position"`
	Name     string `json:"name"`
	Action   string `json:"action"`
	Layer    string `json:"layer"`
	Scope    string `json:"scope"`
}

func toRuleJSON(r resolve.Rule) ruleJSON {
	return ruleJSON{r.Position, r.Name, r.Action, r.Layer.String(), r.Scope.String()}
}

// securityJSON is a security check's answer: one type for a --file target and
// for each hop of a path (spec 2026-10-07 E14, §8.2).
type securityJSON struct {
	// Verdict is pass, stop, undecided or, on a hop, not-evaluated; Reason says
	// why (spec §4.7).
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
	// Rule is the rule or default rule that decides; empty when undecided.
	Rule string `json:"rule"`
	// Default is the default rule that decides when no rule matches, empty when
	// none does; DefaultSource says where its action came from.
	Default       string            `json:"default"`
	DefaultAction string            `json:"default_action"`
	DefaultSource string            `json:"default_source"`
	Fidelity      simulate.Fidelity `json:"fidelity"`
	FirstMatch    *ruleJSON         `json:"first_match"`
	Candidates    []ruleJSON        `json:"candidates"`
	// Doubts names the candidates that set a matching field no stage evaluates.
	Doubts []securitypolicy.Doubt        `json:"doubts"`
	Zones  securitypolicy.ZoneDerivation `json:"zones"`
	Stages []stageJSON                   `json:"stages"`
}

// securityOf is a security answer's JSON. v is nil when the check did not run.
func securityOf(v *securitypolicy.Verdict, verdict, reason, rule string, fid simulate.Fidelity, stages []simulate.Stage) securityJSON {
	out := securityJSON{
		Verdict: verdict, Reason: reason, Rule: rule, Fidelity: fid, Stages: simStages(stages),
		Candidates: []ruleJSON{}, Doubts: []securitypolicy.Doubt{},
	}
	// Zones print [] rather than null, as every list of the block does.
	out.Zones.From, out.Zones.To = []string{}, []string{}
	if v == nil {
		return out
	}
	if v.Rule != nil {
		r := toRuleJSON(*v.Rule)
		out.FirstMatch = &r
	}
	for _, r := range v.Candidates {
		out.Candidates = append(out.Candidates, toRuleJSON(r))
	}
	if v.Doubts != nil {
		out.Doubts = v.Doubts
	}
	out.Default, out.DefaultAction, out.DefaultSource = v.Default, v.DefaultAction, v.DefaultSource
	out.Zones = v.Zones
	out.Zones.From, out.Zones.To = nonNil(v.Zones.From), nonNil(v.Zones.To)
	return out
}

// policyResult is one device and vsys's simulate policy answer in the JSON envelope.
type policyResult struct {
	securityJSON
	Kind      string                   `json:"kind"`
	Relevance securitypolicy.Relevance `json:"relevance"`
	Target    target                   `json:"target"`
}

func runJSON(run simulate.Run, t estate.Target, v securitypolicy.Verdict) policyResult {
	outcome, why := v.Decision()
	var rule string
	if outcome != securitypolicy.Undecided {
		rule = v.Default
		if v.Rule != nil {
			rule = v.Rule.Name
		}
	}
	return policyResult{
		securityJSON: securityOf(&v, string(outcome), why.Text, rule, run.Fidelity, run.Stages),
		Kind:         run.Kind, Target: targetOf(t), Relevance: v.Relevance,
	}
}

// dedupeUnresolved keeps one entry per device, vsys and reason. A stage's
// unresolved entry and the run's fidelity can carry the same reason.
func dedupeUnresolved(in []unresolved) []unresolved {
	seen := map[string]bool{}
	var out []unresolved
	for _, u := range in {
		k := u.Device + "|" + u.Vsys + "|" + u.Reason
		if !seen[k] {
			seen[k] = true
			out = append(out, u)
		}
	}
	return out
}

func (fl *flowFlags) bindProtocol(cmd *cobra.Command) {
	cmd.Flags().StringVar(&fl.protocol, "protocol", "tcp", "tcp, udp, sctp, icmp or a protocol number")
}

func (fl *flowFlags) bindPort(cmd *cobra.Command) {
	cmd.Flags().StringVar(&fl.port, "port", "", "destination port: 443 or tcp/443")
}

func (fl *flowFlags) bindSourcePort(cmd *cobra.Command) {
	cmd.Flags().IntVar(&fl.sourcePort, "source-port", 0, "source port")
}

func (fl *flowFlags) bindZones(cmd *cobra.Command) {
	cmd.Flags().StringVar(&fl.fromZone, "from-zone", "", "source zone; derived when absent")
	cmd.Flags().StringVar(&fl.toZone, "to-zone", "", "destination zone; derived when absent")
}

func (fl *flowFlags) bindL7(cmd *cobra.Command) {
	cmd.Flags().StringVar(&fl.url, "url", "", "URL, matched against URL categories")
	cmd.Flags().StringVar(&fl.application, "application", "", "application (not evaluated yet)")
	cmd.Flags().StringVar(&fl.user, "user", "", "source user (not evaluated yet)")
}

// bindWhy registers --why with the one help text every command shares; a command's
// Long says what its --why shows beyond that.
func bindWhy(cmd *cobra.Command, v *bool) {
	cmd.Flags().BoolVar(v, "why", false, "show every stage: what it decided and why")
}

// bindNoDNS registers --no-dns.
func bindNoDNS(cmd *cobra.Command, v *bool) {
	cmd.Flags().BoolVar(v, "no-dns", false, "do not resolve an FQDN")
}
