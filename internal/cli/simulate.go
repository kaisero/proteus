package cli

import (
	"cmp"
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kaisero/proteus/internal/estate"
	"github.com/kaisero/proteus/internal/query"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/nat"
	"github.com/kaisero/proteus/internal/simulate/routing"
	"github.com/kaisero/proteus/internal/simulate/securitypolicy"
)

// flowFlags are the flow of spec §11.3 as flags (spec §15 C12).
type flowFlags struct {
	protocol, port, application, user, url string
	sourcePort                             int
	fromZone, toZone                       string
	why, noDNS                             bool
	// protocolSet says --protocol was given. Without it, simulate policy
	// with --application takes the application's default protocol (spec
	// 2026-10-16 §4.1); routing and NAT keep tcp (D14).
	protocolSet bool
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

// policyAnswer is simulate policy's answer on a file: one result when a target
// could be read, none when the selection resolved to nothing but holes.
type policyAnswer struct {
	enveloped[query.PolicyFileInput, query.SecurityResult]
	why bool
}

// runPolicyFile is simulate policy on one configuration file (--file): one
// target, its zones given or derived from the configuration.
func (a *app) runPolicyFile(ctx context.Context, o policyOptions) (answer, error) {
	in := query.PolicyFileInput{Flow: o.fl.input(o.src, o.dst), Selection: o.sel.input(), Router: o.router}
	if u := in.Validate(); u != nil {
		return nil, u
	}
	s, err := a.settings(false)
	if err != nil {
		return nil, err
	}
	e, err := query.PolicyFile(ctx, a.queryEnv(s), in)
	if err != nil {
		return nil, err
	}
	return policyAnswer{enveloped: enveloped[query.PolicyFileInput, query.SecurityResult]{e}, why: o.fl.why}, nil
}

func (p policyAnswer) SummaryResults() any {
	return query.Summarize(p.e, query.SecurityResult.Summary).Results
}

func (p policyAnswer) Input() any {
	return p.e.Input.Echo()
}

func (p policyAnswer) Text(t *textOut) error {
	if len(p.e.Results) == 0 {
		printQualifiers(t, p.Qualifiers())
		fmt.Fprintln(t, "no device and vsys to simulate on")
		return t.err
	}
	r := p.e.Results[0]
	printRun(t, r.Run, r.From, r.Check, p.e.Input.Simulated, p.why)
	printQualifiers(t, p.Qualifiers())
	// The decision line, then, behind candidates in doubt, the undecided line
	// that is the answer (query.FileAnswer).
	if line := query.DecisionLine(r.Check, t.pal.accent); line != "" {
		fmt.Fprintln(t, line)
	}
	if v := r.Check; len(v.Undecided) > 0 {
		fmt.Fprintf(t, "%s %s\n", t.pal.warn("undecided:"), v.Undecided.Text())
	}
	return t.err
}

// input is the flow as the query layer takes it.
func (fl flowFlags) input(src, dst string) query.FlowInput {
	proto := fl.protocol
	if fl.application != "" && !fl.protocolSet {
		proto = ""
	}
	return query.FlowInput{
		Source: src, Destination: dst, Protocol: proto, Port: fl.port, SourcePort: fl.sourcePort,
		Application: fl.application, User: fl.user, URL: fl.url, FromZone: fl.fromZone, ToZone: fl.toZone,
		NoDNS: fl.noDNS,
	}
}

func printRun(w *textOut, run simulate.Run, t estate.Target, v securitypolicy.Verdict, flow simulate.Flow, why bool) {
	// A flow with an application and no protocol runs with its default's.
	fmt.Fprintf(w, "%s -> %s %s", flow.Source, flow.Destination, cmp.Or(flow.Protocol, v.Protocol))
	if flow.DestPort != 0 {
		fmt.Fprintf(w, "/%d", flow.DestPort)
	}
	if flow.URL != "" {
		fmt.Fprintf(w, " %s", flow.URL)
	}
	fmt.Fprintf(w, "\n%s\n", w.pal.head(header(t, w.now)))
	// The run's notes hold the target's and its own, such as which file
	// the application data came from (spec 2026-10-16 §6).
	for _, n := range run.Notes {
		fmt.Fprintf(w, "  %s\n", noteStyle(w.pal, n)("note: "+n.Text))
	}
	for _, ep := range []simulate.Endpoint{flow.Source, flow.Destination} {
		if ep.Name != "" {
			fmt.Fprintf(w, "  dns        %s -> %v\n", ep.Name, ep.Addrs)
		}
	}
	for _, n := range simulate.DNSNotes(flow, "checked") {
		fmt.Fprintf(w, "  %s\n", noteStyle(w.pal, n)("note: "+n.Text))
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

// protocolHelp is --protocol's help text; policyProtocolHelp adds what
// simulate policy does with --application.
const (
	protocolHelp       = "tcp, udp, sctp, icmp or a protocol number"
	policyProtocolHelp = protocolHelp + "; with --application, the application's default when absent"
)

func (fl *flowFlags) bindProtocol(cmd *cobra.Command, help string) {
	cmd.Flags().StringVar(&fl.protocol, "protocol", "tcp", help)
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
	cmd.Flags().StringVar(&fl.application, "application", "", "application: a predefined or custom application")
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
