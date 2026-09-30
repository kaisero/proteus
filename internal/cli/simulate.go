package cli

import (
	"context"
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

// kindCommands are the kinds whose flags differ from the flow command's, and so
// need a command of their own.
var kindCommands = map[string]func(*app, simulate.Simulation) *cobra.Command{
	routing.Kind: (*app).routingCmd,
	nat.Kind:     (*app).natCmd,
}

// simulateCmds returns one subcommand per registered simulation kind. A kind takes
// the flow command unless it has its own; a new flow kind is a registry entry, not a
// command change.
func (a *app) simulateCmds() []*cobra.Command {
	var out []*cobra.Command
	for _, kind := range estate.Kinds() {
		build := (*app).simulateCmd
		if own, ok := kindCommands[kind]; ok {
			build = own
		}
		out = append(out, build(a, estate.Simulations[kind]))
	}
	return out
}

func (a *app) simulateCmd(sim simulate.Simulation) *cobra.Command {
	var sel selection
	var fl flowFlags
	cmd := &cobra.Command{
		Use:   sim.Kind() + " <source> <destination>",
		Short: sim.Describe(),
		Long: "Source and destination are an address or an FQDN; an FQDN is resolved with this\n" +
			"machine's DNS unless --no-dns. Zones are derived from the stored forwarding table,\n" +
			"or from the configuration, when --from-zone and --to-zone are not given.\n\n" +
			"Stages: " + strings.Join(sim.Stages(), ", "),
		Args: args(cobra.ExactArgs(2)),
		RunE: func(c *cobra.Command, argv []string) error {
			return a.runSimulation(c.Context(), sim, sel, fl, argv[0], argv[1])
		},
	}
	sel.bind(cmd, true)
	f := cmd.Flags()
	f.StringVar(&fl.protocol, "protocol", "tcp", "tcp, udp, sctp, icmp or a protocol number")
	f.StringVar(&fl.port, "port", "", "destination port: 443 or tcp/443")
	f.IntVar(&fl.sourcePort, "source-port", 0, "source port")
	f.StringVar(&fl.fromZone, "from-zone", "", "source zone; derived when absent")
	f.StringVar(&fl.toZone, "to-zone", "", "destination zone; derived when absent")
	cmd.MarkFlagsRequiredTogether("from-zone", "to-zone")
	f.StringVar(&fl.url, "url", "", "URL, matched against URL categories")
	f.StringVar(&fl.application, "application", "", "application (not evaluated yet)")
	f.StringVar(&fl.user, "user", "", "source user (not evaluated yet)")
	f.BoolVar(&fl.why, "why", false, "show every stage: its fidelity, what it kept, and why")
	f.BoolVar(&fl.noDNS, "no-dns", false, "do not resolve an FQDN endpoint")
	return cmd
}

func (a *app) runSimulation(ctx context.Context, sim simulate.Simulation, sel selection, fl flowFlags, src, dst string) error {
	flow, err := parseFlow(fl)
	if err != nil {
		return err
	}
	s, err := a.settings(sel.file == "")
	if err != nil {
		return err
	}
	// An FQDN that resolves to no address is simulated: FQDN objects still match,
	// and the answer says it may miss rules.
	if flow.Source, err = a.endpoint(ctx, src, fl.noDNS); err != nil {
		return err
	}
	if flow.Destination, err = a.endpoint(ctx, dst, fl.noDNS); err != nil {
		return err
	}
	t, holes, err := a.oneTarget(ctx, sel, s)
	if err != nil {
		return err
	}
	env, err := a.policyEnv(t, s, fl.noDNS)
	if err != nil {
		return err
	}
	a.log.Infof(runlog.TagStep, "%s %s -> %s on %s/%s", sim.Kind(), flow.Source, flow.Destination, t.Device, t.Vsys)
	run, err := sim.Run(ctx, env, simulate.Input{Flow: flow, Device: t.Device, Vsys: t.Vsys})
	if err != nil {
		return err
	}
	a.log.Infof(runlog.TagStep, "%s: fidelity %s", sim.Kind(), run.Fidelity)
	un, notes := qualifiers([]estate.Target{t})
	un = dedupeUnresolved(append(un, runUnresolved(run, t.Device, t.Vsys, true)...))
	verdict, _ := run.Output.(securitypolicy.Verdict)
	if a.format == formatJSON {
		if err := writeJSON(a.stdout, envelope{
			Command: "simulate " + sim.Kind(), Input: policyInput{Flow: flow, Selection: sel.input()},
			Results: runJSON(run, t, verdict), Holes: holes, Unresolved: un, Notes: notes,
		}); err != nil {
			return err
		}
		return finish(holes, un)
	}
	a.printRun(run, t, verdict, flow, fl.why)
	printQualifiers(a, holes, un, notes)
	if verdict.Rule == nil {
		fmt.Fprintln(a.stdout, "no enabled rule matches")
	} else {
		fmt.Fprintf(a.stdout, "first match: %s (%s)\n", verdict.Rule.Name, verdict.Rule.Action)
	}
	return finish(holes, un)
}

// oneTarget opens the selection and requires exactly one device and vsys: a policy
// simulation runs on one rulebase.
func (a *app) oneTarget(ctx context.Context, sel selection, s settings) (estate.Target, []estate.Hole, error) {
	ts, holes, err := a.targets(ctx, sel, s, a.stderr)
	if err != nil {
		return estate.Target{}, nil, err
	}
	switch len(ts) {
	case 1:
		return ts[0], holes, nil
	case 0:
		printQualifiers(a, holes, nil, nil)
		return estate.Target{}, nil, fmt.Errorf("the selection has no device and vsys to simulate on")
	}
	return estate.Target{}, nil, usageErr(
		"the selection has %d device and vsys pairs; estate simulation arrives in M5, so select one device and one vsys", len(ts))
}

// policyEnv is the simulation environment for one target: its configuration, the
// user and zone providers, and the device's stored tables, so NAT can give the
// post-NAT zone (spec §18 N10).
func (a *app) policyEnv(t estate.Target, s settings, noDNS bool) (*simulate.Env, error) {
	users, err := a.userSnapshot()
	if err != nil {
		return nil, err
	}
	env := &simulate.Env{Log: a.log, Load: func(string, string) (simulate.Target, error) {
		idx, err := index.For(t.Config, t.Scope)
		if err != nil {
			return simulate.Target{}, err
		}
		p := index.Providers{Users: users}
		if t.Snapshot != nil {
			if z, err := t.Snapshot.Zones(); err == nil {
				p.Zones = z
			} else {
				a.log.Infof(runlog.TagStep, "%s: no stored zones: %v", t.Device, err)
			}
		}
		return simulate.Target{Config: t.Config, Index: idx, Providers: p, Notes: t.Notes}, nil
	}, Resolve: a.lookup}
	if noDNS {
		env.Resolve = nil
	}
	if t.Snapshot != nil {
		if st, err := a.openStore(s.storeRoot); err == nil {
			env.Network = estate.NewNetwork(st, []string{t.Device}, estate.When{At: t.Snapshot.Meta.TakenAt, Now: a.now(), Log: a.log})
		}
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

func (a *app) printRun(run simulate.Run, t estate.Target, v securitypolicy.Verdict, flow simulate.Flow, why bool) {
	fmt.Fprintf(a.stdout, "%s -> %s %s", flow.Source, flow.Destination, flow.Protocol)
	if flow.DestPort != 0 {
		fmt.Fprintf(a.stdout, "/%d", flow.DestPort)
	}
	if flow.URL != "" {
		fmt.Fprintf(a.stdout, " %s", flow.URL)
	}
	fmt.Fprintf(a.stdout, "\n%s\n", header(t, a.now()))
	printNotes(a, t)
	for _, ep := range []simulate.Endpoint{flow.Source, flow.Destination} {
		if ep.Name != "" {
			fmt.Fprintf(a.stdout, "  dns        %s -> %v\n", ep.Name, ep.Addrs)
		}
	}
	zones := "not evaluated"
	if v.Zones.Source != "not evaluated" && (len(v.Zones.From) > 0 || len(v.Zones.To) > 0) {
		zones = fmt.Sprintf("from %s, to %s (%s)", orAny(v.Zones.From), orAny(v.Zones.To), v.Zones.Source)
	}
	fmt.Fprintf(a.stdout, "  zones      %s\n", zones)
	switch {
	case !v.Relevance.Known:
		fmt.Fprintf(a.stdout, "  relevance  unknown: %s\n", v.Relevance.Reason)
	case v.Relevance.Relevant:
		fmt.Fprintf(a.stdout, "  relevant   %s\n", v.Relevance.Reason)
	default:
		fmt.Fprintf(a.stdout, "  relevance  not relevant: %s\n", v.Relevance.Reason)
	}
	fmt.Fprintf(a.stdout, "  fidelity   %s\n", run.Fidelity)
	if why {
		for _, st := range run.Stages {
			fmt.Fprintf(a.stdout, "  %-20s %-10s %5d  %s\n", st.Slug, st.Fidelity.Level(), st.State.Candidates, st.Detail)
		}
	}
	for _, r := range v.Candidates {
		fmt.Fprintf(a.stdout, "  %3d. %-26s %-6s [%-11s %s]\n", r.Position, r.Name, r.Action, r.Layer, r.Scope)
	}
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

type stageJSON struct {
	Slug       string             `json:"slug"`
	Name       string             `json:"name"`
	Fidelity   simulate.Fidelity  `json:"fidelity"`
	Candidates uint64             `json:"candidates"`
	Detail     string             `json:"detail,omitempty"`
	ElapsedMS  float64            `json:"elapsed_ms"`
	Unresolved []index.Unresolved `json:"unresolved,omitempty"`
}

// policyResult is one device and vsys's simulate policy answer in the JSON envelope.
type policyResult struct {
	Candidates []ruleJSON                    `json:"candidates"`
	Fidelity   simulate.Fidelity             `json:"fidelity"`
	FirstMatch *ruleJSON                     `json:"first_match"`
	Kind       string                        `json:"kind"`
	Relevance  securitypolicy.Relevance      `json:"relevance"`
	Stages     []stageJSON                   `json:"stages"`
	Target     target                        `json:"target"`
	Zones      securitypolicy.ZoneDerivation `json:"zones"`
}

func runJSON(run simulate.Run, t estate.Target, v securitypolicy.Verdict) policyResult {
	stages := make([]stageJSON, len(run.Stages))
	for i, st := range run.Stages {
		stages[i] = stageJSON{
			Slug: st.Slug, Name: st.Name, Fidelity: st.Fidelity, Candidates: st.State.Candidates,
			Detail: st.Detail, ElapsedMS: float64(st.Elapsed.Microseconds()) / 1000, Unresolved: st.Unresolved,
		}
	}
	var first *ruleJSON
	if v.Rule != nil {
		r := toRuleJSON(*v.Rule)
		first = &r
	}
	cands := make([]ruleJSON, len(v.Candidates))
	for i, r := range v.Candidates {
		cands[i] = toRuleJSON(r)
	}
	return policyResult{
		Kind: run.Kind, Target: targetOf(t), Fidelity: run.Fidelity, Stages: stages,
		FirstMatch: first, Candidates: cands, Zones: v.Zones, Relevance: v.Relevance,
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
