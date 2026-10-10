package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
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
			// --each first, then --file, else the path (spec 2026-10-07 §3.1).
			// Each mode's input says which flags it refuses.
			switch {
			case o.each:
				return usageErr("fan-out (--each) arrives in a later release")
			case o.sel.file != "":
				return a.emitRun(a.runPolicyFile(c.Context(), o))
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
	a.bindDetail(cmd)
	return cmd
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
	enveloped[query.PolicyInput, query.PathResult]
	why bool
}

func (a *app) runPolicyPath(ctx context.Context, o policyOptions) (answer, error) {
	in := query.PolicyInput{
		Flow: o.fl.input(o.src, o.dst), Device: o.device(), Router: o.router, At: o.sel.at,
		Vsys: o.sel.vsys, Label: o.sel.labels,
	}
	if u := in.Validate(); u != nil {
		return nil, u
	}
	// Only a repeatable flag can name two starts.
	if len(o.sel.devices) > 1 {
		return nil, usageErr("path mode starts on one device; --device has %d", len(o.sel.devices))
	}
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	env, err := a.storeEnv(s)
	if err != nil {
		return nil, err
	}
	e, err := query.Policy(ctx, env, in)
	if choice, ok := errors.AsType[*simulate.ChoiceError](err); ok {
		// A start only the user can choose: routing's text, and the way forward
		// (spec 2026-10-07 §3.3).
		if in.Device == "" && len(choice.Options) > 0 {
			return nil, usageErr("%w; name the start with --device <name>", choice)
		}
		return nil, usageErr("%w", choice)
	}
	if err != nil {
		return nil, err
	}
	return pathAnswer{enveloped: enveloped[query.PolicyInput, query.PathResult]{e}, why: o.fl.why}, nil
}

func (p pathAnswer) SummaryResults() any {
	return query.Summarize(p.e, query.PathResult.Summary).Results
}

func (p pathAnswer) Input() any {
	return p.e.Input.Echo()
}

func (p pathAnswer) Text(t *textOut) error {
	if len(p.e.Results) > 0 {
		p.text(t, p.e.Results[0])
	}
	printQualifiers(t, p.Qualifiers())
	return t.err
}

// text is the path answer (spec §8.1): the verdict line and the notes the
// routing boxes do not show, then the path with a policy row per hop and, with
// --why, each hop's security check.
func (p pathAnswer) text(t *textOut, res query.PathResult) {
	r, flow := res.Result, p.e.Input.Simulated
	fmt.Fprintln(t, verdictLine(t.pal, r))
	for _, h := range r.Hops {
		for _, c := range h.Checks {
			for _, n := range c.Notes {
				fmt.Fprintf(t, "  %s\n", noteStyle(t.pal, n)(fmt.Sprintf("note: %s / %s: %s", h.Routing.Device, h.Routing.Vsys, n.Text)))
			}
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(t, "  %s\n", noteStyle(t.pal, n)("note: "+n.Text))
	}
	fmt.Fprintln(t)
	title := fmt.Sprintf("simulate policy %s -> %s %s", sourceText(r.Path), r.Path.Destination, flow.Protocol)
	if flow.DestPort != 0 {
		title += fmt.Sprintf("/%d", flow.DestPort)
	}
	renderPath(t, title, simulate.Run{Fidelity: r.Fidelity, Stages: res.RunStages}, r.Path, t.now, p.why,
		func(i int) [][2]string { return policyRows(r.Hops[i]) })
	if !p.why {
		return
	}
	for _, h := range r.Hops {
		for _, c := range h.Checks {
			fmt.Fprintf(t, "\nhop %d: %s / %s, %s %s", h.Index, h.Routing.Device, h.Routing.Vsys, c.Name, c.Verdict)
			if len(c.Reason) > 0 {
				fmt.Fprintf(t, ": %s", c.Reason.Text())
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
			s = fmt.Sprintf("%s (%s)", c.Rule, query.CheckAction(c))
		case pathpolicy.Undecided:
			s = "undecided: " + c.Reason.Text()
		default:
			s = "not evaluated: " + c.Reason.Text()
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

// verdictLine is the answer's first line, coloured by the verdict (spec §8.1):
// ok when allowed, warn when undecided, bad when denied.
func verdictLine(pal palette, r pathpolicy.Result) string {
	line := query.PathAnswer(r)
	if r.At == nil {
		return pal.ok(line)
	}
	if _, ok := query.PointHop(r); !ok || r.Verdict == pathpolicy.VerdictUndecided {
		return pal.warn(line)
	}
	return pal.bad(line)
}
