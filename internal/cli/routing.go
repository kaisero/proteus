package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/routing"
)

// routingOptions are simulate routing's flags.
type routingOptions struct {
	sim                      simulate.Simulation
	src, dst                 string
	device, router, at, port string
	rib, why, noDNS          bool
}

// routingCmd is simulate routing (spec §17). A path crosses devices, so it takes
// no selectors but --device, which names the start (R13).
func (a *app) routingCmd(sim simulate.Simulation) *cobra.Command {
	var o routingOptions
	o.sim = sim
	var fl flowFlags
	cmd := &cobra.Command{
		Use:   "routing <source> <destination> | <destination> --device <name>",
		Short: sim.Describe(),
		Long: "Routing traces the path a packet takes across the inventory's firewalls: per\n" +
			"firewall the zones it enters and leaves by, the interfaces and the route. The\n" +
			"path starts where the source is connected, or where the most specific route to\n" +
			"it leaves; --device names the start instead, and is needed with a destination\n" +
			"alone. It follows each firewall's stored forwarding table from one firewall to\n" +
			"the next, and names what may make the answer incomplete: ECMP, policy-based\n" +
			"forwarding, NAT, and a path that leaves the inventory. --port decides NAT and\n" +
			"PBF rules that name a service.\n\n" +
			"Source and destination are IPv4 addresses or FQDNs; an FQDN is resolved with this\n" +
			"machine's DNS unless --no-dns.",
		Args: args(cobra.RangeArgs(1, 2)),
		RunE: func(c *cobra.Command, argv []string) error {
			o.dst = argv[len(argv)-1]
			if len(argv) == 2 {
				o.src = argv[0]
			} else if o.device == "" {
				return usageErr("give a source, or a start device with --device")
			}
			o.port = fl.port
			return a.emitRun(a.runRouting(c.Context(), o))
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.device, "device", "", "the firewall the path starts on; needed with a destination alone")
	f.StringVar(&o.router, "router", "", "start in this logical router of --device")
	f.StringVar(&o.at, "at", "", "read each device's newest snapshot at or before this time (id, RFC 3339 or date)")
	fl.bindPort(cmd)
	f.BoolVar(&o.rib, "rib", false, "list the routing table's other routes to the destination at each firewall")
	bindWhy(cmd, &o.why)
	bindNoDNS(cmd, &o.noDNS)
	return cmd
}

// routingResult is simulate routing's result element.
type routingResult struct {
	routing.Path
	Fidelity simulate.Fidelity `json:"fidelity"`
	Stages   []stageJSON       `json:"stages"`
}

// routingAnswer is simulate routing's answer: one result when the path could be
// simulated, none when its start device was a hole.
type routingAnswer struct {
	o     routingOptions
	flow  simulate.Flow
	run   simulate.Run
	path  routing.Path
	ok    bool
	holes []estate.Hole
	un    []unresolved
	notes []note
}

func (a *app) runRouting(ctx context.Context, o routingOptions) (answer, error) {
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	if o.device != "" {
		if _, err := s.inv.Select([]string{o.device}, nil); err != nil {
			return nil, usageErr("%w", err)
		}
	}
	flow, err := parseFlow(flowFlags{protocol: "tcp", port: o.port})
	if err != nil {
		return nil, err
	}
	if err := a.endpoints(ctx, &flow, o.src, o.dst, o.noDNS); err != nil {
		return nil, err
	}
	es, err := a.openEstate(s, o.at)
	if err != nil {
		return nil, err
	}
	env := es.env(a)
	env.Resolve = nil // routing resolves only the endpoints, above
	params := map[string]string{"device": o.device, "router": o.router}
	if o.rib {
		params["rib"] = "true"
	}
	a.log.Infof(runlog.TagStep, "routing %s -> %s, start %q", flow.Source, flow.Destination, o.device)
	run, holes, err := runEstate(ctx, o.sim, env, simulate.Input{Flow: flow, Params: params})
	if err != nil {
		return nil, err
	}
	ans := routingAnswer{o: o, flow: flow, holes: holes}
	if len(holes) > 0 {
		return ans, nil
	}
	ans.run, ans.ok = run, true
	ans.path, _ = run.Output.(routing.Path)
	a.log.Infof(runlog.TagStep, "routing: %s, fidelity %s", ans.path.Outcome, run.Fidelity)
	ans.un = dedupeUnresolved(runUnresolved(run, run.Device, "", false))
	for _, h := range ans.path.Hops {
		ans.notes = append(ans.notes, runNotes(h.Device, h.Notes)...)
	}
	ans.notes = append(ans.notes, runNotes(run.Device, ans.path.Notes)...)
	return ans, nil
}

func (r routingAnswer) Command() string { return "simulate routing" }

func (r routingAnswer) Input() any {
	return routingInput{Flow: r.flow, Device: r.o.device, Router: r.o.router, RIB: r.o.rib, At: r.o.at}
}

func (r routingAnswer) Results() any {
	if !r.ok {
		return []routingResult{}
	}
	return []routingResult{{Path: r.path, Fidelity: r.run.Fidelity, Stages: simStages(r.run.Stages)}}
}

func (r routingAnswer) Qualifiers() qualifiers {
	return qualifiers{Holes: r.holes, Unresolved: r.un, Notes: r.notes}
}

func (r routingAnswer) Text(t *textOut) error {
	if r.ok {
		renderPath(t, r.run, r.path, t.now, r.o.why)
	}
	printQualifiers(t, r.Qualifiers())
	return t.err
}
