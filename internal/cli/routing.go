package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/routing"
)

// routingOptions are simulate routing's flags.
type routingOptions struct {
	device, router, at, port string
	rib, why, noDNS          bool
}

// routingCmd is simulate routing (spec §17). A path crosses devices, so it takes
// no selectors but --device, which names the start (R13).
func (a *app) routingCmd(sim simulate.Simulation) *cobra.Command {
	var o routingOptions
	cmd := &cobra.Command{
		Use:   "routing <source> <destination> | <destination> --device <name>",
		Short: sim.Describe(),
		Long: "Routing traces the path a packet takes across the inventory's firewalls: per\n" +
			"firewall the zones it enters and leaves by, the interfaces and the route. The\n" +
			"path starts where the source is connected, or where the most specific route to\n" +
			"it leaves; --device names the start instead, and is needed with a destination\n" +
			"alone. It follows each firewall's stored forwarding table from one firewall to\n" +
			"the next, and names what may make the answer incomplete: ECMP, policy-based\n" +
			"forwarding, NAT, and a path that leaves the inventory.\n\n" +
			"Source and destination are IPv4 addresses or FQDNs; an FQDN is resolved with this\n" +
			"machine's DNS unless --no-dns.",
		Args: args(cobra.RangeArgs(1, 2)),
		RunE: func(c *cobra.Command, argv []string) error {
			src, dst := "", argv[len(argv)-1]
			if len(argv) == 2 {
				src = argv[0]
			} else if o.device == "" {
				return usageErr("give a source, or a start device with --device")
			}
			return a.runRouting(c.Context(), sim, src, dst, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.device, "device", "", "start on this device")
	f.StringVar(&o.router, "router", "", "start in this logical router of --device")
	f.StringVar(&o.at, "at", "", "read each device's newest snapshot at or before this time (id, RFC 3339 or date)")
	f.StringVar(&o.port, "port", "", "destination port, 443 or tcp/443: decides NAT and PBF rules that name a service")
	f.BoolVar(&o.rib, "rib", false, "list the routing table's other routes to the destination at each firewall")
	f.BoolVar(&o.why, "why", false, "show every stage: its fidelity and what it found")
	f.BoolVar(&o.noDNS, "no-dns", false, "do not resolve an FQDN endpoint")
	return cmd
}

func (a *app) runRouting(ctx context.Context, sim simulate.Simulation, src, dst string, o routingOptions) error {
	s, err := a.settings(true)
	if err != nil {
		return err
	}
	flow, err := parseFlow(flowFlags{protocol: "tcp", port: o.port})
	if err != nil {
		return err
	}
	if err := a.endpoints(ctx, &flow, src, dst, o.noDNS); err != nil {
		return err
	}
	es, err := a.openEstate(s, o.at)
	if err != nil {
		return err
	}
	env := es.env(a)
	env.Resolve = nil // routing resolves only the endpoints, above
	params := map[string]string{"device": o.device, "router": o.router}
	if o.rib {
		params["rib"] = "true"
	}
	a.log.Infof(runlog.TagStep, "routing %s -> %s, start %q", flow.Source, flow.Destination, o.device)
	run, err := runEstate(ctx, sim, env, simulate.Input{Flow: flow, Params: params})
	if err != nil {
		return err
	}
	path, _ := run.Output.(routing.Path)
	a.log.Infof(runlog.TagStep, "routing: %s, fidelity %s", path.Outcome, run.Fidelity)
	un := dedupeUnresolved(runUnresolved(run, run.Device, "", false))
	if s.output == "json" {
		in := routingInput{Flow: flow, Device: o.device, Router: o.router, RIB: o.rib, At: o.at}
		res := struct {
			routing.Path
			Fidelity simulate.Fidelity `json:"fidelity"`
			Stages   []simulate.Stage  `json:"stages"`
		}{path, run.Fidelity, run.Stages}
		if err := writeJSON(a.stdout, envelope{Command: "simulate routing", Input: in, Results: res, Unresolved: un}); err != nil {
			return err
		}
		return finish(nil, un)
	}
	renderPath(a.stdout, run, path, a.now(), o.why)
	printQualifiers(a, nil, un, nil)
	return finish(nil, un)
}
