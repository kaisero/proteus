package cli

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/kaisero/proteus/internal/query"
	"github.com/kaisero/proteus/internal/simulate"
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
	a.bindDetail(cmd)
	return cmd
}

// routingAnswer is simulate routing's answer: one result when the path could be
// simulated, none when its start device was a hole.
type routingAnswer struct {
	enveloped[query.RoutingInput, query.RoutingResult]
	why bool
}

func (a *app) runRouting(ctx context.Context, o routingOptions) (answer, error) {
	in := query.RoutingInput{
		Source: o.src, Destination: o.dst, Port: o.port, Device: o.device, Router: o.router, At: o.at,
		RIB: o.rib, NoDNS: o.noDNS,
	}
	// Settings first, as before the query layer: a broken inventory wins over
	// a bad port.
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	if u := in.Validate(); u != nil {
		return nil, u
	}
	env, err := a.storeEnv(s)
	if err != nil {
		return nil, err
	}
	e, err := query.Routing(ctx, env, in)
	if choice, ok := errors.AsType[*simulate.ChoiceError](err); ok {
		return nil, usageErr("%w", choice)
	}
	if err != nil {
		return nil, err
	}
	return routingAnswer{enveloped: enveloped[query.RoutingInput, query.RoutingResult]{e}, why: o.why}, nil
}

func (r routingAnswer) SummaryResults() any {
	return query.Summarize(r.e, query.RoutingResult.Summary).Results
}

func (r routingAnswer) Input() any {
	return r.e.Input.Echo()
}

func (r routingAnswer) Text(t *textOut) error {
	if len(r.e.Results) > 0 {
		res := r.e.Results[0]
		renderPath(t, routingTitle(res.Path), res.Run, res.Path, t.now, r.why, nil)
	}
	printQualifiers(t, r.Qualifiers())
	return t.err
}
