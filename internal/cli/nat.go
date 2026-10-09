package cli

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/simulate"
)

// natOptions are simulate nat's flags.
type natOptions struct {
	sim                                  simulate.Simulation
	src, dst                             string
	device, router, fromZone, fromIf, at string
	fl                                   flowFlags
}

// natCmd is simulate nat (spec §18 N8): one firewall, a flow, and optionally the
// ingress; the zones and interfaces come from the stored tables.
func (a *app) natCmd(sim simulate.Simulation) *cobra.Command {
	var o natOptions
	o.sim = sim
	cmd := &cobra.Command{
		Use:   "nat <source> <destination> --device <name>",
		Short: sim.Describe(),
		Long: "NAT names the NAT rule a packet hits on one firewall and shows the packet after\n" +
			"translation, and what security policy then matches: the addresses and port\n" +
			"before NAT, the zones after it. The ingress is where the source is connected, or\n" +
			"where its return route leaves; --from-zone or --from-interface sets it. The\n" +
			"destination zone and interface come from the stored forwarding table.\n\n" +
			"Source and destination are IPv4 addresses or FQDNs; the source may be -, for\n" +
			"any. --why lists every rule above the match and what excluded it. --no-dns also\n" +
			"leaves a translated destination's FQDN unresolved.\n\n" +
			"Stages: place, pbf, lookup, match, translate, post-lookup",
		Args: args(cobra.ExactArgs(2)),
		RunE: func(c *cobra.Command, argv []string) error {
			o.src, o.dst = argv[0], argv[1]
			return a.emitRun(a.runNAT(c.Context(), o))
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.device, "device", "", "the firewall to simulate on")
	_ = cmd.MarkFlagRequired("device")
	f.StringVar(&o.router, "router", "", "the logical router, when the firewall has several")
	f.StringVar(&o.fromZone, "from-zone", "", "the zone the packet arrives in")
	f.StringVar(&o.fromIf, "from-interface", "", "the interface the packet arrives on")
	cmd.MarkFlagsMutuallyExclusive("from-zone", "from-interface")
	o.fl.bindProtocol(cmd)
	o.fl.bindPort(cmd)
	o.fl.bindSourcePort(cmd)
	f.StringVar(&o.at, "at", "", "read the newest snapshot at or before this time (id, RFC 3339 or date)")
	bindWhy(cmd, &o.fl.why)
	bindNoDNS(cmd, &o.fl.noDNS)
	return cmd
}

// natAnswer is simulate nat's answer: one result when the device could be read,
// none when it was a hole.
type natAnswer struct {
	enveloped[query.NATInput, query.NATResult]
	why bool
}

func (a *app) runNAT(ctx context.Context, o natOptions) (answer, error) {
	// NAT binds only protocol, port and source port of the flow flags; the
	// ingress has flags of its own.
	in := query.NATInput{
		Flow: o.fl.input(o.src, o.dst), Device: o.device, Router: o.router, FromZone: o.fromZone,
		FromInterface: o.fromIf, At: o.at,
	}
	if u := in.Validate(); u != nil {
		return nil, u
	}
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	env, err := a.storeEnv(s)
	if err != nil {
		return nil, err
	}
	e, err := query.NAT(ctx, env, in)
	if choice, ok := errors.AsType[*simulate.ChoiceError](err); ok {
		return nil, usageErr("%w", choice)
	}
	if err != nil {
		return nil, err
	}
	return natAnswer{enveloped: enveloped[query.NATInput, query.NATResult]{e}, why: o.fl.why}, nil
}

func (n natAnswer) Input() any {
	in := n.e.Input
	return natInput{Flow: in.Simulated, Device: in.Device, Router: in.Router, FromZone: in.FromZone, FromInterface: in.FromInterface, At: in.At}
}

func (n natAnswer) Text(t *textOut) error {
	if len(n.e.Results) > 0 {
		r := n.e.Results[0]
		renderNAT(t, r.Run, r.Result, r.Answer, r.TakenAt, t.now, n.why)
	}
	printQualifiers(t, n.Qualifiers())
	return t.err
}
