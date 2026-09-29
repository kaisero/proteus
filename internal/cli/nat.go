package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/store"
)

// natOptions are simulate nat's flags.
type natOptions struct {
	device, router, fromZone, fromIf, at string
	fl                                   flowFlags
}

// natCmd is simulate nat (spec §18 N8): one firewall, a flow, and optionally the
// ingress; the zones and interfaces come from the stored tables.
func (a *app) natCmd(sim simulate.Simulation) *cobra.Command {
	var o natOptions
	cmd := &cobra.Command{
		Use:   "nat <source> <destination> --device <name>",
		Short: sim.Describe(),
		Long: "NAT names the NAT rule a packet hits on one firewall and shows the packet after\n" +
			"translation, and what security policy then matches: the addresses and port\n" +
			"before NAT, the zones after it. The ingress is where the source is connected, or\n" +
			"where its return route leaves; --from-zone or --from-interface sets it. The\n" +
			"destination zone and interface come from the stored forwarding table.\n\n" +
			"Source and destination are IPv4 addresses or FQDNs; the source may be -, for\n" +
			"any. --why lists every rule above the match and what excluded it.\n\n" +
			"Stages: place, pbf, lookup, match, translate, post-lookup",
		Args: args(cobra.ExactArgs(2)),
		RunE: func(c *cobra.Command, argv []string) error { return a.runNAT(c.Context(), sim, argv[0], argv[1], o) },
	}
	f := cmd.Flags()
	f.StringVar(&o.device, "device", "", "the firewall (required)")
	f.StringVar(&o.router, "router", "", "the logical router, when the firewall has several")
	f.StringVar(&o.fromZone, "from-zone", "", "the zone the packet arrives in")
	f.StringVar(&o.fromIf, "from-interface", "", "the interface the packet arrives on")
	cmd.MarkFlagsMutuallyExclusive("from-zone", "from-interface")
	f.StringVar(&o.fl.protocol, "protocol", "tcp", "tcp, udp, sctp, icmp or a protocol number")
	f.StringVar(&o.fl.port, "port", "", "destination port: 443 or tcp/443")
	f.IntVar(&o.fl.sourcePort, "source-port", 0, "source port")
	f.StringVar(&o.at, "at", "", "read the newest snapshot at or before this time (id, RFC 3339 or date)")
	f.BoolVar(&o.fl.why, "why", false, "list the rules above the match and every stage")
	f.BoolVar(&o.fl.noDNS, "no-dns", false, "resolve no FQDN, neither an endpoint nor a translated destination")
	return cmd
}

func (a *app) runNAT(ctx context.Context, sim simulate.Simulation, src, dst string, o natOptions) error {
	flow, err := parseFlow(o.fl)
	if err != nil {
		return err
	}
	s, err := a.settings(true)
	if err != nil {
		return err
	}
	if src == "-" {
		src = "" // any source
	}
	if err := a.endpoints(ctx, &flow, src, dst, o.fl.noDNS); err != nil {
		return err
	}
	es, err := a.openEstate(s, o.at)
	if err != nil {
		return err
	}
	env := es.env(a)
	if o.fl.noDNS {
		env.Resolve = nil
	}
	params := map[string]string{"device": o.device, "router": o.router, "from-zone": o.fromZone, "from-interface": o.fromIf}
	a.log.Infof(runlog.TagStep, "nat %s -> %s on %s", flow.Source, flow.Destination, o.device)
	run, err := runEstate(ctx, sim, env, simulate.Input{Flow: flow, Params: params})
	if err != nil {
		return err
	}
	res, _ := run.Output.(nat.Result)
	a.log.Infof(runlog.TagStep, "nat: fidelity %s", run.Fidelity)
	un := dedupeUnresolved(runUnresolved(run, run.Device, run.Vsys, true))
	if s.output == "json" {
		in := natInput{Flow: flow, Device: o.device, Router: o.router, FromZone: o.fromZone, FromInterface: o.fromIf, At: o.at}
		out := struct {
			nat.Result
			Fidelity simulate.Fidelity `json:"fidelity"`
			Stages   []simulate.Stage  `json:"stages"`
		}{res, run.Fidelity, run.Stages}
		if err := writeJSON(a.stdout, envelope{Command: "simulate nat", Input: in, Results: out, Unresolved: un}); err != nil {
			return err
		}
		return finish(nil, un)
	}
	d, _ := es.network.Device(run.Device)
	renderNAT(a.stdout, run, res, d.TakenAt, a.now(), o.fl.why)
	printQualifiers(a, nil, un, nil)
	return finish(nil, un)
}

// endpoints resolves a flow's source, when one is given, and its destination. An
// FQDN that resolves to no address is a usage error: there is nothing to simulate.
func (a *app) endpoints(ctx context.Context, flow *simulate.Flow, src, dst string, noDNS bool) error {
	var err error
	if src != "" {
		if flow.Source, err = a.endpoint(ctx, src, noDNS); err != nil {
			return err
		}
	}
	if flow.Destination, err = a.endpoint(ctx, dst, noDNS); err != nil {
		return err
	}
	for _, ep := range []simulate.Endpoint{flow.Source, flow.Destination} {
		if ep.Name != "" && len(ep.Addrs) == 0 {
			return usageErr("%s resolved to no address", ep.Name)
		}
	}
	return nil
}

// fetchedEstate is the store at one point in time, for the simulations that follow a
// packet across devices.
type fetchedEstate struct {
	st      *store.Store
	when    estate.When
	network *estate.Network
}

func (a *app) openEstate(s settings, at string) (fetchedEstate, error) {
	when := estate.When{Now: a.now(), MaxAge: s.maxAge, Log: a.log}
	if at != "" {
		var err error
		if when.At, err = estate.ParseAt(at); err != nil {
			return fetchedEstate{}, usageErr("%w", err)
		}
	}
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return fetchedEstate{}, err
	}
	return fetchedEstate{st: st, when: when, network: estate.NewNetwork(st, s.inv.Names(), when)}, nil
}

// env is a simulation environment over the estate, resolving FQDNs with the app's
// DNS lookup.
func (e fetchedEstate) env(a *app) *simulate.Env {
	return &simulate.Env{Log: a.log, Network: e.network, Load: storeLoader(e.st, e.when), Resolve: a.lookup}
}

// runEstate runs a simulation. A choice only the user can make, such as which of two
// firewalls a source enters, is a usage error.
func runEstate(ctx context.Context, sim simulate.Simulation, env *simulate.Env, in simulate.Input) (simulate.Run, error) {
	run, err := sim.Run(ctx, env, in)
	if choice, ok := errors.AsType[*simulate.ChoiceError](err); ok {
		return run, usageErr("%w", choice)
	}
	return run, err
}

// runUnresolved collects what makes a run's answer incomplete: its stages'
// unresolved entries and, with withReasons, the reasons of an under-matching run.
// vsys is "" when the run spans devices and no single vsys applies.
func runUnresolved(run simulate.Run, device, vsys string, withReasons bool) []unresolved {
	var un []unresolved
	for _, stg := range run.Stages {
		for _, u := range stg.Unresolved {
			un = append(un, unresolved{Device: device, Vsys: vsys, Value: u.Value, Reason: u.Reason})
		}
	}
	if withReasons && run.Fidelity.Level() == "undermatch" {
		for _, r := range run.Fidelity.Reasons() {
			un = append(un, unresolved{Device: device, Vsys: vsys, Reason: r})
		}
	}
	return un
}

// storeLoader loads a device's vsys configuration and index from the store, as
// every multi-device simulation needs.
func storeLoader(st *store.Store, when estate.When) func(dev, vsys string) (simulate.Target, error) {
	return func(dev, vsys string) (simulate.Target, error) {
		ts, holes := estate.Open(st, []string{dev}, []string{vsys}, when)
		if len(ts) == 0 {
			return simulate.Target{}, fmt.Errorf("%s/%s: %v", dev, vsys, holes)
		}
		idx, err := index.For(ts[0].Config, ts[0].Scope)
		if err != nil {
			return simulate.Target{}, err
		}
		return simulate.Target{Config: ts[0].Config, Index: idx, Notes: ts[0].Notes}, nil
	}
}
