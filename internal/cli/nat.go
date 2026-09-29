package cli

import (
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

// natCmd is simulate nat (spec §18 N8): one firewall, a flow, and optionally the
// ingress; the zones and interfaces come from the stored tables.
func (a *app) natCmd(sim simulate.Simulation) *cobra.Command {
	var device, router, fromZone, fromIf, at string
	var fl flowFlags
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
		RunE: func(c *cobra.Command, argv []string) error {
			if fromZone != "" && fromIf != "" {
				return usageErr("give --from-zone or --from-interface, not both")
			}
			flow, err := parseFlow(fl)
			if err != nil {
				return err
			}
			s, err := a.settings(true)
			if err != nil {
				return err
			}
			if argv[0] != "-" {
				if flow.Source, err = a.endpoint(c.Context(), argv[0], fl.noDNS); err != nil {
					return err
				}
			}
			if flow.Destination, err = a.endpoint(c.Context(), argv[1], fl.noDNS); err != nil {
				return err
			}
			for _, ep := range []simulate.Endpoint{flow.Source, flow.Destination} {
				if ep.Name != "" && len(ep.Addrs) == 0 {
					return usageErr("%s resolved to no address", ep.Name)
				}
			}
			when := estate.When{Now: a.now(), MaxAge: s.maxAge, Log: a.log}
			if at != "" {
				if when.At, err = estate.ParseAt(at); err != nil {
					return usageErr("%v", err)
				}
			}
			st, err := a.openStore(s.storeRoot)
			if err != nil {
				return err
			}
			network := estate.NewNetwork(st, s.inv.Names(), when)
			env := &simulate.Env{Log: a.log, Network: network, Load: storeLoader(st, when), Resolve: a.lookup}
			if fl.noDNS {
				env.Resolve = nil
			}
			params := map[string]string{"device": device, "router": router, "from-zone": fromZone, "from-interface": fromIf}
			a.log.Infof(runlog.TagStep, "nat %s -> %s on %s", flow.Source, flow.Destination, device)
			run, err := sim.Run(c.Context(), env, simulate.Input{Flow: flow, Params: params})
			if choice, ok := errors.AsType[*simulate.ChoiceError](err); ok {
				return usageErr("%v", choice)
			}
			if err != nil {
				return err
			}
			res, _ := run.Output.(nat.Result)
			a.log.Infof(runlog.TagStep, "nat: fidelity %s", run.Fidelity)

			var un []unresolved
			for _, stg := range run.Stages {
				for _, u := range stg.Unresolved {
					un = append(un, unresolved{Device: run.Device, Vsys: run.Vsys, Value: u.Value, Reason: u.Reason})
				}
			}
			if run.Fidelity.Level() == "undermatch" {
				for _, r := range run.Fidelity.Reasons() {
					un = append(un, unresolved{Device: run.Device, Vsys: run.Vsys, Reason: r})
				}
			}
			un = dedupeUnresolved(un)
			if s.output == "json" {
				in := map[string]any{"flow": flow, "device": device, "router": router, "from_zone": fromZone, "from_interface": fromIf, "at": at}
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
			d, _ := network.Device(run.Device)
			renderNAT(a.stdout, run, res, d.TakenAt, a.now(), fl.why)
			printQualifiers(a, nil, un, nil)
			return finish(nil, un)
		},
	}
	f := cmd.Flags()
	f.StringVar(&device, "device", "", "the firewall (required)")
	f.StringVar(&router, "router", "", "the logical router, when the firewall has several")
	f.StringVar(&fromZone, "from-zone", "", "the zone the packet arrives in")
	f.StringVar(&fromIf, "from-interface", "", "the interface the packet arrives on")
	f.StringVar(&fl.protocol, "protocol", "tcp", "tcp, udp, sctp, icmp or a protocol number")
	f.StringVar(&fl.port, "port", "", "destination port: 443 or tcp/443")
	f.IntVar(&fl.sourcePort, "source-port", 0, "source port")
	f.StringVar(&at, "at", "", "read the newest snapshot at or before this time (id, RFC 3339 or date)")
	f.BoolVar(&fl.why, "why", false, "list the rules above the match and every stage")
	f.BoolVar(&fl.noDNS, "no-dns", false, "resolve no FQDN, neither an endpoint nor a translated destination")
	return cmd
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
