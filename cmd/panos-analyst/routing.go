package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/okaiser/panos-analyst/estate"
	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/runlog"
	"github.com/okaiser/panos-analyst/simulate"
	"github.com/okaiser/panos-analyst/simulate/routing"
)

// routingCmd is simulate routing (spec §17). A path crosses devices, so it takes
// no selectors but --device, which names the start (R13).
func (a *app) routingCmd(sim simulate.Simulation) *cobra.Command {
	var device, router, at string
	var rib, why, noDNS bool
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
			if len(argv) == 1 && device == "" {
				return usageErr("give a source, or a start device with --device")
			}
			s, err := a.settings(true)
			if err != nil {
				return err
			}
			var flow simulate.Flow
			if len(argv) == 2 {
				if flow.Source, err = a.endpoint(c.Context(), argv[0], noDNS); err != nil {
					return err
				}
			}
			if flow.Destination, err = a.endpoint(c.Context(), argv[len(argv)-1], noDNS); err != nil {
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
			env := &simulate.Env{
				Log: a.log, Network: estate.NewNetwork(st, s.inv.Names(), when),
				Load: func(dev, vsys string) (simulate.Target, error) {
					ts, holes := estate.Open(st, []string{dev}, []string{vsys}, when)
					if len(ts) == 0 {
						return simulate.Target{}, fmt.Errorf("%s/%s: %v", dev, vsys, holes)
					}
					idx, err := index.For(ts[0].Config, ts[0].Scope)
					if err != nil {
						return simulate.Target{}, err
					}
					return simulate.Target{Config: ts[0].Config, Index: idx, Notes: ts[0].Notes}, nil
				},
			}
			params := map[string]string{"device": device, "router": router}
			if rib {
				params["rib"] = "true"
			}
			a.log.Infof(runlog.TagStep, "routing %s -> %s, start %q", flow.Source, flow.Destination, device)
			run, err := sim.Run(c.Context(), env, simulate.Input{Flow: flow, Params: params})
			var choice *simulate.ChoiceError
			if errors.As(err, &choice) {
				return usageErr("%v", choice)
			}
			if err != nil {
				return err
			}
			path, _ := run.Output.(routing.Path)
			a.log.Infof(runlog.TagStep, "routing: %s, fidelity %s", path.Outcome, run.Fidelity)

			var un []unresolved
			for _, stg := range run.Stages {
				for _, u := range stg.Unresolved {
					un = append(un, unresolved{Device: run.Device, Value: u.Value, Reason: u.Reason})
				}
			}
			un = dedupeUnresolved(un)
			if s.output == "json" {
				in := map[string]any{"flow": flow, "device": device, "router": router, "rib": rib, "at": at}
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
			renderPath(a.stdout, run, path, a.now(), why)
			printQualifiers(a, nil, un, nil)
			return finish(nil, un)
		},
	}
	f := cmd.Flags()
	f.StringVar(&device, "device", "", "start on this device")
	f.StringVar(&router, "router", "", "start in this logical router of --device")
	f.StringVar(&at, "at", "", "read each device's newest snapshot at or before this time (id, RFC 3339 or date)")
	f.BoolVar(&rib, "rib", false, "list the routing table's other routes to the destination at each firewall")
	f.BoolVar(&why, "why", false, "show every stage: its fidelity and what it found")
	f.BoolVar(&noDNS, "no-dns", false, "do not resolve an FQDN endpoint")
	return cmd
}
