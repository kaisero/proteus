package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/store"
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

// natResult is simulate nat's result element.
type natResult struct {
	nat.Result
	Fidelity simulate.Fidelity `json:"fidelity"`
	Stages   []stageJSON       `json:"stages"`
}

// natAnswer is simulate nat's answer: one result when the device could be read,
// none when it was a hole.
type natAnswer struct {
	o       natOptions
	flow    simulate.Flow
	run     simulate.Run
	res     nat.Result
	takenAt time.Time
	ok      bool // the simulation ran; false when its device was a hole
	holes   []estate.Hole
	un      []unresolved
	notes   []note
}

func (a *app) runNAT(ctx context.Context, o natOptions) (answer, error) {
	flow, err := parseFlow(o.fl)
	if err != nil {
		return nil, err
	}
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	if _, err := s.inv.Select([]string{o.device}, nil); err != nil {
		return nil, usageErr("%w", err)
	}
	src := o.src
	if src == "-" {
		src = "" // any source
	}
	if err := a.endpoints(ctx, &flow, src, o.dst, o.fl.noDNS); err != nil {
		return nil, err
	}
	es, err := a.openEstate(s, o.at)
	if err != nil {
		return nil, err
	}
	env := es.env(a)
	if o.fl.noDNS {
		env.Resolve = nil
	}
	params := map[string]string{"device": o.device, "router": o.router, "from-zone": o.fromZone, "from-interface": o.fromIf}
	a.log.Infof(runlog.TagStep, "nat %s -> %s on %s", flow.Source, flow.Destination, o.device)
	run, holes, err := runEstate(ctx, o.sim, env, simulate.Input{Flow: flow, Params: params})
	if err != nil {
		return nil, err
	}
	ans := natAnswer{o: o, flow: flow, holes: holes}
	if len(holes) > 0 {
		return ans, nil
	}
	ans.run, ans.ok = run, true
	ans.res, _ = run.Output.(nat.Result)
	a.log.Infof(runlog.TagStep, "nat: fidelity %s", run.Fidelity)
	ans.un = dedupeUnresolved(runUnresolved(run, run.Device, run.Vsys, true))
	d, _ := es.network.Device(run.Device)
	ans.takenAt = d.TakenAt
	ans.notes = runNotes(run.Device, append(append(append(simulate.Reasons{}, run.Notes...), d.Notes...), ans.res.Notes...))
	return ans, nil
}

func (n natAnswer) Command() string { return "simulate nat" }

func (n natAnswer) Input() any {
	return natInput{Flow: n.flow, Device: n.o.device, Router: n.o.router, FromZone: n.o.fromZone, FromInterface: n.o.fromIf, At: n.o.at}
}

func (n natAnswer) Results() any {
	if !n.ok {
		return []natResult{}
	}
	return []natResult{{Result: n.res, Fidelity: n.run.Fidelity, Stages: simStages(n.run.Stages)}}
}

func (n natAnswer) Qualifiers() qualifiers {
	return qualifiers{Holes: n.holes, Unresolved: n.un, Notes: n.notes}
}

func (n natAnswer) Text(t *textOut) error {
	if n.ok {
		renderNAT(t, n.run, n.res, n.takenAt, t.now, n.o.fl.why)
	}
	printQualifiers(t, n.Qualifiers())
	return t.err
}

// runNotes turns a run's note strings into envelope notes for one device, without
// duplicates.
func runNotes(device string, rs simulate.Reasons) []note {
	seen := map[string]bool{}
	var out []note
	for _, r := range rs {
		if !seen[r.Text] {
			seen[r.Text] = true
			out = append(out, noteOf(device, "", r))
		}
	}
	return out
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
	return &simulate.Env{Log: a.log, Network: e.network, Load: storeLoader(e.st, e.when, e.network, nil), Resolve: a.lookup}
}

// runEstate runs a simulation. A choice only the user can make, such as which of two
// firewalls a source enters, is a usage error. Data the simulation could not read is
// returned as holes with no error, so the command answers with them.
func runEstate(ctx context.Context, sim simulate.Simulation, env *simulate.Env, in simulate.Input) (simulate.Run, []estate.Hole, error) {
	run, err := sim.Run(ctx, env, in)
	if u, ok := errors.AsType[*simulate.UnavailableError](err); ok {
		holes := make([]estate.Hole, len(u.Missing))
		for i, m := range u.Missing {
			holes[i] = estate.NewHole(m.Device, "", m.Why())
		}
		return run, holes, nil
	}
	if choice, ok := errors.AsType[*simulate.ChoiceError](err); ok {
		return run, nil, usageErr("%w", choice)
	}
	return run, nil, err
}

// runUnresolved collects what makes a run's answer incomplete: its stages'
// unresolved entries and, with withReasons, the undermatch reasons of an
// under-matching run. Its overmatch reasons stay out: they name rules kept, not
// a gap (CLI spec §4.1).
// vsys is "" when the run spans devices and no single vsys applies.
func runUnresolved(run simulate.Run, device, vsys string, withReasons bool) []unresolved {
	var un []unresolved
	for _, stg := range run.Stages {
		for _, u := range stg.Unresolved {
			un = append(un, unresolved{Device: device, Vsys: vsys, Value: u.Value, Reason: u.Reason, Code: u.Code})
		}
	}
	if withReasons && run.Fidelity.Level() == "undermatch" {
		for _, r := range run.Fidelity.UnderMatchReasons() {
			un = append(un, unresolvedOf(device, vsys, r))
		}
	}
	return un
}

// indexSets keeps one index set per configuration a run reads, so the run builds
// each (configuration, scope, rulebase) index at most once. The run owns it: one
// process answers one command, so it lives as long as the command.
type indexSets map[*config.Config]*index.Set

func (m indexSets) of(cfg *config.Config) *index.Set {
	s, ok := m[cfg]
	if !ok {
		s = index.NewSet(cfg)
		m[cfg] = s
	}
	return s
}

// storeLoader loads a device's vsys configuration and index from the store, as
// every multi-device simulation needs. A device the network knows reads the
// snapshot its routing data came from: for an HA pair, the active member's, not
// the first member's (spec 2026-10-07 §3.4). Each member, snapshot and vsys
// loads once.
func storeLoader(st *store.Store, when estate.When, net *estate.Network, users index.UserDirectory) func(dev, vsys string) (simulate.Target, error) {
	type key struct{ member, snapshot, vsys string }
	cache := map[key]simulate.Target{}
	sets := indexSets{}
	return func(dev, vsys string) (simulate.Target, error) {
		k := key{member: dev, vsys: vsys}
		if d, err := net.Device(dev); err == nil {
			k.member, k.snapshot = d.Member, d.SnapshotID
		}
		if t, ok := cache[k]; ok {
			return t, nil
		}
		var ts []estate.Target
		var holes []estate.Hole
		if k.snapshot != "" {
			// Exactly the snapshot routing read: one without a configuration is
			// a hole, not an older snapshot.
			ts, holes = estate.OpenSnapshot(st, k.member, k.snapshot, []string{vsys}, when)
		} else {
			ts, holes = estate.Open(st, []string{k.member}, []string{vsys}, when)
		}
		if len(ts) == 0 {
			var why []string
			for _, h := range holes {
				why = append(why, h.Reason)
			}
			return simulate.Target{}, fmt.Errorf("%s/%s: %s", dev, vsys, strings.Join(why, "; "))
		}
		set := sets.of(ts[0].Config)
		idx, err := set.Index(ts[0].Scope, resolve.Security)
		if err != nil {
			return simulate.Target{}, err
		}
		t := simulate.Target{
			Config: ts[0].Config, Index: idx, Indexes: set.Provider(ts[0].Scope),
			Providers: index.Providers{Users: users}, Notes: ts[0].Notes,
		}
		cache[k] = t
		return t, nil
	}
}
