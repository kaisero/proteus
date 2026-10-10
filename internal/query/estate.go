package query

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/store"
)

// Errors of an env that lacks what a query reads. The command line always
// gives both; they say what a caller left out.
var (
	errNoInventory = errors.New("no inventory: no device to read")
	errNoStore     = errors.New("no snapshot store")
)

// Selection is what a question runs against: one configuration file, or the
// selected devices' snapshots. Only the fields given appear in JSON.
type Selection struct {
	At     string   `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; empty for the latest"`
	Device []string `json:"device,omitempty" jsonschema:"the devices to read; empty for every device"`
	File   string   `json:"file,omitempty" jsonschema:"one configuration file to read in place of the store"`
	Fresh  bool     `json:"fresh,omitempty" jsonschema:"fetch the devices before reading them"`
	Label  []string `json:"label,omitempty" jsonschema:"select devices by label, key=value"`
	Vsys   []string `json:"vsys,omitempty" jsonschema:"the vsys to read; empty for every vsys"`
}

// parseAt reads a point in time, or the zero time for none.
func parseAt(at string) (estate.When, *UsageError) {
	var when estate.When
	if at == "" {
		return when, nil
	}
	var err error
	if when.At, err = estate.ParseAt(at); err != nil {
		// The text names the flag: --at "x": want ...
		return when, usageOf(err, err.Error(), strings.TrimPrefix(err.Error(), "--"))
	}
	return when, nil
}

// Targets opens what a question runs against: one file, or the selected devices'
// snapshots. What a fresh fetch found becomes notes on that device's targets.
func Targets(ctx context.Context, env Env, sel Selection) ([]estate.Target, []estate.Hole, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if sel.File != "" {
		return estate.OpenFile(sel.File, sel.Vsys, env.Log)
	}
	if env.Inventory == nil {
		return nil, nil, errNoInventory
	}
	names, err := env.Inventory.Select(sel.Device, sel.Label)
	if err != nil {
		return nil, nil, usageOf(err, err.Error(), "")
	}
	if len(names) == 0 {
		return nil, nil, usage("the selection matches no device", "")
	}
	when, u := parseAt(sel.At)
	if u != nil {
		return nil, nil, u
	}
	when.Now, when.MaxAge, when.Log, when.Ops, when.Configs = env.now(), env.MaxAge, env.Log, env.Ops, env.Configs
	if env.Store == nil {
		return nil, nil, errNoStore
	}
	var fresh map[string][]reason.Reason
	if sel.Fresh {
		if env.Fresh == nil {
			return nil, nil, usage("--fresh: this front end does not fetch", "fresh: this server does not fetch")
		}
		if fresh, err = env.Fresh(ctx, names); err != nil {
			return nil, nil, err
		}
	}
	ts, holes := estate.Open(env.Store, names, sel.Vsys, when)
	for i := range ts {
		// A copy: the target's notes may share their array with a cached load.
		ts[i].Notes = append(slices.Clone(ts[i].Notes), fresh[ts[i].Device]...)
	}
	return ts, holes, nil
}

// TargetQualifiers splits each target's notes: a version gap can make an answer
// miss rules, so it is unresolved; a stale snapshot or a failed fresh fetch is a
// note.
func TargetQualifiers(ts []estate.Target) ([]Unresolved, []Note) {
	var un []Unresolved
	var notes []Note
	for _, t := range ts {
		for _, n := range t.Notes {
			if n.Code == "gap.version" {
				un = append(un, UnresolvedOf(t.Device, t.Vsys, n))
				continue
			}
			notes = append(notes, NoteOf(t.Device, t.Vsys, n))
		}
	}
	return un, notes
}

// indexSets keeps one index set per configuration a query reads, so it builds
// each (configuration, scope, rulebase) index at most once. The query owns it
// and drops it when it returns. A target whose source keeps its indexes, as a
// server's cache does, uses those.
type indexSets map[*config.Config]*index.Set

func (m indexSets) of(t estate.Target) estate.Indexes {
	if t.Indexes != nil {
		return t.Indexes
	}
	s, ok := m[t.Config]
	if !ok {
		s = index.NewSet(t.Config)
		m[t.Config] = s
	}
	return s
}

// indexesOf is a target's own indexes, or a new set over its configuration.
func indexesOf(t estate.Target) estate.Indexes {
	if t.Indexes != nil {
		return t.Indexes
	}
	return index.NewSet(t.Config)
}

// provider is a scope's index of any rulebase, the shape a simulation's
// target carries.
func provider(ix estate.Indexes, sc config.Scope) func(resolve.Rulebase) (*index.Index, error) {
	return func(rb resolve.Rulebase) (*index.Index, error) { return ix.Index(sc, rb) }
}

// fetchedEstate is the store at one point in time, for the simulations that
// follow a packet across devices.
type fetchedEstate struct {
	st      *store.Store
	when    estate.When
	network *estate.Network
}

// openEstate is the inventory's devices in the store at a time, "" for the
// newest snapshots.
func openEstate(env Env, at string) (fetchedEstate, error) {
	if env.Inventory == nil {
		return fetchedEstate{}, errNoInventory
	}
	when, u := parseAt(at)
	if u != nil {
		return fetchedEstate{}, u
	}
	when.Now, when.MaxAge, when.Log, when.Ops, when.Configs = env.now(), env.MaxAge, env.Log, env.Ops, env.Configs
	if env.Store == nil {
		return fetchedEstate{}, errNoStore
	}
	return fetchedEstate{st: env.Store, when: when, network: estate.NewNetwork(env.Store, env.Inventory.Names(), when)}, nil
}

// simEnv is a simulation environment over the estate, resolving FQDNs with
// the env's resolver.
func (e fetchedEstate) simEnv(env Env) *simulate.Env {
	return &simulate.Env{Log: env.Log, Network: e.network, Load: storeLoader(e.st, e.when, e.network, nil), Resolve: env.Resolve}
}

// storeLoader loads a device's vsys configuration and index from the store, as
// every multi-device simulation needs. A device the network knows reads the
// snapshot its routing data came from: for an HA pair, the active member's, not
// the first member's (spec 2026-10-07 §3.4). Each member, snapshot and vsys
// loads once, and the vsys of one snapshot share its configuration and index set,
// so the edge list of a snapshot is read once however many vsys a run visits.
func storeLoader(st *store.Store, when estate.When, net *estate.Network, users index.UserDirectory) func(dev, vsys string) (simulate.Target, error) {
	type key struct{ member, snapshot, vsys string }
	type snap struct{ member, id string }
	cache := map[key]simulate.Target{}
	sets := map[snap]estate.Indexes{}
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
			// The code is the first hole's whose code is more specific than
			// gap.load-failed, such as a missing configuration.
			code := reason.Code("gap.load-failed")
			var why []string
			for _, h := range holes {
				why = append(why, h.Reason)
				if code == "gap.load-failed" && h.Code != "" {
					code = h.Code
				}
			}
			return simulate.Target{}, &simulate.CodedError{Reason: reason.Reason{
				Code: code, Text: fmt.Sprintf("%s/%s: %s", dev, vsys, strings.Join(why, "; ")),
			}}
		}
		sk := snap{member: k.member, id: k.snapshot}
		if ts[0].Snapshot != nil {
			sk.id = ts[0].Snapshot.ID
		}
		set, ok := sets[sk]
		if !ok {
			set = indexesOf(ts[0])
			sets[sk] = set
		}
		// Built here, so a failed build is the load's error.
		if _, err := set.Index(ts[0].Scope, resolve.Security); err != nil {
			return simulate.Target{}, err
		}
		t := simulate.Target{
			Config: ts[0].Config, Indexes: provider(set, ts[0].Scope),
			Providers: index.Providers{Users: users}, Notes: ts[0].Notes,
		}
		cache[k] = t
		return t, nil
	}
}

// holesOf turns what a simulation could not read into holes.
func holesOf(ms []simulate.Missing) []estate.Hole {
	var out []estate.Hole
	for _, m := range ms {
		out = append(out, estate.NewHole(m.Device, "", m.Why()))
	}
	return out
}

// runUnresolved collects what makes a run's answer incomplete: its stages'
// unresolved entries and, with withReasons, the undermatch reasons of an
// under-matching run. Its overmatch reasons stay out: they name rules kept, not
// a gap (CLI spec §4.1).
// vsys is "" when the run spans devices and no single vsys applies.
func runUnresolved(run simulate.Run, device, vsys string, withReasons bool) []Unresolved {
	var un []Unresolved
	for _, stg := range run.Stages {
		for _, u := range stg.Unresolved {
			un = append(un, Unresolved{Device: device, Vsys: vsys, Value: u.Value, Reason: u.Reason, Code: u.Code})
		}
	}
	if withReasons && run.Fidelity.Level() == "undermatch" {
		for _, g := range run.Fidelity.UnderMatchGroups() {
			un = append(un, UnresolvedOfParts(device, vsys, g)...)
		}
	}
	return un
}

// runNotes turns a run's notes into envelope notes for one device, without
// duplicates.
func runNotes(device string, rs simulate.Reasons) []Note {
	seen := map[string]bool{}
	var out []Note
	for _, r := range rs {
		if !seen[r.Text] {
			seen[r.Text] = true
			out = append(out, NoteOf(device, "", r))
		}
	}
	return out
}

// dedupeUnresolved keeps one entry per device, vsys and reason. A stage's
// unresolved entry and the run's fidelity can carry the same reason. A
// composite reason's parts go or stay together: it is the same when its whole
// text is.
func dedupeUnresolved(in []Unresolved) []Unresolved {
	seen := map[string]bool{}
	var out []Unresolved
	for i := 0; i < len(in); {
		j := i + 1
		for j < len(in) && in[j].Part {
			j++
		}
		texts := make([]string, 0, j-i)
		for _, u := range in[i:j] {
			texts = append(texts, u.Reason)
		}
		k := in[i].Device + "|" + in[i].Vsys + "|" + strings.Join(texts, "; ")
		if !seen[k] {
			seen[k] = true
			out = append(out, in[i:j]...)
		}
		i = j
	}
	return out
}

// runEstate runs a simulation over the estate. Data the simulation could not
// read is returned as holes with no error, so the query answers with them. A
// choice only the caller can make, such as which of two firewalls a source
// enters, is the simulation's *simulate.ChoiceError.
func runEstate(ctx context.Context, sim simulate.Simulation, env *simulate.Env, in simulate.Input) (simulate.Run, []estate.Hole, error) {
	run, err := sim.Run(ctx, env, in)
	if u, ok := errors.AsType[*simulate.UnavailableError](err); ok {
		return run, holesOf(u.Missing), nil
	}
	return run, nil, err
}
