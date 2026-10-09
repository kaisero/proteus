package simulate

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
)

// Endpoint is one side of a flow: an address, or an FQDN and the addresses it
// resolved to.
type Endpoint struct {
	Name     string       `json:"name,omitempty"` // the FQDN; empty for an address
	Addrs    []netip.Addr `json:"addrs"`          // the address, or the FQDN's addresses
	Resolved bool         `json:"resolved"`       // Addrs came from DNS
	// Canonical is the FQDN's canonical name when this machine's resolver
	// reports one other than Name; DNSNotes names it.
	Canonical string `json:"-"`
}

// Addr returns an endpoint for one address.
func Addr(a netip.Addr) Endpoint { return Endpoint{Addrs: []netip.Addr{a}} }

func (e Endpoint) String() string {
	if e.Name != "" {
		return e.Name
	}
	if len(e.Addrs) > 0 {
		return e.Addrs[0].String()
	}
	return ""
}

// Flow is what every simulation in this domain takes. The differences between
// simulations are in what they evaluate, not in the shape of a flow. Spec §11.3.
type Flow struct {
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
	Protocol    string   `json:"protocol"` // tcp, udp, sctp, icmp or a number
	SourcePort  uint16   `json:"source_port,omitempty"`
	DestPort    uint16   `json:"port,omitempty"`
	Application string   `json:"application,omitempty"`
	User        string   `json:"user,omitempty"`
	URL         string   `json:"url,omitempty"`
	FromZone    string   `json:"from_zone,omitempty"` // derived when empty
	ToZone      string   `json:"to_zone,omitempty"`
}

// Input is one simulation's input: a flow, and where to run it.
type Input struct {
	Flow   Flow              `json:"flow"`
	Device string            `json:"device"`
	Vsys   string            `json:"vsys"`
	Params map[string]string `json:"params,omitempty"` // documented per kind
}

// Target is what a simulation reads for one device and vsys.
type Target struct {
	Config *config.Config
	// Indexes gives the vsys's index of a rulebase. The loader's owner builds and
	// keeps the indexes (spec §4.8); a simulation never builds its own. It is the
	// one source of a target's indexes: the security check takes its index here too.
	Indexes   func(resolve.Rulebase) (*index.Index, error)
	Providers index.Providers
	Notes     Reasons
}

// Index is the target's index of a rulebase from its provider. A target without
// a provider is a loader's mistake, reported as an error rather than built here.
func (t Target) Index(rb resolve.Rulebase) (*index.Index, error) {
	if t.Indexes == nil {
		return nil, errors.New("no index provider")
	}
	return t.Indexes(rb)
}

// Env bundles one run's dependencies. It is single-use and not safe for
// concurrent runs.
type Env struct {
	Load func(device, vsys string) (Target, error)
	Log  *runlog.Logger
	// Network is the operational data beyond one device, for a simulation that
	// crosses devices. Nil for a run that needs none.
	Network Network
	// Resolve resolves an FQDN with this machine's DNS; nil resolves nothing. The
	// command layer sets it, so simulations stay free of I/O.
	Resolve func(ctx context.Context, name string) ([]netip.Addr, error)
}

// Stepf writes a STEP line to the run log, for a run that composes simulations
// and says what it does between their stages. A nil log writes nothing.
func (e *Env) Stepf(format string, args ...any) { e.Log.Infof(runlog.TagStep, format, args...) }

// Network is the operational data a simulation reads beyond one device's
// configuration: interface state and routing tables of every device it may cross.
// Configuration still comes through Env.Load, and only for devices a run reaches.
// Spec §17.4.
type Network interface {
	// Devices names one node per firewall; an HA pair is one node.
	Devices() []string
	// Device returns a node's data. A member name of an HA pair returns the pair's
	// node. A device with no usable snapshot is an error naming it.
	Device(name string) (DeviceData, error)
}

// DeviceData is one node's operational data, from one snapshot.
type DeviceData struct {
	Name       string
	Member     string // the inventory member whose snapshot was read; Name for a single device
	SnapshotID string
	TakenAt    time.Time
	Interfaces []resolve.InterfaceState
	FIB        []resolve.FIBRoute
	RIB        []resolve.RIBRoute // nil when the snapshot has none
	Notes      Reasons            // an HA pair, a fetch from the peer, an old snapshot
}

// StageState is the candidate set as a stage left it. Its count answers "why did
// rule 8 win" after the fact; the bitmap is kept only when asked for.
type StageState struct {
	Candidates uint64          `json:"candidates"`
	Bitmap     *roaring.Bitmap `json:"-"`
}

// Stage is one step of a run: its name, what it declared, what it concluded, and
// the state it left behind.
type Stage struct {
	Name       string             `json:"name"`
	Slug       string             `json:"slug"`
	Fidelity   Fidelity           `json:"fidelity"`
	Detail     string             `json:"detail,omitempty"`
	Unresolved []index.Unresolved `json:"unresolved,omitempty"`
	State      StageState         `json:"state"`
	Err        error              `json:"-"`
	Elapsed    time.Duration      `json:"elapsed_ns"`
}

// Run is one simulation of one flow against one device and vsys.
type Run struct {
	Kind     string   `json:"kind"`
	Device   string   `json:"device"`
	Vsys     string   `json:"vsys"`
	Input    Input    `json:"input"`
	Stages   []Stage  `json:"stages"`
	Output   any      `json:"output"`   // the type each kind documents
	Fidelity Fidelity `json:"fidelity"` // the weakest stage's
	Notes    Reasons  `json:"notes,omitempty"`
}

// Simulation is one kind of simulation.
type Simulation interface {
	Kind() string
	Describe() string
	Stages() []string // stage slugs in order, for a plan before running
	Run(ctx context.Context, env *Env, in Input) (Run, error)
}
