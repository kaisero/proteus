package routing

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/okaiser/panos-analyst/resolve"
	"github.com/okaiser/panos-analyst/simulate"
	"github.com/okaiser/panos-analyst/simulate/topology"
)

// Kind is the registry key and the command name.
const Kind = "routing"

// MaxHops is where a path stops as too long (spec §17 R7).
const MaxHops = 16

// Simulation is the routing simulation.
type Simulation struct{}

var _ simulate.Simulation = Simulation{}

// Kind implements simulate.Simulation.
func (Simulation) Kind() string { return Kind }

// Describe implements simulate.Simulation.
func (Simulation) Describe() string {
	return "which firewalls a packet crosses, and by which interfaces, zones and routes"
}

// Stages implements simulate.Simulation: place runs once, the others once per hop
// as hop<N>/<stage>, in PAN-OS packet-flow order (spec §17.4).
func (Simulation) Stages() []string {
	return []string{"place", "pbf", "lookup", "zones", "nat", "next"}
}

// Outcome is how a path ends.
type Outcome string

// The ends of a path (spec §17 R6, R7).
const (
	Delivered       Outcome = "delivered"         // into a connected net
	Local           Outcome = "local"             // an address of the device itself
	LeftEstate      Outcome = "left-estate"       // to a next hop no node owns
	LeftByInterface Outcome = "left-by-interface" // by an interface, outside its net
	Dropped         Outcome = "dropped"           // no route, or a discarding one
	Loop            Outcome = "loop"
	TooLong         Outcome = "too-long"
	Unresolved      Outcome = "unresolved"
)

// Lookup is one route lookup in one router.
type Lookup struct {
	Router   string         `json:"router"`
	Match    simulate.Match `json:"route"`
	Protocol string         `json:"protocol,omitempty"` // from the routing table; empty without one
}

// NotFollowed is an ECMP next hop the path did not take, and the node it reaches.
type NotFollowed struct {
	NextHop string `json:"next_hop"`
	Reaches string `json:"reaches,omitempty"`
}

// Hop is one device and vsys on the path: one box of the output (spec §17 R16).
type Hop struct {
	Device     string             `json:"device"`
	Vsys       string             `json:"vsys"`
	SnapshotID string             `json:"snapshot,omitempty"`
	TakenAt    time.Time          `json:"taken_at,omitzero"`
	In         simulate.Port      `json:"in"`
	Out        simulate.Port      `json:"out"`
	Lookups    []Lookup           `json:"lookups"`
	Flow       simulate.Flow      `json:"flow"`     // pre-NAT, with this hop's zones
	PostNAT    *simulate.Flow     `json:"post_nat"` // nil until NAT is simulated
	ECMP       []NotFollowed      `json:"ecmp_not_followed,omitempty"`
	Alternates []resolve.RIBRoute `json:"alternates,omitempty"`
	Notes      []string           `json:"notes,omitempty"`
	Fidelity   simulate.Fidelity  `json:"fidelity"`
}

// Path is a run's output.
type Path struct {
	Source      simulate.Endpoint `json:"source"`
	Destination simulate.Endpoint `json:"destination"`
	Placed      topology.Placed   `json:"placed"`
	PlacedVia   string            `json:"placed_via,omitempty"`
	Outcome     Outcome           `json:"outcome"`
	End         string            `json:"end"` // the end line's text
	Hops        []Hop             `json:"hops"`
	Hidden      []string          `json:"hidden,omitempty"` // spec §17 R19
	Notes       []string          `json:"notes,omitempty"`
}

// Run implements simulate.Simulation.
//
// Params: "device" starts the path on that node, "router" in that router, "rib"
// ("true") lists the routing table's alternates at each hop.
func (Simulation) Run(ctx context.Context, env *simulate.Env, in simulate.Input) (simulate.Run, error) {
	run := simulate.Run{Kind: Kind, Device: in.Params["device"], Input: in}
	if env.Network == nil {
		return run, errors.New("routing: no network to read")
	}
	if len(in.Flow.Destination.Addrs) == 0 || !in.Flow.Destination.Addrs[0].Is4() {
		return run, &simulate.ChoiceError{Question: "the destination must be an IPv4 address; IPv6 is not simulated yet"}
	}
	if a := in.Flow.Source.Addrs; len(a) > 0 && !a[0].Is4() {
		return run, &simulate.ChoiceError{Question: "the source must be an IPv4 address; IPv6 is not simulated yet"}
	}
	s := newState(env, in)
	s.path.Notes = append(s.path.Notes, endpointNotes(in.Flow)...)
	stages, err := simulate.Execute(ctx, Kind, s, []simulate.Step[state]{{Name: "place the start", Slug: "place", Do: place}}, false, env.Log)
	run.Stages = append(run.Stages, stages...)
	for err == nil && !s.done {
		s.newHop()
		stages, err = simulate.Execute(ctx, Kind, s, hopSteps(len(s.path.Hops)), false, env.Log)
		run.Stages = append(run.Stages, stages...)
		s.closeHop(stages)
	}
	if len(s.path.Hops) > 0 {
		run.Device, run.Vsys = s.path.Hops[0].Device, s.path.Hops[0].Vsys
	}
	s.hidden()
	run.Fidelity = simulate.Overall(run.Stages)
	run.Output = s.path
	return run, err
}

// endpointNotes names what an FQDN resolved to beyond the address traced.
func endpointNotes(f simulate.Flow) []string {
	var out []string
	for _, ep := range []simulate.Endpoint{f.Source, f.Destination} {
		if ep.Name != "" && len(ep.Addrs) > 1 {
			var rest []string
			for _, a := range ep.Addrs[1:] {
				rest = append(rest, a.String())
			}
			out = append(out, fmt.Sprintf("%s resolved to %d addresses; traced %s, not %s", ep.Name, len(ep.Addrs), ep.Addrs[0], strings.Join(rest, ", ")))
		}
	}
	return out
}

func hopSteps(n int) []simulate.Step[state] {
	p := fmt.Sprintf("hop%d/", n)
	return []simulate.Step[state]{
		{Name: "policy-based forwarding", Slug: p + "pbf", Do: pbf},
		{Name: "route lookup", Slug: p + "lookup", Do: lookup},
		{Name: "zones", Slug: p + "zones", Do: zones},
		{Name: "NAT", Slug: p + "nat", Do: nat},
		{Name: "next hop", Slug: p + "next", Do: next},
	}
}

// vsysName maps the number an interface reports to the configuration's name.
// Vsys entries are named vsys<N> in the firewall schema.
func vsysName(n string) string {
	if n == "" || strings.HasPrefix(n, "vsys") {
		return n
	}
	return "vsys" + n
}

func addr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	return a, err == nil && !a.IsUnspecified()
}
