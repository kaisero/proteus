package simulate

import (
	"net/netip"
	"strings"

	"github.com/okaiser/panos-analyst/resolve"
)

// Port is one interface of one firewall, with the address that placed it. The
// routing, NAT and security-policy simulations share it (spec §18.4).
type Port struct {
	Device    string       `json:"device"`
	Vsys      string       `json:"vsys"` // as the device reports it: "1"
	Router    string       `json:"router"`
	Interface string       `json:"interface"`
	Zone      string       `json:"zone,omitempty"`
	Addr      netip.Prefix `json:"address,omitzero"` // the interface address; its masked form is the link net
}

// Link is the net a port's address sits in.
func (p Port) Link() netip.Prefix { return p.Addr.Masked() }

// Match is the forwarding entry a lookup found: the destination prefix and every
// next hop the table holds for it, sorted by next-hop address (spec §17 R4).
type Match struct {
	Destination netip.Prefix       `json:"destination"`
	NextHops    []resolve.FIBRoute `json:"next_hops"`
}

// First is the next hop the path follows.
func (m Match) First() resolve.FIBRoute { return m.NextHops[0] }

// The ends of one route lookup that forward nothing.
const (
	EndLocal       = "local"        // an address of the firewall itself
	EndNoRoute     = "no-route"     // nothing covers the address
	EndDiscard     = "discard"      // the route discards (not yet seen on a device)
	EndUnknownType = "unknown-type" // a next-hop type not read yet
)

// Forward is one route lookup's whole answer: where the packet leaves, the routes
// that decided it, and how certain that is.
type Forward struct {
	Out      Port     `json:"out"`           // the egress, or the interface owning a local address
	Routes   []Match  `json:"routes"`        // one per router crossed
	End      string   `json:"end,omitempty"` // "" when the packet leaves by Out
	Fidelity Fidelity `json:"fidelity"`
	Notes    []string `json:"notes,omitempty"`
}

// ChoiceError is a question only the user can answer: which device, which router,
// which of several starts. A command turns it into a usage error.
type ChoiceError struct {
	Question string
	Options  []string
}

func (e *ChoiceError) Error() string {
	if len(e.Options) == 0 {
		return e.Question
	}
	return e.Question + ": " + strings.Join(e.Options, ", ")
}
