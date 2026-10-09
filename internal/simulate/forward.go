package simulate

import (
	"net/netip"
	"strings"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
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
	// Kind is what the user chooses: ChoiceDevice or ChoiceRouter, from
	// Options. It is empty for a question that offers no choice, such as an
	// input the simulation cannot take; that stays a usage error.
	Kind     string
	Question string
	Options  []string
}

// The kinds of choice.
const (
	ChoiceDevice = "device"
	ChoiceRouter = "router"
)

func (e *ChoiceError) Error() string {
	if len(e.Options) == 0 {
		return e.Question
	}
	return e.Question + ": " + strings.Join(e.Options, ", ")
}

// UnavailableError says a simulation could not read data it needs, such as a device
// with no usable snapshot. It is not the user's to fix on the command line; the
// command layer reports one hole per Missing entry.
type UnavailableError struct {
	Missing []Missing
}

// Missing is one device a simulation could not read, and why.
type Missing struct {
	Device string
	Reason string
	Code   reason.Code `json:"-"` // the kind of Reason; out of the JSON until format 2
}

// CodedError is an error that keeps the kind of a failure as a reason code. A
// loader returns one so a simulation that reports the failure keeps its kind, as
// gap.config-missing for a snapshot without a configuration.
type CodedError struct {
	Reason reason.Reason
}

// Error is the reason's text.
func (e *CodedError) Error() string { return e.Reason.Text }

// Code is the kind of the failure.
func (e *CodedError) Code() reason.Code { return e.Reason.Code }

// NewMissing returns a Missing entry for device with r's code and text.
func NewMissing(device string, r reason.Reason) Missing {
	return Missing{Device: device, Reason: r.Text, Code: r.Code}
}

// Why returns the entry's code and text as one reason.
func (m Missing) Why() reason.Reason { return reason.Reason{Code: m.Code, Text: m.Reason} }

// Error is the reason alone for one device, so a message that embeds it reads as
// before; "device: reason; device: reason" for several.
func (e *UnavailableError) Error() string {
	if len(e.Missing) == 1 {
		return e.Missing[0].Reason
	}
	parts := make([]string, len(e.Missing))
	for i, m := range e.Missing {
		parts[i] = m.Device + ": " + m.Reason
	}
	return strings.Join(parts, "; ")
}
