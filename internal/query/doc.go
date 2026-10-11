package query

import (
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/simulate"
)

// Doc is an envelope as JSON: what the command line prints with --output json
// and what an MCP tool returns. Echo is the command's input block: the question
// as answered, its flow resolved. Every list prints [] when it is empty (spec
// 2026-09-27 U5). The jsonschema tags describe each key in the generated
// schemas (spec 2026-10-09 §3.6).
type Doc[Echo, Res any] struct {
	Format     int           `json:"format" jsonschema:"the envelope format; a change that breaks a consumer increments it"`
	Command    string        `json:"command" jsonschema:"the command that answered"`
	Detail     string        `json:"detail" jsonschema:"summary or full: how much of each result the envelope holds"`
	Input      Echo          `json:"input" jsonschema:"the question as answered, with the flow as simulated"`
	Results    []Res         `json:"results" jsonschema:"the answers; empty when no target could be read"`
	Summary    *Summary      `json:"summary,omitempty" jsonschema:"search, lookup and snapshot diff only: the count of results over the targets read"`
	Holes      []estate.Hole `json:"holes" jsonschema:"devices or snapshots the answer could not read; each one makes the answer incomplete"`
	Unresolved []Unresolved  `json:"unresolved" jsonschema:"values the answer could not resolve; each one can hide matches"`
	Notes      []Note        `json:"notes" jsonschema:"facts that qualify the answer without making it incomplete, such as a stale snapshot"`
}

// Echoer is an input that gives its envelope's input block.
type Echoer[E any] interface{ Echo() E }

// DocOf is an envelope's JSON form, every list non-nil.
func DocOf[In Echoer[E], E, Res any](e Envelope[In, Res]) Doc[E, Res] {
	return Doc[E, Res]{
		Format: e.Format, Command: e.Command, Detail: e.Detail, Input: e.Input.Echo(),
		Results: nonNil(e.Results), Summary: e.Summary,
		Holes: nonNil(e.Holes), Unresolved: nonNil(e.Unresolved), Notes: nonNil(e.Notes),
	}
}

// FileEcho is simulate policy's input block on one configuration.
type FileEcho struct {
	Flow      simulate.Flow `json:"flow" jsonschema:"the flow as simulated: endpoints resolved, ports as numbers"`
	Selection Selection     `json:"selection" jsonschema:"the configuration file and vsys asked"`
}

// Echo is the input block.
func (in PolicyFileInput) Echo() FileEcho {
	return FileEcho{Flow: in.Simulated, Selection: in.Selection}
}

// PathEcho is simulate policy's input block along the path (spec 2026-10-07
// §8.2).
type PathEcho struct {
	Mode   string        `json:"mode" jsonschema:"path: the flow is checked on every firewall it crosses"`
	Flow   simulate.Flow `json:"flow" jsonschema:"the flow as simulated: endpoints resolved, ports as numbers"`
	Device string        `json:"device" jsonschema:"the firewall the path starts on; empty when the source places the start"`
	Router string        `json:"router" jsonschema:"the start's logical router; empty when it has one"`
	At     string        `json:"at" jsonschema:"the time each device's snapshot is read at or before; empty for the latest"`
}

// Echo is the input block.
func (in PolicyInput) Echo() PathEcho {
	return PathEcho{Mode: "path", Flow: in.Simulated, Device: in.Device, Router: in.Router, At: in.At}
}

// RoutingEcho is simulate routing's input block.
type RoutingEcho struct {
	At     string        `json:"at" jsonschema:"the time each device's snapshot is read at or before; empty for the latest"`
	Device string        `json:"device" jsonschema:"the firewall the path starts on; empty when the source places the start"`
	Flow   simulate.Flow `json:"flow" jsonschema:"the flow as simulated: endpoints resolved, ports as numbers"`
	RIB    bool          `json:"rib" jsonschema:"whether each hop lists the routing table's other routes to the destination"`
	Router string        `json:"router" jsonschema:"the start's logical router; empty when it has one"`
}

// Echo is the input block.
func (in RoutingInput) Echo() RoutingEcho {
	return RoutingEcho{Flow: in.Simulated, Device: in.Device, Router: in.Router, RIB: in.RIB, At: in.At}
}

// NATEcho is simulate nat's input block.
type NATEcho struct {
	At            string        `json:"at" jsonschema:"the time the device's snapshot is read at or before; empty for the latest"`
	Device        string        `json:"device" jsonschema:"the firewall"`
	Flow          simulate.Flow `json:"flow" jsonschema:"the packet as simulated: endpoints resolved, ports as numbers"`
	FromInterface string        `json:"from_interface" jsonschema:"the ingress interface given; empty when the forwarding table gives it"`
	FromZone      string        `json:"from_zone" jsonschema:"the ingress zone given; empty when the forwarding table gives it"`
	Router        string        `json:"router" jsonschema:"the logical router; empty when the device has one"`
}

// Echo is the input block.
func (in NATInput) Echo() NATEcho {
	return NATEcho{Flow: in.Simulated, Device: in.Device, Router: in.Router, FromZone: in.FromZone, FromInterface: in.FromInterface, At: in.At}
}

// SearchEcho is search's input block.
type SearchEcho struct {
	Direct    bool      `json:"direct" jsonschema:"whether groups are followed one level up only"`
	Fields    []string  `json:"fields" jsonschema:"the rule fields searched; empty for every field"`
	Kinds     []string  `json:"kinds" jsonschema:"the object kinds searched; empty for every kind"`
	Limit     int       `json:"limit" jsonschema:"the most results kept; 0 for every result"`
	Mode      string    `json:"mode" jsonschema:"how the term matches: the mode asked (exact, within or contains) or the one the term sets (covers, overlaps or matches)"`
	Selection Selection `json:"selection" jsonschema:"the file or the devices searched"`
	Show      []string  `json:"show" jsonschema:"the finding stages shown; empty for every stage"`
	Term      string    `json:"term" jsonschema:"the value or name searched for"`
}

// Echo is the input block.
func (in SearchInput) Echo() SearchEcho {
	return SearchEcho{
		Term: in.Term, Mode: in.Matching(), Kinds: in.Kinds, Fields: in.Fields, Show: in.Show,
		Direct: in.Direct, Selection: in.Selection, Limit: in.Limit,
	}
}

// LookupEcho is lookup's input block.
type LookupEcho struct {
	Expand    bool      `json:"expand" jsonschema:"whether the text card expands groups"`
	Full      bool      `json:"full" jsonschema:"whether the text card shows every field"`
	Kind      string    `json:"kind" jsonschema:"the kind asked for; empty for any kind"`
	Limit     int       `json:"limit" jsonschema:"the most results kept; 0 for every result"`
	Name      string    `json:"name" jsonschema:"the rule or object name looked up"`
	Selection Selection `json:"selection" jsonschema:"the file or the devices read"`
}

// Echo is the input block.
func (in LookupInput) Echo() LookupEcho {
	return LookupEcho{Name: in.Name, Kind: in.Kind, Expand: in.Expand, Full: in.Full, Selection: in.Selection, Limit: in.Limit}
}

// DiffEcho is snapshot diff's input block.
type DiffEcho struct {
	From      string    `json:"from" jsonschema:"the older point in time; empty for the snapshot before the newer one"`
	Limit     int       `json:"limit" jsonschema:"the most results kept; 0 for every result"`
	Selection Selection `json:"selection" jsonschema:"the devices compared"`
	To        string    `json:"to" jsonschema:"the newer point in time; empty for the latest snapshot"`
}

// Echo is the input block.
func (in DiffInput) Echo() DiffEcho {
	return DiffEcho{Selection: in.Selection, From: in.From, To: in.To, Limit: in.Limit}
}
