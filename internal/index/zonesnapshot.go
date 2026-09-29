package index

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/gaissmai/bart"

	"github.com/okaiser/proteus/internal/resolve"
)

// ZoneSnapshot is a firewall's forwarding table and interface list, as the device
// reported them.
//
// A configuration says what a firewall was told. This says what it is doing, and the
// two differ routinely: on a lab firewall the configuration held one static route and
// the forwarding table held 25, and they disagreed about the default route, so the
// configuration-derived answer was reasoning from a route the device had replaced.
//
// The library defines this format and reads it. Capturing it belongs to the caller,
// because the library performs no network access. scripts/capture-zones.sh is a
// reference implementation, and docs/zone-snapshot-format.md is the prose contract.
//
// The file is one JSON object. InterfacesXML and FIBXML are required and hold the two
// op-command responses verbatim: do not distil, reformat or strip sections, so that a
// capture that went wrong stays distinguishable from a device that answered oddly.
// Both envelopes load — the API's <response><result> and the bare <result> the CLI
// prints with op-command-xml-output on.
//
// Only two parts are read. From the interface list, the ifnet section: name, vsys,
// zone, fwd ("lr:<router>", or "vr:<router>" on older releases, or "N/A") and ip.
// From the forwarding table, one <fibs><entry> per router per address family, where
// type 0 is IPv4 and 1 is IPv6, each holding dst, interface, nexthop and flags.
// Everything else is ignored, so a future release adding fields does no harm.
type ZoneSnapshot struct {
	// TakenAt is provenance and is not enforced. Unlike a user-to-group mapping, a
	// forwarding table is expected to be supplied fresh by whatever captured it, so
	// the library does not second-guess its age.
	TakenAt time.Time `json:"taken_at"`
	Source  string    `json:"source,omitempty"`
	Serial  string    `json:"serial,omitempty"`

	// InterfacesXML is the output of "show interface all".
	InterfacesXML string `json:"interfaces_xml"`
	// FIBXML is the output of "show advanced-routing fib", or of the legacy
	// "show routing fib": both share one handler on the device and one shape.
	FIBXML string `json:"fib_xml"`

	interfaces map[string]resolve.InterfaceState
	tables     map[string]*bart.Table[[]ZonePlacement] // by router
	routers    []string
	// unrouted records interfaces a route leaves by that sit in no zone.
	unrouted map[string]bool
}

// LoadZoneSnapshot reads a snapshot in the library's JSON format and indexes it.
func LoadZoneSnapshot(r io.Reader) (*ZoneSnapshot, error) {
	var s ZoneSnapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return nil, fmt.Errorf("zone snapshot: %w", err)
	}
	if err := s.index(); err != nil {
		return nil, err
	}
	return &s, nil
}

// NewZoneSnapshot builds a snapshot from two op-command responses, so a caller with
// two HTTP bodies need not assemble JSON by hand.
func NewZoneSnapshot(takenAt time.Time, source string, interfaces, fib io.Reader) (*ZoneSnapshot, error) {
	ib, err := io.ReadAll(interfaces)
	if err != nil {
		return nil, fmt.Errorf("zone snapshot: reading interfaces: %w", err)
	}
	fb, err := io.ReadAll(fib)
	if err != nil {
		return nil, fmt.Errorf("zone snapshot: reading fib: %w", err)
	}
	s := &ZoneSnapshot{
		TakenAt:       takenAt,
		Source:        source,
		InterfacesXML: string(ib),
		FIBXML:        string(fb),
	}
	if err := s.index(); err != nil {
		return nil, err
	}
	return s, nil
}

// index parses both documents and builds one longest-prefix table per router.
func (s *ZoneSnapshot) index() error {
	ifaces, err := resolve.ReadInterfaceStates([]byte(s.InterfacesXML))
	if err != nil {
		return fmt.Errorf("zone snapshot: %w", err)
	}
	routes, err := resolve.ReadFIBRoutes([]byte(s.FIBXML))
	if err != nil {
		return fmt.Errorf("zone snapshot: %w", err)
	}

	s.interfaces = make(map[string]resolve.InterfaceState, len(ifaces))
	for _, i := range ifaces {
		s.interfaces[i.Name] = i
	}

	s.tables = map[string]*bart.Table[[]ZonePlacement]{}
	s.unrouted = map[string]bool{}
	seen := map[string]bool{}
	for _, r := range routes {
		iface, known := s.interfaces[r.Interface]
		if !known || iface.Zone == "" {
			// A route can leave by an interface that is in no zone. A lab firewall's
			// default route pointed at tunnel.99, which has none, so nothing the
			// route covers can be placed. Recorded rather than dropped.
			s.unrouted[r.Interface] = true
			continue
		}
		t, ok := s.tables[r.Router]
		if !ok {
			t = new(bart.Table[[]ZonePlacement])
			s.tables[r.Router] = t
		}
		p := ZonePlacement{
			Zone:      iface.Zone,
			Interface: r.Interface,
			Router:    r.Router,
			Route:     r.Destination.String(),
			Vsys:      iface.Vsys,
		}
		if existing, found := t.Get(r.Destination); found {
			t.Insert(r.Destination, append(existing, p))
		} else {
			t.Insert(r.Destination, []ZonePlacement{p})
		}
		if !seen[r.Router] {
			seen[r.Router] = true
			s.routers = append(s.routers, r.Router)
		}
	}
	slices.Sort(s.routers)
	if len(s.tables) == 0 {
		return fmt.Errorf(
			"zone snapshot: no forwarding entry leaves by an interface that is in a zone; " +
				"the two documents may be from different devices")
	}
	return nil
}

// ZonesOf returns every zone the address could arrive on, one lookup per router.
//
// Longest prefix wins within a router, the way a router decides. Across routers there
// is no winner to pick: see ZoneLocator.
func (s *ZoneSnapshot) ZonesOf(addr netip.Addr) []ZonePlacement {
	var out []ZonePlacement
	for _, router := range s.routers {
		if ps, ok := s.tables[router].Lookup(addr); ok {
			out = append(out, ps...)
		}
	}
	return out
}

// Routers returns the logical routers the snapshot covers, in order.
func (s *ZoneSnapshot) Routers() []string {
	return append([]string{}, s.routers...)
}

// UnroutedInterfaces returns the interfaces a forwarding entry leaves by that are in
// no zone, so a caller can see why an address was not placed.
func (s *ZoneSnapshot) UnroutedInterfaces() []string {
	out := make([]string, 0, len(s.unrouted))
	for n := range s.unrouted {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// Describe names the device and time the snapshot came from, for a report line.
func (s *ZoneSnapshot) Describe() string {
	var parts []string
	if s.Source != "" {
		parts = append(parts, s.Source)
	}
	if s.Serial != "" {
		parts = append(parts, "serial "+s.Serial)
	}
	if !s.TakenAt.IsZero() {
		parts = append(parts, "taken "+s.TakenAt.Format(time.RFC3339))
	}
	if len(parts) == 0 {
		return "an unlabelled zone snapshot"
	}
	return strings.Join(parts, ", ")
}
