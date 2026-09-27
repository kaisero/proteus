package index

import (
	"net/netip"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/gaissmai/bart"

	"github.com/okaiser/go-panos-schema/config"
	"github.com/okaiser/go-panos-schema/resolve"
)

// zoneResolver answers which zone an address could arrive on, from the configuration
// alone.
//
// A zone is a set of interfaces, and which addresses reach an interface is decided by
// routing. So this is a small routing table: connected prefixes from interface
// addresses, plus configured static routes, each mapped through its interface to the
// zone holding it. Longest prefix wins, the way a router decides.
//
// It is an inference, not a reading, and it has real limits which it reports rather
// than hides. Routes learned by BGP or OSPF are not in the file. An interface in no
// zone places nothing. On Panorama the network configuration lives in a template, so a
// device-group scope has no zones at all. And a firewall decides a source zone by the
// interface a packet actually arrived on, which is why the device's own
// test security-policy-match takes the zone as an argument instead of working it out.
type zoneResolver struct {
	table *bart.Table[[]Hit]
	// zonesOf records, for each interface, the zones holding it.
	zonesOf map[string][]zoneRef
	limits  []Unresolved
	empty   bool
}

type zoneRef struct {
	name  string
	scope config.Scope
}

const kindZone = "zone"

func newZoneResolver(
	zones []resolve.Zone,
	addrs []resolve.InterfaceAddress,
	routes []resolve.StaticRoute,
	dynamic []string,
) *zoneResolver {
	r := &zoneResolver{table: new(bart.Table[[]Hit]), zonesOf: map[string][]zoneRef{}}

	for _, z := range zones {
		for _, iface := range z.Interfaces {
			key := strings.ToLower(iface)
			r.zonesOf[key] = append(r.zonesOf[key], zoneRef{name: z.Name, scope: z.Scope})
		}
		if len(z.Interfaces) == 0 {
			r.limits = append(r.limits, Unresolved{
				Value:  z.Name,
				Kind:   kindZone,
				Reason: "this zone has no interface assigned, so no address can be placed in it",
			})
		}
	}
	if len(zones) == 0 {
		r.empty = true
	}

	// Connected prefixes: an address on an interface means that prefix arrives there.
	for _, a := range addrs {
		r.insert(a.Prefix.Masked(), a.Interface, a.Prefix.String())
	}
	// Static routes that name an egress interface tie a destination to that
	// interface's zone. A route with only a next hop resolves through another route,
	// which the file cannot follow reliably, so it is left alone.
	for _, rt := range routes {
		if rt.Interface == "" {
			continue
		}
		r.insert(rt.Destination, rt.Interface, "static route "+rt.Name)
	}

	for _, d := range dynamic {
		r.limits = append(r.limits, Unresolved{
			Value: d,
			Kind:  kindZone,
			Reason: "this virtual router learns routes at runtime, and a route learned that " +
				"way is not in the configuration, so an address reachable only by it cannot " +
				"be placed in a zone",
		})
	}
	return r
}

func (r *zoneResolver) insert(p netip.Prefix, iface, via string) {
	refs, ok := r.zonesOf[strings.ToLower(iface)]
	if !ok {
		// An interface in no zone carries traffic nowhere a policy can name.
		r.limits = append(r.limits, Unresolved{
			Value: iface,
			Kind:  kindZone,
			Reason: "interface " + iface + " is in no zone, so " + p.String() +
				" cannot be placed in one",
		})
		return
	}
	hits := make([]Hit, 0, len(refs))
	for _, ref := range refs {
		hits = append(hits, Hit{Name: ref.name, Kind: kindZone, Scope: ref.scope, Via: iface + " " + via})
	}
	if existing, found := r.table.Get(p); found {
		r.table.Insert(p, append(existing, hits...))
		return
	}
	r.table.Insert(p, hits)
}

func (r *zoneResolver) kinds() []string { return []string{kindZone} }

// resolve returns the zones an address could arrive on. Longest prefix wins, so a
// specific route beats a default one, as it does on a router.
func (r *zoneResolver) resolve(value string, _ Providers) ([]Hit, []Unresolved, bool) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		p, perr := netip.ParsePrefix(value)
		if perr != nil {
			return nil, nil, false
		}
		addr = p.Addr()
	}
	if r.empty {
		return nil, []Unresolved{{
			Value: value,
			Kind:  kindZone,
			Reason: "this scope defines no zones. On Panorama they live in a template, not in " +
				"a device group, so an address cannot be placed in a zone from here",
		}}, true
	}

	hits, found := r.table.Lookup(addr)
	if !found {
		return nil, append(r.limitsCopy(), Unresolved{
			Value: value,
			Kind:  kindZone,
			Reason: "no interface address and no static route in this configuration covers " +
				"this address, so the zone it would arrive on is unknown",
		}), true
	}
	return hits, r.limitsCopy(), true
}

func (r *zoneResolver) limitsCopy() []Unresolved {
	return append([]Unresolved{}, r.limits...)
}

// literalRules returns nothing: a rule's from and to fields name zones.
func (r *zoneResolver) literalRules(Field, string) *roaring.Bitmap { return roaring.New() }

func (r *zoneResolver) search(substr string) []Hit {
	want := strings.ToLower(substr)
	var out []Hit
	for p, hits := range r.table.All() {
		if strings.Contains(strings.ToLower(p.String()), want) {
			out = append(out, hits...)
		}
	}
	return out
}
