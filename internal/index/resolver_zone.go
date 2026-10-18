package index

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/gaissmai/bart"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
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
// zone places nothing. And a firewall decides a source zone by the interface a
// packet actually arrived on, which is why the device's own test
// security-policy-match takes the zone as an argument instead of working it out.
type zoneResolver struct {
	scope config.Scope
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
	sc config.Scope,
	zones []resolve.Zone,
	addrs []resolve.InterfaceAddress,
	routes []resolve.StaticRoute,
	dynamic []string,
) *zoneResolver {
	r := &zoneResolver{scope: sc, table: new(bart.Table[[]Hit]), zonesOf: map[string][]zoneRef{}}

	for _, z := range zones {
		for _, iface := range z.Interfaces {
			key := strings.ToLower(iface)
			r.zonesOf[key] = append(r.zonesOf[key], zoneRef{name: z.Name, scope: z.Scope})
		}
		if len(z.Interfaces) == 0 {
			r.limits = append(r.limits, NewUnresolved(z.Name, kindZone, reason.New("zone.no-interface",
				"this zone has no interface assigned, so no address can be placed in it")))
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
	// which the file cannot follow reliably, so it is left alone. The placement
	// ends with the route's prefix, as a forwarding table's does, so a reader can
	// tell a default route.
	for _, rt := range routes {
		if rt.Interface == "" {
			continue
		}
		r.insert(rt.Destination, rt.Interface, "static route "+rt.Name+" "+rt.Destination.String())
	}

	for _, d := range dynamic {
		r.limits = append(r.limits, NewUnresolved(d, kindZone, reason.New("zone.dynamic-routing",
			"this virtual router learns routes at runtime, and a route learned that "+
				"way is not in the configuration, so an address reachable only by it cannot "+
				"be placed in a zone")))
	}
	return r
}

func (r *zoneResolver) insert(p netip.Prefix, iface, via string) {
	refs, ok := r.zonesOf[strings.ToLower(iface)]
	if !ok {
		// An interface in no zone carries traffic nowhere a policy can name.
		r.limits = append(r.limits, NewUnresolved(iface, kindZone, reason.New("zone.interface-unzoned",
			"interface "+iface+" is in no zone, so "+p.String()+
				" cannot be placed in one")))
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

// resolve returns the zones an address could arrive on.
//
// A snapshot of the device's own forwarding table answers if the caller supplied one,
// and it is authoritative: when it places nothing, the configuration is not consulted
// instead. Falling back there would hide a real disagreement, and the two do disagree
// routinely.
//
// Without a snapshot the configuration answers, and says so. That answer is an
// inference from what the firewall was told, not from what it is doing.
func (r *zoneResolver) resolve(value string, p Providers) ([]Hit, []Unresolved, bool) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		q, perr := netip.ParsePrefix(value)
		if perr != nil {
			return nil, nil, false
		}
		addr = q.Addr()
	}
	if p.Zones != nil {
		return r.fromSnapshot(value, addr, p.Zones)
	}
	if r.empty {
		return nil, []Unresolved{NewUnresolved(value, kindZone, reason.New("zone.none-defined",
			"this scope defines no zones, so an address cannot be placed in a "+
				"zone from its configuration"))}, true
	}

	un := append(r.limitsCopy(), NewUnresolved(value, kindZone, reason.New("zone.derived",
		"this zone came from the configuration, not from the device. It is an "+
			"inference from interface addresses and static routes, and a firewall's "+
			"forwarding table routinely differs: supply a zone snapshot for what the "+
			"device is actually doing")))
	hits, found := r.table.Lookup(addr)
	if !found {
		return nil, append(un, NewUnresolved(value, kindZone, reason.New("zone.missing",
			"no interface address and no static route in this configuration covers "+
				"this address, so the zone it would arrive on is unknown"))), true
	}
	return hits, un, true
}

// fromSnapshot answers from the device's own forwarding table.
func (r *zoneResolver) fromSnapshot(value string, addr netip.Addr, loc ZoneLocator) ([]Hit, []Unresolved, bool) {
	placements := loc.ZonesOf(addr)
	if len(placements) == 0 {
		un := []Unresolved{NewUnresolved(value, kindZone, reason.New("zone.missing",
			"no forwarding entry in the snapshot covers this address, so the device "+
				"would not forward it and no zone applies"))}
		if snap, ok := loc.(*ZoneSnapshot); ok {
			for _, iface := range snap.UnroutedInterfaces() {
				un = append(un, NewUnresolved(iface, kindZone, reason.New("zone.interface-unzoned",
					"a forwarding entry leaves by interface "+iface+
						", which is in no zone, so nothing it covers can be placed")))
			}
		}
		return nil, un, true
	}

	var un []Unresolved
	// A zone belongs to one vsys. A snapshot covers the whole firewall, so on a
	// multi-vsys device it carries zones this scope cannot see.
	placements, dropped := keepVsys(placements, r.scope)
	if dropped > 0 {
		un = append(un, NewUnresolved(value, kindZone, reason.New("zone.other-vsys",
			fmt.Sprintf(
				"%d placement(s) in the snapshot belong to another vsys and were left out, "+
					"because a zone is visible only inside the vsys that defines it", dropped))))
	}
	if len(placements) == 0 {
		return nil, append(un, NewUnresolved(value, kindZone, reason.New("zone.other-vsys",
			"the snapshot places this address, but only in a vsys other than "+
				r.scope.String()))), true
	}

	hits := make([]Hit, 0, len(placements))
	for _, p := range placements {
		hits = append(hits, Hit{
			Name:  p.Zone,
			Kind:  kindZone,
			Scope: r.scope,
			Via:   p.Interface + " via " + p.Router + " " + p.Route,
		})
	}

	// Several routers can cover one address, and which applies depends on the
	// interface the packet arrived on. Reporting one of them as the answer would be
	// a guess.
	if routers := distinctRouters(placements); len(routers) > 1 {
		un = append(un, NewUnresolved(value, kindZone, reason.New("zone.several-routers",
			"this address is covered by more than one logical router ("+
				strings.Join(routers, ", ")+"), and which applies depends on the "+
				"interface the packet arrives on, so every zone is reported and none is "+
				"chosen")))
	}
	return hits, un, true
}

// keepVsys drops placements from another vsys, and reports how many.
//
// The shared scope keeps everything: a snapshot comes from one firewall, and shared
// belongs to none of its vsys.
func keepVsys(ps []ZonePlacement, sc config.Scope) ([]ZonePlacement, int) {
	if sc.Sort != config.ScopeVsys {
		return ps, 0
	}
	want := strings.TrimPrefix(sc.Name, "vsys")
	out := ps[:0:0]
	dropped := 0
	for _, p := range ps {
		// An unlabelled placement is kept: saying nothing is not the same as saying
		// another vsys.
		if p.Vsys == "" || p.Vsys == want {
			out = append(out, p)
			continue
		}
		dropped++
	}
	return out, dropped
}

func distinctRouters(ps []ZonePlacement) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range ps {
		if p.Router == "" || seen[p.Router] {
			continue
		}
		seen[p.Router] = true
		out = append(out, p.Router)
	}
	slices.Sort(out)
	return out
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
