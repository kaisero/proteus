package index

import (
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

func zonesIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-zones.xml", "vsys1")
}

func zoneNames(rep Report) map[string]string {
	out := map[string]string{}
	for _, h := range rep.Hits {
		if h.Kind == kindZone {
			out[h.Name] = h.Via
		}
	}
	return out
}

// An interface address is a connected route, so the prefix it carries arrives on that
// interface and therefore in that interface's zone. Every nesting shape has to be read:
// an ethernet address sits behind layer3, a subinterface behind layer3/units, and a
// loopback address directly under units with no layer3 at all.
func TestZoneResolverPlacesAnAddressFromEveryInterfaceShape(t *testing.T) {
	idx := zonesIndex(t)

	for _, c := range []struct{ addr, zone, iface string }{
		{"10.1.0.50", "inside", "ethernet1/1"},
		{"10.2.0.50", "dmz", "ethernet1/2.20"},
		{"10.255.255.1", "loop", "loopback.1"},
	} {
		_, rep := idx.Candidates(FromZone, c.addr)
		got := zoneNames(rep)
		via, ok := got[c.zone]
		if !ok {
			t.Errorf("%s was not placed in %s, got %v", c.addr, c.zone, got)
			continue
		}
		if !strings.Contains(via, c.iface) {
			t.Errorf("%s placed via %q, want it to name %s", c.addr, via, c.iface)
		}
	}
}

// A placed address reaches the rules whose from-zone is that zone.
func TestZoneResolverReachesTheRules(t *testing.T) {
	idx := zonesIndex(t)

	rules, _ := idx.Candidates(FromZone, "10.1.0.50")
	if !ruleNames(idx, rules)["from-inside"] {
		t.Error("an address on ethernet1/1 did not reach the rule whose from-zone is inside")
	}
	rules, _ = idx.Candidates(FromZone, "10.255.255.1")
	if !ruleNames(idx, rules)["from-loop"] {
		t.Error("a loopback address did not reach the rule whose from-zone is loop")
	}
}

// Longest prefix wins, the way a router decides: a /32 on a loopback beats the /24 that
// contains it on another interface.
func TestZoneResolverPrefersTheMoreSpecificRoute(t *testing.T) {
	idx := zonesIndex(t)

	// 10.255.255.1/32 is in zone loop. Nothing else covers it.
	_, rep := idx.Candidates(FromZone, "10.255.255.1")
	got := zoneNames(rep)
	if len(got) != 1 || got["loop"] == "" {
		t.Errorf("zones = %v, want only loop", got)
	}
}

// A static route that names an egress interface ties its destination to that
// interface's zone. A route with only a next hop resolves through another route, which
// a file cannot follow reliably, so it is left alone.
func TestZoneResolverUsesStaticRoutesWithAnInterface(t *testing.T) {
	idx := zonesIndex(t)

	_, rep := idx.Candidates(FromZone, "172.16.5.5")
	got := zoneNames(rep)
	if got["inside"] == "" {
		t.Errorf("a static route out ethernet1/1 did not place the destination in inside: %v", got)
	}
	if !strings.Contains(got["inside"], "to-branch") {
		t.Errorf("the path does not name the route: %q", got["inside"])
	}

	// The next-hop-only route places nothing.
	_, rep = idx.Candidates(FromZone, "192.0.2.5")
	if z := zoneNames(rep); len(z) != 0 {
		t.Errorf("a next-hop-only route placed an address: %v", z)
	}
}

// Every limit is reported rather than hidden: a zone with no interface, an interface in
// no zone, a virtual router learning routes at runtime, and an address nothing covers.
func TestZoneResolverReportsItsLimits(t *testing.T) {
	idx := zonesIndex(t)

	_, rep := idx.Candidates(FromZone, "203.0.113.9")

	var haveEmptyZone, haveZonelessInterface, haveDynamic, haveNoRoute bool
	for _, u := range rep.Unresolved {
		switch {
		case u.Value == "empty-zone":
			haveEmptyZone = true
		case u.Value == "tunnel.99":
			haveZonelessInterface = true
		case strings.Contains(u.Value, "bgp"):
			haveDynamic = true
		case u.Value == "203.0.113.9":
			haveNoRoute = true
		}
	}
	if !haveEmptyZone {
		t.Error("a zone with no interface was not reported")
	}
	if !haveZonelessInterface {
		t.Errorf("the default route out an interface in no zone was not reported: %v", rep.Unresolved)
	}
	if !haveDynamic {
		t.Error("a virtual router running BGP was not reported")
	}
	if !haveNoRoute {
		t.Error("an address no route covers was not reported")
	}
}

// The default route out a zoneless interface must not place an address. Reporting the
// zone of an interface that carries no policy would be worse than saying nothing.
func TestZoneResolverIgnoresADefaultRouteWithNoZone(t *testing.T) {
	idx := zonesIndex(t)

	_, rep := idx.Candidates(FromZone, "8.8.8.8")
	if z := zoneNames(rep); len(z) != 0 {
		t.Errorf("an address covered only by a zoneless default route was placed: %v", z)
	}
}

// A vsys with no zones says so rather than returning nothing silently.
func TestZoneResolverSaysWhenAScopeHasNoZones(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-multivsys.xml", "vsys3")

	_, rep := idx.Candidates(FromZone, "10.0.0.1")
	var told bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "defines no zones") {
			told = true
		}
	}
	if !told {
		t.Errorf("a vsys with no zones did not explain why: %v", rep.Unresolved)
	}
}

// A zone name still works, and is not affected by any of this.
func TestZoneNameStillResolves(t *testing.T) {
	idx := zonesIndex(t)

	rules, rep := idx.Candidates(FromZone, "inside")
	if len(rep.Hits) != 0 {
		t.Errorf("a zone name should not produce value hits: %+v", rep.Hits)
	}
	if !ruleNames(idx, rules)["from-inside"] {
		t.Error("the rule naming the zone was not found")
	}
}

// A prefix is accepted as well as an address, so a caller can ask which zone a whole
// network sits in.
func TestZoneResolverAcceptsAPrefix(t *testing.T) {
	idx := zonesIndex(t)

	_, rep := idx.Candidates(FromZone, "10.1.0.0/24")
	if zoneNames(rep)["inside"] == "" {
		t.Errorf("a prefix was not placed: %v", zoneNames(rep))
	}
}

// Two interfaces in the same zone both place their prefixes, and one prefix reachable
// through two zones reports both rather than choosing.
func TestZoneResolverReportsEveryZoneForAPrefix(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-zones-shared.xml", "vsys1")

	_, rep := idx.Candidates(FromZone, "10.50.0.5")
	got := zoneNames(rep)
	if len(got) != 2 {
		t.Errorf("zones = %v, want both zones holding the interface", got)
	}
	// The fixture also has a static route whose destination is the connected prefix
	// itself, so the same prefix is recorded twice and both records have to survive.
	var paths int
	for _, h := range rep.Hits {
		if h.Kind == kindZone {
			paths++
		}
	}
	if paths < 4 {
		t.Errorf("got %d zone paths, want one per zone per route", paths)
	}
}

// Searching finds a zone by a fragment of the prefix that reaches it.
func TestZoneResolverSearch(t *testing.T) {
	idx := zonesIndex(t)

	hits := idx.SearchValues("10.255.255")
	var found bool
	for _, h := range hits {
		if h.Kind == kindZone && h.Name == "loop" {
			found = true
		}
	}
	if !found {
		t.Errorf("searching a loopback prefix did not find its zone: %+v", hits)
	}
}

// A snapshot is authoritative. Where it answers, the configuration is not consulted,
// and the answer names the route that decided it.
func TestZoneResolverPrefersTheSnapshot(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-zones.xml", "vsys1")
	v := idx.With(Providers{Zones: zoneSnap(t)})

	// 198.18.0.5 is placed by the snapshot and by nothing in this configuration.
	_, rep := v.Candidates(FromZone, "198.18.0.5")
	got := zoneNames(rep)
	if got["transport"] == "" {
		t.Fatalf("the snapshot did not place the address: %v", got)
	}
	if !strings.Contains(got["transport"], "ethernet1/1 via default") {
		t.Errorf("the placement does not name the route: %q", got["transport"])
	}
	// The configuration's own zones must not appear: this fixture has "inside" and
	// "dmz", and the snapshot came from another device.
	for _, unwanted := range []string{"inside", "dmz", "loop"} {
		if got[unwanted] != "" {
			t.Errorf("a configuration zone leaked into a snapshot answer: %v", got)
		}
	}
}

// When the snapshot places nothing, the configuration is still not consulted. Falling
// back would hide a disagreement between what a device was told and what it is doing.
//
// The fixture device has a default route, so every address is covered. Removing it
// leaves 10.1.0.50 unplaceable by the snapshot while the configuration still places it
// in "inside", which is exactly the case that must not fall back.
func TestZoneResolverDoesNotFallBackWhenASnapshotIsPresent(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-zones.xml", "vsys1")

	// The configuration can answer on its own.
	if _, rep := idx.Candidates(FromZone, "10.1.0.50"); zoneNames(rep)["inside"] == "" {
		t.Fatal("the fixture no longer places this address, so the test proves nothing")
	}

	snap := zoneSnap(t)
	snap.FIBXML = strings.Replace(snap.FIBXML,
		"<dst>0.0.0.0/0</dst>", "<dst>203.0.113.0/24</dst>", 1)
	if err := snap.index(); err != nil {
		t.Fatal(err)
	}

	_, rep := idx.With(Providers{Zones: snap}).Candidates(FromZone, "10.1.0.50")
	if got := zoneNames(rep); len(got) != 0 {
		t.Errorf("the configuration answered while a snapshot was present: %v", got)
	}
	var told bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "would not forward it") {
			told = true
		}
	}
	if !told {
		t.Errorf("the empty answer did not explain itself: %v", rep.Unresolved)
	}
}

// Every configuration-derived answer says that it is one. It is an inference from what
// the firewall was told, and on a real device it was reasoning from a default route
// that had since been replaced.
func TestZoneResolverAlwaysReportsAConfigurationAnswer(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-zones.xml", "vsys1")

	_, rep := idx.Candidates(FromZone, "10.1.0.50")
	if len(zoneNames(rep)) == 0 {
		t.Fatal("the configuration should place this address")
	}
	var told bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "came from the configuration, not from the device") {
			told = true
		}
	}
	if !told {
		t.Errorf("a configuration-derived zone was not reported as such: %v", rep.Unresolved)
	}
}

// Several routers covering one address is reported, not resolved by picking one.
func TestZoneResolverReportsRouterAmbiguity(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-zones.xml", "vsys1")
	v := idx.With(Providers{Zones: zoneSnap(t)})

	_, rep := v.Candidates(FromZone, "198.19.11.5")
	if len(zoneNames(rep)) != 2 {
		t.Errorf("both routers should be reported: %v", zoneNames(rep))
	}
	var told bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "more than one logical router") {
			told = true
		}
	}
	if !told {
		t.Errorf("the ambiguity was not reported: %v", rep.Unresolved)
	}
}

// A zone is visible only inside the vsys that defines it, so a snapshot of a
// multi-vsys firewall must not leak zones across a scope boundary.
func TestZoneResolverFiltersByVsys(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-zones.xml", "vsys1")

	// The same forwarding table, but every interface belongs to vsys 2.
	other := zoneSnap(t)
	other.InterfacesXML = strings.ReplaceAll(other.InterfacesXML, "<vsys>1</vsys>", "<vsys>2</vsys>")
	if err := other.index(); err != nil {
		t.Fatal(err)
	}

	_, rep := idx.With(Providers{Zones: other}).Candidates(FromZone, "198.18.0.5")
	if got := zoneNames(rep); len(got) != 0 {
		t.Errorf("zones from another vsys were reported: %v", got)
	}
	var told bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "another vsys") {
			told = true
		}
	}
	if !told {
		t.Errorf("the vsys mismatch was not reported: %v", rep.Unresolved)
	}

	// And the unmodified snapshot, whose vsys matches, still answers.
	if _, rep := idx.With(Providers{Zones: zoneSnap(t)}).Candidates(FromZone, "198.18.0.5"); len(zoneNames(rep)) == 0 {
		t.Error("vsys1 should see its own zones")
	}
}

// The resolver surfaces an unrouted interface, so an empty answer explains itself
// rather than looking like "this address is nowhere".
func TestZoneResolverSurfacesUnroutedInterfaces(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-zones.xml", "vsys1")
	snap := zoneSnap(t)
	snap.FIBXML = strings.Replace(snap.FIBXML,
		"<interface>ethernet1/1</interface>", "<interface>tunnel.99</interface>", 1)
	if err := snap.index(); err != nil {
		t.Fatal(err)
	}

	_, rep := idx.With(Providers{Zones: snap}).Candidates(FromZone, "8.8.8.8")
	var told bool
	for _, u := range rep.Unresolved {
		if u.Value == "tunnel.99" && strings.Contains(u.Reason, "in no zone") {
			told = true
		}
	}
	if !told {
		t.Errorf("the zoneless interface was not surfaced: %v", rep.Unresolved)
	}
}

// The shared scope keeps every placement: a snapshot comes from one firewall, and
// shared belongs to none of its vsys.
func TestZoneResolverKeepsEveryPlacementForShared(t *testing.T) {
	cfg, _, err := config.Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeShared})
	if err != nil {
		t.Fatal(err)
	}
	_, rep := idx.With(Providers{Zones: zoneSnap(t)}).Candidates(FromZone, "198.18.0.5")
	if got := zoneNames(rep); len(got) == 0 {
		t.Errorf("the shared scope dropped every placement: %v", rep.Unresolved)
	}
}

// A forwarding entry with no router still places, and the ambiguity note is not
// raised for it.
func TestZoneResolverHandlesAnUnnamedRouter(t *testing.T) {
	body := `{"interfaces_xml":"<result><ifnet><entry><name>ethernet1/1</name><vsys>1</vsys>` +
		`<zone>a</zone><fwd>N/A</fwd></entry></ifnet></result>",` +
		`"fib_xml":"<result><fibs><entry><vr></vr><type>0</type><entries>` +
		`<entry><dst>10.0.0.0/8</dst><interface>ethernet1/1</interface></entry>` +
		`</entries></entry></fibs></result>"}`
	snap, err := LoadZoneSnapshot(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	idx := indexOf(t, "../../testdata/config/firewall-zones.xml", "vsys1")

	_, rep := idx.With(Providers{Zones: snap}).Candidates(FromZone, "10.1.2.3")
	if zoneNames(rep)["a"] == "" {
		t.Errorf("a route with no named router did not place: %v", rep.Hits)
	}
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "more than one logical router") {
			t.Error("a single unnamed router was reported as ambiguous")
		}
	}
}
