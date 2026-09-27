package index

import (
	"strings"
	"testing"
)

func zonesIndex(t *testing.T) *Index {
	t.Helper()
	return indexOfVsys(t, "../testdata/config/firewall-zones.xml", "vsys1")
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

// On Panorama the network configuration lives in a template, so a device group has no
// zones. That is where PAN-OS keeps it, not a failure to look, and the answer says so.
func TestZoneResolverSaysWhenAScopeHasNoZones(t *testing.T) {
	idx := indexOf(t, "../testdata/config/panorama-lab.xml", "at-ktn")

	_, rep := idx.Candidates(FromZone, "10.0.0.1")
	var told bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "template") {
			told = true
		}
	}
	if !told {
		t.Errorf("a device group with no zones did not explain why: %v", rep.Unresolved)
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
	idx := indexOfVsys(t, "../testdata/config/firewall-zones-shared.xml", "vsys1")

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
