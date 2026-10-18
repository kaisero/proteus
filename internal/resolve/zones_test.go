package resolve

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/kaisero/proteus/internal/config"
)

func zonesCfg(t *testing.T) *config.Config {
	t.Helper()
	return loadT(t, "../../testdata/config/firewall-zones.xml")
}

// A zone is a set of interfaces, and the interface list is what makes it usable.
func TestZonesInScope(t *testing.T) {
	t.Parallel()
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	zones := ZonesInScope(zonesCfg(t), sc)
	got := map[string]Zone{}
	for _, z := range zones {
		got[z.Name] = z
	}
	for name, iface := range map[string]string{
		"inside": "ethernet1/1",
		"dmz":    "ethernet1/2.20",
		"loop":   "loopback.1",
	} {
		z, ok := got[name]
		if !ok {
			t.Errorf("zone %s missing", name)
			continue
		}
		if len(z.Interfaces) != 1 || z.Interfaces[0] != iface {
			t.Errorf("zone %s interfaces = %v, want [%s]", name, z.Interfaces, iface)
		}
		if z.Mode != "layer3" {
			t.Errorf("zone %s mode = %q, want layer3", name, z.Mode)
		}
	}
	if z, ok := got["empty-zone"]; !ok || len(z.Interfaces) != 0 {
		t.Errorf("a zone with no interface should still be listed, got %+v", got["empty-zone"])
	}
}

// Every nesting shape has to be read. An ethernet address sits behind layer3, a
// subinterface behind layer3/units, and a loopback address directly under units.
// Missing the layer3 wrapper silently dropped every base ethernet address.
func TestInterfaceAddressesReadsEveryShape(t *testing.T) {
	t.Parallel()
	addrs := InterfaceAddresses(zonesCfg(t))
	got := map[string]string{}
	for _, a := range addrs {
		got[a.Interface] = a.Prefix.String()
	}
	for iface, want := range map[string]string{
		"ethernet1/1":    "10.1.0.1/24",
		"ethernet1/2.20": "10.2.0.1/24",
		"ethernet1/9":    "10.9.0.1/24",
		"loopback.1":     "10.255.255.1/32",
	} {
		if got[iface] != want {
			t.Errorf("%s address = %q, want %q", iface, got[iface], want)
		}
	}
	// A subinterface address belongs to the subinterface, not to its parent, because
	// the two can be in different zones.
	if got["ethernet1/2"] == "10.2.0.1/24" {
		t.Error("a subinterface address was attributed to its parent interface")
	}
	// An interface with no address contributes nothing.
	if _, present := got["tunnel.99"]; present {
		t.Error("an interface with no address was reported as having one")
	}
}

// A route with an egress interface is what ties a destination to a zone. One with only a
// next hop resolves through another route, which a file cannot follow reliably.
func TestStaticRoutes(t *testing.T) {
	t.Parallel()
	routes := StaticRoutes(zonesCfg(t))
	got := map[string]StaticRoute{}
	for _, r := range routes {
		got[r.Name] = r
	}
	if r := got["to-branch"]; r.Interface != "ethernet1/1" ||
		r.Destination != netip.MustParsePrefix("172.16.0.0/16") {
		t.Errorf("to-branch = %+v", r)
	}
	if r := got["default"]; r.Interface != "tunnel.99" {
		t.Errorf("default route interface = %q, want tunnel.99", r.Interface)
	}
	if r := got["nexthop-only"]; r.Interface != "" || r.NextHop != "10.1.0.254" {
		t.Errorf("nexthop-only = %+v, want no interface and a next hop", r)
	}
	if r := got["to-branch"]; r.VirtualRouter != "default" {
		t.Errorf("virtual router = %q", r.VirtualRouter)
	}
}

// A route learned at runtime is not in the file, so a virtual router that learns them
// has to be reported. An absent enable counts as enabled, because PAN-OS defaults it on
// once the protocol block exists.
func TestDynamicRoutingProtocols(t *testing.T) {
	t.Parallel()
	got := DynamicRoutingProtocols(zonesCfg(t))
	if len(got) != 1 || got[0] != "default/bgp" {
		t.Errorf("protocols = %v, want [default/bgp]", got)
	}

	// A configuration with no dynamic routing reports none.
	if got := DynamicRoutingProtocols(loadT(t, "../../testdata/config/firewall-urlcat.xml")); len(got) != 0 {
		t.Errorf("protocols = %v, want none", got)
	}
}

// A vsys that defines no zones has none, and that is an answer, not an error.
func TestZonesInScopeOnAVsysWithNone(t *testing.T) {
	t.Parallel()
	zones := ZonesInScope(vsysLab(t), config.Scope{Sort: config.ScopeVsys, Name: "vsys3"})
	if len(zones) != 0 {
		t.Errorf("got %d zones in vsys3, want none: %+v", len(zones), zones)
	}
}

// ZoneNames lists a scope's zones by name, sorted: the one list of the zones a
// vsys defines that every check reads.
func TestZoneNames(t *testing.T) {
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-ruletype.xml")
	if got := ZoneNames(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}); !slices.Equal(got, []string{"dmz", "inside", "out"}) {
		t.Errorf("vsys1: %v", got)
	}
	if got := ZoneNames(vsysLab(t), config.Scope{Sort: config.ScopeVsys, Name: "vsys3"}); len(got) != 0 {
		t.Errorf("a vsys without zones: %v", got)
	}
}
