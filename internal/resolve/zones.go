package resolve

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/config"
)

// Zone is one security zone and the interfaces assigned to it.
type Zone struct {
	Name       string
	Scope      config.Scope
	Mode       string // layer3, layer2, virtual-wire, tap, external
	Interfaces []string
}

// InterfaceAddress is one address configured on an interface, which is a connected
// route: traffic for that prefix arrives on that interface.
type InterfaceAddress struct {
	Interface string
	Prefix    netip.Prefix
}

// StaticRoute is one configured route. Interface is the egress interface when the
// route names one, which is what ties a destination to a zone.
type StaticRoute struct {
	VirtualRouter string
	Name          string
	Destination   netip.Prefix
	Interface     string
	NextHop       string
}

// zoneModes are the interface lists a zone can hold.
var zoneModes = []string{"layer3", "layer2", "virtual-wire", "tap", "external"}

// ZonesInScope returns the zones visible in a scope, with the interfaces assigned to
// each.
//
// A vsys that defines no zones has none, and that is an answer rather than an
// error.
func ZonesInScope(cfg *config.Config, sc config.Scope) []Zone {
	entries := entriesInScope(cfg, sc, "zone")
	out := make([]Zone, 0, len(entries))
	for _, e := range entries {
		z := Zone{Name: e.name, Scope: e.scope}
		net := e.el.Child("network")
		for _, mode := range zoneModes {
			if m := net.Child(mode).Members(); len(m) > 0 {
				z.Mode = mode
				z.Interfaces = append(z.Interfaces, m...)
			}
		}
		out = append(out, z)
	}
	return out
}

// ZoneNames are the names of the zones a scope defines, sorted.
func ZoneNames(cfg *config.Config, sc config.Scope) []string {
	var out []string
	for _, z := range ZonesInScope(cfg, sc) {
		out = append(out, z.Name)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// InterfaceAddresses returns every address configured on an interface.
//
// The families nest differently and every shape has to be read. An ethernet address
// sits at ethernet/entry/layer3/ip/entry, a subinterface one level further down under
// layer3/units/entry/ip/entry, and a loopback address at loopback/units/entry/ip/entry
// with no layer3 in between. Rather than encode each shape, an interface is any entry
// under network/interface, and its addresses are the ip lists in its own subtree —
// stopping at the next entry down, because that is a subinterface with a name and a
// zone of its own.
func InterfaceAddresses(cfg *config.Config) []InterfaceAddress {
	var out []InterfaceAddress
	for _, iface := range cfg.Root().Find("devices", "entry", "network", "interface") {
		collectInterfaceAddresses(iface, &out)
	}
	return out
}

func collectInterfaceAddresses(e *config.Element, out *[]InterfaceAddress) {
	if e == nil {
		return
	}
	if e.Name == "entry" {
		for _, p := range ownAddresses(e) {
			*out = append(*out, InterfaceAddress{Interface: e.Attr("name"), Prefix: p})
		}
	}
	for _, c := range e.Children {
		collectInterfaceAddresses(c, out)
	}
}

// ownAddresses returns the prefixes configured on one interface entry, looking through
// the mode wrapper it may sit behind but never into a nested entry.
func ownAddresses(entry *config.Element) []netip.Prefix {
	var out []netip.Prefix
	var walk func(e *config.Element)
	walk = func(e *config.Element) {
		for _, c := range e.Children {
			switch c.Name {
			case "entry":
				// A subinterface, with its own name and possibly its own zone.
				continue
			case "ip":
				for _, ip := range c.Find("entry") {
					// An address is written as a prefix, so a host address keeps its
					// mask.
					if p, err := netip.ParsePrefix(ip.Attr("name")); err == nil {
						out = append(out, p)
					}
				}
			default:
				walk(c)
			}
		}
	}
	walk(entry)
	return out
}

// StaticRoutes returns the configured routes of every virtual router.
func StaticRoutes(cfg *config.Config) []StaticRoute {
	var out []StaticRoute
	for _, vr := range cfg.Root().Find("devices", "entry", "network", "virtual-router", "entry") {
		name := vr.Attr("name")
		for _, sr := range vr.Find("routing-table", "ip", "static-route", "entry") {
			p, err := netip.ParsePrefix(sr.Child("destination").TextOr(""))
			if err != nil {
				continue
			}
			out = append(out, StaticRoute{
				VirtualRouter: name,
				Name:          sr.Attr("name"),
				Destination:   p.Masked(),
				Interface:     sr.Child("interface").TextOr(""),
				NextHop:       sr.Child("nexthop").Child("ip-address").TextOr(""),
			})
		}
	}
	return out
}

// DynamicRoutingProtocols returns the routing protocols a virtual router enables.
//
// A route learned by one of these is not in the configuration, so an address reachable
// only that way cannot be placed in a zone by reading a file.
func DynamicRoutingProtocols(cfg *config.Config) []string {
	var out []string
	seen := map[string]bool{}
	for _, vr := range cfg.Root().Find("devices", "entry", "network", "virtual-router", "entry") {
		proto := vr.Child("protocol")
		if proto == nil {
			continue
		}
		for _, p := range []string{"bgp", "ospf", "ospfv3", "rip"} {
			el := proto.Child(p)
			if el == nil {
				continue
			}
			// Absent enable counts as enabled: PAN-OS defaults it on once the
			// protocol block exists.
			if v := el.Child("enable").TextOr("yes"); !strings.EqualFold(v, "yes") {
				continue
			}
			label := vr.Attr("name") + "/" + p
			if !seen[label] {
				seen[label] = true
				out = append(out, label)
			}
		}
	}
	return out
}
