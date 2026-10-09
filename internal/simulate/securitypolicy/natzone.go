package securitypolicy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/simulate/topology"
)

// natZone is what destination NAT makes of the destination zone (spec §18 N10):
// security policy matches the post-NAT zone (§18 F5, verified on fw01).
type natZone struct {
	zones   []string         // the post-NAT destination zones; nil when no destination NAT applies
	rules   []string         // the NAT rules that translated
	doubts  simulate.Reasons // each NAT doubt, named with its rule
	skipped string           // why NAT was not checked
}

// postNATZones runs the NAT engine once per source zone (an unknown one included)
// on the device's stored tables. The destination zone after a destination NAT is
// that of the lookup of the translated address; runs that disagree give a set.
func (s *state) postNATZones(fromZones []string) natZone {
	if s.env == nil || s.env.Network == nil {
		return natZone{skipped: "no stored interfaces and forwarding table, so NAT is not checked"}
	}
	d, err := s.env.Network.Device(s.in.Device)
	if err != nil {
		return natZone{skipped: "NAT is not checked: " + err.Error()}
	}
	topo := topology.NewTopology([]simulate.DeviceData{d})
	router := ""
	if rs := topo.Routers(d.Name); len(rs) == 1 {
		router = rs[0]
	}
	for _, a := range s.in.Flow.Source.Addrs {
		for _, p := range topo.Connected(a) {
			if router == "" {
				router = p.Router
			}
		}
	}
	if router == "" {
		return natZone{skipped: d.Name + " has several routers and the source names none, so NAT is not checked"}
	}
	dst := s.in.Flow.Destination.Addrs[0]
	pre := topo.Forward(d.Name, router, dst)
	if len(fromZones) == 0 {
		fromZones = []string{""}
	}
	var out natZone
	seen := map[string]bool{}
	translated := false
	for _, fz := range fromZones {
		in := nat.Input{
			Target: s.target, Vsys: s.in.Vsys, Flow: s.in.Flow,
			In:     simulate.Port{Device: d.Name, Router: router, Zone: fz},
			PreNAT: &pre, Interfaces: d.Interfaces,
			Lookup: func(a netip.Addr) simulate.Forward { return topo.Forward(d.Name, router, a) },
		}
		in.Flow.Destination = simulate.Addr(dst)
		m := nat.Match(in)
		for _, db := range m.Doubts {
			out.doubts = append(out.doubts, db.Reasons.Prefixed("nat rule "+db.Rule+": ")...)
		}
		zone := pre.Out.Zone
		if m.Rule != nil && m.Rule.Destination != nil {
			if r := nat.Translate(in, m); r.PostNAT != nil {
				zone, translated = r.PostNAT.Out.Zone, true
				if !slices.Contains(out.rules, m.Rule.Name) {
					out.rules = append(out.rules, m.Rule.Name)
				}
			}
		}
		if zone != "" && !seen[zone] {
			seen[zone] = true
			out.zones = append(out.zones, zone)
		}
	}
	if !translated {
		out.zones = nil
	}
	slices.Sort(out.zones)
	return out
}

func (z natZone) describe() string {
	return fmt.Sprintf("to %s (after NAT rule %s)", strings.Join(z.zones, ", "), strings.Join(z.rules, ", "))
}
