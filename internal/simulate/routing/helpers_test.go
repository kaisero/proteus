package routing

import (
	"net/netip"

	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// iface is "name zone router address...".
func iface(name, zone, router string, addrs ...string) resolve.InterfaceState {
	st := resolve.InterfaceState{Name: name, Zone: zone, Router: router, Vsys: "1"}
	for _, a := range addrs {
		p := netip.MustParsePrefix(a)
		if st.Addrs == nil {
			st.Prefix = p
		}
		st.Addrs = append(st.Addrs, p)
	}
	return st
}

// route is "router destination interface next-hop".
func route(router, dst, ifc, nh string) resolve.FIBRoute {
	return resolve.FIBRoute{Router: router, Destination: netip.MustParsePrefix(dst), Interface: ifc, NextHop: nh, NextHopType: "0"}
}

func dev(name string, ifs []resolve.InterfaceState, fib ...resolve.FIBRoute) simulate.DeviceData {
	return simulate.DeviceData{Name: name, Interfaces: ifs, FIB: fib}
}
