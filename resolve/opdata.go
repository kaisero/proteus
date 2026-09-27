package resolve

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// InterfaceState is one logical interface as a firewall reports it.
//
// This is the operational counterpart of what ZonesInScope and InterfaceAddresses
// infer from a configuration, and it is better in every way: the zone, the vsys, the
// router and the address arrive together, flat, with no mode wrapper to look through
// and no guess about which interface a route leaves by.
type InterfaceState struct {
	Name   string
	Zone   string
	Vsys   string
	Router string // the logical router, from "lr:<name>"; empty when unrouted
	Prefix netip.Prefix
}

// FIBRoute is one forwarding entry, in the router and address family that hold it.
type FIBRoute struct {
	Router      string
	IPv6        bool
	Destination netip.Prefix
	Interface   string
	NextHop     string
	Flags       string
}

// opResponse is the envelope the API returns. A caller may also hand over a bare
// <result>, which is what the CLI prints with op-command-xml-output on.
type opResponse struct {
	XMLName xml.Name
	Status  string    `xml:"status,attr"`
	Result  *opResult `xml:"result"`
}

type opResult struct {
	Ifnet struct {
		Entries []struct {
			Name string `xml:"name"`
			Vsys string `xml:"vsys"`
			Zone string `xml:"zone"`
			Fwd  string `xml:"fwd"`
			IP   string `xml:"ip"`
		} `xml:"entry"`
	} `xml:"ifnet"`

	FIBs struct {
		Entries []struct {
			VR      string `xml:"vr"`
			Type    string `xml:"type"`
			Entries struct {
				Routes []struct {
					Dst       string `xml:"dst"`
					Interface string `xml:"interface"`
					NextHop   string `xml:"nexthop"`
					Flags     string `xml:"flags"`
				} `xml:"entry"`
			} `xml:"entries"`
		} `xml:"entry"`
	} `xml:"fibs"`
}

// decodeOp reads either a <response> envelope or a bare <result>.
func decodeOp(r io.Reader) (*opResult, error) {
	var env opResponse
	if err := xml.NewDecoder(r).Decode(&env); err != nil {
		return nil, fmt.Errorf("op data: %w", err)
	}
	if env.XMLName.Local == "result" {
		// A bare result decodes into the envelope's own fields, so decode again
		// against the inner shape.
		return nil, errBareResult
	}
	if env.Status != "" && env.Status != "success" {
		return nil, fmt.Errorf("op data: the device reported status %q", env.Status)
	}
	if env.Result == nil {
		return nil, fmt.Errorf("op data: no <result> element")
	}
	return env.Result, nil
}

var errBareResult = fmt.Errorf("op data: bare result")

// readOp decodes op-command output given either envelope shape.
func readOp(b []byte) (*opResult, error) {
	res, err := decodeOp(strings.NewReader(string(b)))
	if err == nil {
		return res, nil
	}
	if err != errBareResult {
		return nil, err
	}
	var bare opResult
	if err := xml.Unmarshal(b, &bare); err != nil {
		return nil, fmt.Errorf("op data: %w", err)
	}
	return &bare, nil
}

// ReadInterfaceStates reads the output of "show interface all".
//
// Only the ifnet section is read. The hw section describes physical links — speed,
// duplex, MAC — and none of that places an address in a zone.
func ReadInterfaceStates(b []byte) ([]InterfaceState, error) {
	res, err := readOp(b)
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceState, 0, len(res.Ifnet.Entries))
	for _, e := range res.Ifnet.Entries {
		st := InterfaceState{
			Name:   strings.TrimSpace(e.Name),
			Zone:   strings.TrimSpace(e.Zone),
			Vsys:   strings.TrimSpace(e.Vsys),
			Router: routerOf(e.Fwd),
		}
		// An interface with no address reports "N/A". It can still hold a zone, and a
		// route may leave by it, so it is kept.
		if p, err := netip.ParsePrefix(strings.TrimSpace(e.IP)); err == nil {
			st.Prefix = p
		}
		if st.Name == "" {
			continue
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("op data: no ifnet entries; is this the output of \"show interface all\"")
	}
	return out, nil
}

// routerOf reads the logical router from the fwd field, which reads "lr:default" when
// the interface is routed and "N/A" when it is not.
func routerOf(fwd string) string {
	v := strings.TrimSpace(fwd)
	if name, ok := strings.CutPrefix(v, "lr:"); ok {
		return name
	}
	// Older releases name a virtual router instead.
	if name, ok := strings.CutPrefix(v, "vr:"); ok {
		return name
	}
	return ""
}

// ReadFIBRoutes reads the output of "show advanced-routing fib", which is also the
// output of the legacy "show routing fib": both command paths share one handler in the
// operational schema, so both produce this shape.
func ReadFIBRoutes(b []byte) ([]FIBRoute, error) {
	res, err := readOp(b)
	if err != nil {
		return nil, err
	}
	var out []FIBRoute
	tables := 0
	for _, fib := range res.FIBs.Entries {
		tables++
		router := strings.TrimSpace(fib.VR)
		// A firewall reports one table per router per address family. Type 1 is IPv6.
		v6 := strings.TrimSpace(fib.Type) == "1"
		for _, r := range fib.Entries.Routes {
			p, err := netip.ParsePrefix(strings.TrimSpace(r.Dst))
			if err != nil {
				continue
			}
			out = append(out, FIBRoute{
				Router:      router,
				IPv6:        v6,
				Destination: p.Masked(),
				Interface:   strings.TrimSpace(r.Interface),
				NextHop:     strings.TrimSpace(r.NextHop),
				Flags:       strings.TrimSpace(r.Flags),
			})
		}
	}
	if tables == 0 {
		return nil, fmt.Errorf("op data: no fib tables; is this the output of \"show advanced-routing fib\"")
	}
	return out, nil
}
