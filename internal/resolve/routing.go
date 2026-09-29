package resolve

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// RIBRoute is one route the routing table holds, installed or not.
type RIBRoute struct {
	Router      string
	Destination netip.Prefix
	Protocol    string // static, connected, local, bgp, ospf, …
	Distance    int
	Metric      int
	Selected    bool // the routing table's choice for this destination
	Installed   bool // in the forwarding table
	NextHops    []RIBNextHop
}

// RIBNextHop is one next hop of a RIB route. IP is invalid for a directly
// connected next hop.
type RIBNextHop struct {
	IP        netip.Addr
	Interface string
	Active    bool
}

// ribJSON is the FRR shape Advanced Routing returns inside <result><json>, verified
// on fw02 (PAN-OS 12.2.2): router -> prefix -> routes.
type ribJSON map[string]map[string][]struct {
	Prefix    string `json:"prefix"`
	Protocol  string `json:"protocol"`
	Distance  int    `json:"distance"`
	Metric    int    `json:"metric"`
	Selected  bool   `json:"selected"`
	Installed bool   `json:"installed"`
	NextHops  []struct {
		IP            string `json:"ip"`
		InterfaceName string `json:"interfaceName"`
		Active        bool   `json:"active"`
	} `json:"nexthops"`
}

// ReadRIBRoutes reads the output of "show advanced-routing route". The legacy
// "show routing route" has another shape, not seen on a device yet, and is refused
// rather than guessed at (AGENTS.md R9). So is the legacy command's answer on an
// Advanced Routing device, which reports success with a deprecation text.
func ReadRIBRoutes(b []byte) ([]RIBRoute, error) {
	res, err := readOp(b)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(res.JSON) == "" {
		if t := strings.TrimSpace(res.Text); t != "" {
			return nil, fmt.Errorf("op data: routing table refused: %s", t)
		}
		return nil, fmt.Errorf("op data: no routing table in Advanced Routing form; the legacy form is not read yet")
	}
	var j ribJSON
	if err := json.Unmarshal([]byte(res.JSON), &j); err != nil {
		return nil, fmt.Errorf("op data: routing table: %w", err)
	}
	var out []RIBRoute
	for router, prefixes := range j {
		for key, routes := range prefixes {
			for _, r := range routes {
				p, err := netip.ParsePrefix(firstNonEmpty(r.Prefix, key))
				if err != nil {
					continue
				}
				rt := RIBRoute{
					Router: router, Destination: p.Masked(), Protocol: r.Protocol,
					Distance: r.Distance, Metric: r.Metric, Selected: r.Selected, Installed: r.Installed,
				}
				for _, nh := range r.NextHops {
					h := RIBNextHop{Interface: nh.InterfaceName, Active: nh.Active}
					if a, err := netip.ParseAddr(nh.IP); err == nil {
						h.IP = a
					}
					rt.NextHops = append(rt.NextHops, h)
				}
				out = append(out, rt)
			}
		}
	}
	sort.SliceStable(out, func(i, k int) bool {
		if out[i].Router != out[k].Router {
			return out[i].Router < out[k].Router
		}
		return out[i].Destination.String() < out[k].Destination.String()
	})
	return out, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// HAState is what "show high-availability state" says about a device and its peer.
//
// Only the disabled shape is verified (fw02: <enabled>no</enabled>). The group
// fields follow the element names PAN-OS tools read (unverified): a caller must
// treat anything short of a complete, consistent pair as "do not follow".
type HAState struct {
	Enabled     bool
	Mode        string // active-passive, active-active
	LocalState  string // active, passive, suspended, non-functional, initial, tentative
	LocalSerial string
	PeerState   string
	PeerSerial  string
	PeerMgmtIP  netip.Addr // any "/len" suffix is stripped
}

// ReadHAState reads the output of "show high-availability state".
func ReadHAState(b []byte) (HAState, error) {
	res, err := readOp(b)
	if err != nil {
		return HAState{}, err
	}
	enabled := strings.TrimSpace(res.Enabled)
	if enabled == "" {
		return HAState{}, fmt.Errorf("op data: no <enabled>; is this the output of \"show high-availability state\"")
	}
	g := res.Group
	st := HAState{
		Enabled:     enabled == "yes",
		Mode:        strings.TrimSpace(g.Mode),
		LocalState:  strings.TrimSpace(g.LocalInfo.State),
		LocalSerial: strings.TrimSpace(g.LocalInfo.Serial),
		PeerState:   strings.TrimSpace(g.PeerInfo.State),
		PeerSerial:  strings.TrimSpace(g.PeerInfo.Serial),
	}
	ip, _, _ := strings.Cut(strings.TrimSpace(g.PeerInfo.MgmtIP), "/")
	if a, err := netip.ParseAddr(ip); err == nil {
		st.PeerMgmtIP = a
	}
	return st, nil
}
