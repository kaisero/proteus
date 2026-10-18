package appid

import (
	"slices"
	"strconv"
	"strings"
)

// protocolNumbers are the IANA numbers of the protocol names a flow or a port
// member can carry. Content writes icmp6 (P5); ipv6-icmp is the IANA name.
var protocolNumbers = map[string]int{
	"tcp": 6, "udp": 17, "sctp": 132, "icmp": 1, "icmp6": 58, "ipv6-icmp": 58,
}

// ProtocolNumber returns the IP protocol number of a protocol name, or of a
// number 0-255 (P4, P5). The name takes any case.
func ProtocolNumber(p string) (int, bool) {
	p = strings.ToLower(p)
	if n, ok := protocolNumbers[p]; ok {
		return n, true
	}
	n, err := strconv.ParseUint(p, 10, 8)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// protocolText is the flow protocol of a number, as the command line takes it:
// the name for tcp, udp, sctp and icmp, the number for any other.
func protocolText(n int) string {
	switch n {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 132:
		return "sctp"
	case 1:
		return "icmp"
	}
	return strconv.Itoa(n)
}

// PortMatch is the answer of an application's default for a flow's protocol
// and port.
type PortMatch int

const (
	// PortNo means the default does not allow the flow.
	PortNo PortMatch = iota
	// PortYes means the default allows the flow.
	PortYes
	// PortSecure means a /secure extended port allows the flow (P2).
	PortSecure
	// PortICMP means the default allows the protocol by ICMP type, and the flow
	// carries no type to check (P5).
	PortICMP
	// PortOpen means the flow leaves the protocol or the port open, and the
	// default allows some value of it.
	PortOpen
)

// String names the value: no, yes, secure, icmp or open.
func (m PortMatch) String() string {
	switch m {
	case PortNo:
		return "no"
	case PortYes:
		return "yes"
	case PortSecure:
		return "secure"
	case PortICMP:
		return "icmp"
	case PortOpen:
		return "open"
	}
	return "PortMatch(" + strconv.Itoa(int(m)) + ")"
}

// rank orders the answers when several forms of one default apply: a plain
// port before a secure one, a port before an ICMP type, a decided answer
// before an open one.
var rank = map[PortMatch]int{PortNo: 0, PortOpen: 1, PortICMP: 2, PortSecure: 3, PortYes: 4}

// Match compares a flow's protocol and destination port with the default
// (spec 2026-10-16 §4.4). proto is a name or a number; "" leaves it open.
// port 0 gives no port. The facts are those measured on the lab VM, PAN-OS
// 12.1.9 (spec 2026-10-16 P1-P6, P11, P12). ident-by-dport and ident-by-sport
// do not change the answer (P12), so Match does not read them.
func (d Default) Match(proto string, port uint16) PortMatch {
	if d.None {
		// No default block: every protocol and port (P6).
		return PortYes
	}
	if proto == "" {
		return PortOpen
	}
	num, ok := ProtocolNumber(proto)
	if !ok {
		return PortNo
	}
	best := PortNo
	better := func(m PortMatch) {
		if rank[m] > rank[best] {
			best = m
		}
	}
	if lo, hi := d.ipProtocols(); lo != 0 && num >= lo && num <= hi {
		// ident-by-ip-protocol N: protocol N with any port (P4). A range
		// N-M holds each protocol from N to M.
		better(PortYes)
	}
	// ident-by-icmp-type is protocol 1, ident-by-icmp6-type protocol 58, with
	// any type (P5).
	if d.ICMP && num == 1 || d.ICMP6 && num == 58 {
		better(PortICMP)
	}
	for _, r := range d.Ports {
		if n, _ := ProtocolNumber(r.Protocol); n != num {
			continue
		}
		// A /secure extended port matches as a default port; a port that port
		// also lists is a plain default port (P2).
		hit := PortYes
		if r.Secure {
			hit = PortSecure
		}
		switch {
		case r.AnyPort:
			// dynamic and any: every port of the protocol (P3, P11), for
			// icmp and icmp6 the protocol (P11).
			better(hit)
		case port == 0:
			better(PortOpen)
		case r.Low <= port && port <= r.High:
			// A port, a list or a range (P1, F10).
			better(hit)
		}
	}
	return best
}

// Protocols returns the flow protocols the default allows, by protocol
// number: "tcp", "udp", "sctp", "icmp", or a number such as "58" or "89". It
// is nil for an application without a default block, which allows every
// protocol (P6).
func (d Default) Protocols() []string {
	if d.None {
		return nil
	}
	var nums []int
	add := func(n int) {
		if !slices.Contains(nums, n) {
			nums = append(nums, n)
		}
	}
	for _, r := range d.Ports {
		n, _ := ProtocolNumber(r.Protocol)
		add(n)
	}
	if lo, hi := d.ipProtocols(); lo != 0 {
		for n := lo; n <= hi; n++ {
			add(n)
		}
	}
	if d.ICMP {
		add(1)
	}
	if d.ICMP6 {
		add(58)
	}
	slices.Sort(nums)
	out := make([]string, len(nums))
	for i, n := range nums {
		out[i] = protocolText(n)
	}
	return out
}

// String gives the default as text: "tcp/80,443", "tcp/80; tcp/443/secure",
// "tcp/80,any", "ip-protocol/89", "icmp-type", "icmp6-type", or "any" for an
// application without a default block. dynamic reads as any (P3, P11).
func (d Default) String() string {
	if d.None {
		return "any"
	}
	type group struct {
		proto  string
		secure bool
		ports  []string
	}
	var groups []*group
	for _, r := range d.Ports {
		i := slices.IndexFunc(groups, func(g *group) bool { return g.proto == r.Protocol && g.secure == r.Secure })
		if i < 0 {
			groups = append(groups, &group{proto: r.Protocol, secure: r.Secure})
			i = len(groups) - 1
		}
		p := "any"
		switch {
		case r.AnyPort:
		case r.Low == r.High:
			p = strconv.Itoa(int(r.Low))
		default:
			p = strconv.Itoa(int(r.Low)) + "-" + strconv.Itoa(int(r.High))
		}
		if !slices.Contains(groups[i].ports, p) {
			groups[i].ports = append(groups[i].ports, p)
		}
	}
	// The groups keep the order of the file: port before extended-port.
	var parts []string
	for _, g := range groups {
		s := g.proto + "/" + strings.Join(g.ports, ",")
		if g.secure {
			s += "/secure"
		}
		parts = append(parts, s)
	}
	if lo, hi := d.ipProtocols(); lo != 0 {
		s := "ip-protocol/" + strconv.Itoa(lo)
		if hi != lo {
			s += "-" + strconv.Itoa(hi)
		}
		parts = append(parts, s)
	}
	if d.ICMP {
		parts = append(parts, "icmp-type")
	}
	if d.ICMP6 {
		parts = append(parts, "icmp6-type")
	}
	return strings.Join(parts, "; ")
}

// ipProtocols gives the ident-by-ip-protocol range: lo 0 for none, and hi
// equal to lo for one protocol.
func (d Default) ipProtocols() (lo, hi int) {
	if d.IPProtocolHigh > d.IPProtocol {
		return d.IPProtocol, d.IPProtocolHigh
	}
	return d.IPProtocol, d.IPProtocol
}
