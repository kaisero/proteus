package resolve

import (
	"strconv"

	"github.com/okaiser/panos-analyst/config"
)

// PBFRule is a policy-based forwarding rule: Rule's member lists, plus what the
// rule matches arrival by and what it does. Element names from the 11.2 schema
// (rulebase/pbf/rules/entry): from/zone or from/interface; action/forward
// (egress-interface, nexthop/ip-address or fqdn), forward-to-vsys, discard, no-pbf.
type PBFRule struct {
	Rule
	FromKind        string   // "zone" or "interface"
	From            []string // the zones or interfaces
	ActionKind      string   // forward, forward-to-vsys, discard, no-pbf
	EgressInterface string
	NextHop         string // an address or an FQDN; empty when none
	ForwardVsys     string
}

// PBF action kinds.
const (
	PBFForward       = "forward"
	PBFForwardToVsys = "forward-to-vsys"
	PBFDiscard       = "discard"
	PBFNoPBF         = "no-pbf"
)

// PBFRules returns the target's PBF rules in evaluation order.
func (t *Target) PBFRules() []PBFRule {
	var out []PBFRule
	for _, re := range t.ruleEntries(PBF) {
		r := PBFRule{Rule: re.Rule}
		from := re.e.Child("from")
		for _, kind := range []string{"zone", "interface"} {
			if m := from.Child(kind).Members(); len(m) > 0 {
				r.FromKind, r.From = kind, m
			}
		}
		act := re.e.Child("action")
		switch {
		case act.Child("forward") != nil:
			fw := act.Child("forward")
			r.ActionKind = PBFForward
			r.EgressInterface = fw.Child("egress-interface").TextOr("")
			nh := fw.Child("nexthop")
			r.NextHop = firstNonEmpty(nh.Child("ip-address").TextOr(""), nh.Child("fqdn").TextOr(""))
		case act.Child("forward-to-vsys") != nil:
			r.ActionKind = PBFForwardToVsys
			r.ForwardVsys = act.Child("forward-to-vsys").TextOr("")
		case act.Child("discard") != nil:
			r.ActionKind = PBFDiscard
		case act.Child("no-pbf") != nil:
			r.ActionKind = PBFNoPBF
		}
		r.Action = r.ActionKind
		out = append(out, r)
	}
	return out
}

// NATRule is a NAT rule: Rule's member lists (from, to, source, destination), plus
// the single-valued fields and what it translates. Element names from the 11.2
// schema (rulebase/nat/rules/entry, source-translation, destination-translation,
// dynamic-destination-translation).
type NATRule struct {
	Rule
	ToInterface string // the egress interface from the route lookup; "any" when absent
	NATType     string // ipv4, nat64, nptv6
	Service     string
	// Source is the source translation; nil when the rule translates no source.
	Source *SourceTranslation
	// Destination is the destination translation; nil when the rule translates no
	// destination.
	Destination *DestinationTranslation
	// HABinding is the active/active device binding; empty when none.
	HABinding string

	// SourceTranslation is Source's kind, or empty. BiDirectional and
	// StaticAddress are a static-ip Source's fields. DestinationTranslation is
	// destination-translation, dynamic-destination-translation, or empty. They are
	// views of Source and Destination kept for the routing path's NAT detection.
	SourceTranslation      string
	BiDirectional          bool
	StaticAddress          string
	DestinationTranslation string
}

// Source translation kinds, as the schema names them. An element the schema adds
// later reads as UnknownKind + its name, never as "no translation".
const (
	DIPP           = "dynamic-ip-and-port"
	PersistentDIPP = "persistent-dynamic-ip-and-port"
	DynamicIP      = "dynamic-ip"
	StaticIP       = "static-ip"
	UnknownKind    = "unknown:"
)

// SourceTranslation is what a NAT rule makes of the source.
type SourceTranslation struct {
	Kind      string
	Addresses []string // translated-address: members, or the static-ip value
	// Interface, InterfaceIP and FloatingIP are the interface-address form.
	// InterfaceIP is an address with its prefix, or an address object's name.
	Interface   string
	InterfaceIP string
	FloatingIP  string
	// IPv6Interface is dynamic-ip's interface-address with an IPv6 address.
	IPv6Interface string
	Fallback      *SourceTranslation // dynamic-ip's fallback
	BiDirectional bool
}

// Destination translation kinds.
const (
	StaticDestination  = "static"
	DynamicDestination = "dynamic"
)

// DestinationTranslation is what a NAT rule makes of the destination.
type DestinationTranslation struct {
	Kind         string
	Address      string // an address, range, netmask, or an object's name
	Port         int    // 0 when the port is unchanged
	Distribution string // dynamic only: round-robin, source-ip-hash, …
	DNSRewrite   string // static only: the dns-rewrite direction, when set
}

// NATRules returns the target's NAT rules in evaluation order.
func (t *Target) NATRules() []NATRule {
	var out []NATRule
	for _, re := range t.ruleEntries(NAT) {
		e := re.e
		r := NATRule{
			Rule:        re.Rule,
			ToInterface: e.Child("to-interface").TextOr("any"),
			NATType:     e.Child("nat-type").TextOr("ipv4"),
			Service:     e.Child("service").TextOr("any"),
			Source:      readSourceTranslation(e.Child("source-translation")),
			Destination: readDestinationTranslation(e),
			HABinding:   e.Child("active-active-device-binding").TextOr(""),
		}
		if r.Source != nil {
			r.SourceTranslation, r.BiDirectional = r.Source.Kind, r.Source.BiDirectional
			if r.Source.Kind == StaticIP && len(r.Source.Addresses) > 0 {
				r.StaticAddress = r.Source.Addresses[0]
			}
		}
		if r.Destination != nil {
			r.DestinationTranslation = map[string]string{
				StaticDestination: "destination-translation", DynamicDestination: "dynamic-destination-translation",
			}[r.Destination.Kind]
		}
		out = append(out, r)
	}
	return out
}

// readSourceTranslation reads source-translation; nil when absent or empty.
func readSourceTranslation(st *config.Element) *SourceTranslation {
	if st == nil || len(st.Children) == 0 {
		return nil
	}
	c := st.Children[0]
	out := &SourceTranslation{Kind: c.Name}
	switch c.Name {
	case DIPP, PersistentDIPP, DynamicIP:
		readPool(c, out)
		if c.Name == DynamicIP {
			out.IPv6Interface = c.Child("interface-address").Child("interface").TextOr("")
			out.Interface = ""
			if fb := c.Child("fallback"); fb != nil {
				out.Fallback = &SourceTranslation{Kind: DIPP}
				readPool(fb, out.Fallback)
			}
		}
	case StaticIP:
		if a := c.Child("translated-address").TextOr(""); a != "" {
			out.Addresses = []string{a}
		}
		out.BiDirectional = c.Child("bi-directional").TextOr("") == "yes"
	default:
		out.Kind = UnknownKind + c.Name
	}
	return out
}

// readPool reads a translated-address list or an interface-address.
func readPool(e *config.Element, out *SourceTranslation) {
	out.Addresses = e.Child("translated-address").Members()
	if ia := e.Child("interface-address"); ia != nil {
		out.Interface = ia.Child("interface").TextOr("")
		out.InterfaceIP = ia.Child("ip").TextOr("")
		out.FloatingIP = ia.Child("floating-ip").TextOr("")
	}
}

// readDestinationTranslation reads a rule's destination translation, static or
// dynamic; nil when it has none.
func readDestinationTranslation(e *config.Element) *DestinationTranslation {
	for _, kn := range [][2]string{{StaticDestination, "destination-translation"}, {DynamicDestination, "dynamic-destination-translation"}} {
		kind, d := kn[0], e.Child(kn[1])
		if d == nil {
			continue
		}
		out := &DestinationTranslation{
			Kind:         kind,
			Address:      d.Child("translated-address").TextOr(""),
			Distribution: d.Child("distribution").TextOr(""),
			DNSRewrite:   d.Child("dns-rewrite").Child("direction").TextOr(""),
		}
		out.Port, _ = strconv.Atoi(d.Child("translated-port").TextOr("0"))
		if kind == DynamicDestination && out.Distribution == "" {
			out.Distribution = "round-robin" // the schema's default
		}
		return out
	}
	return nil
}
