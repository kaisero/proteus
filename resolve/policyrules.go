package resolve

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
// schema (rulebase/nat/rules/entry).
type NATRule struct {
	Rule
	ToInterface string // the egress interface from the route lookup; "any" when absent
	NATType     string // ipv4, nat64, nptv6
	Service     string
	// SourceTranslation is dynamic-ip-and-port, dynamic-ip, static-ip, or empty.
	SourceTranslation string
	BiDirectional     bool // a static-ip source translation that also translates back
	// StaticAddress is a static-ip translation's translated address: an address
	// or an address object's name.
	StaticAddress string
	// DestinationTranslation is destination-translation, dynamic-destination-translation, or empty.
	DestinationTranslation string
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
		}
		st := e.Child("source-translation")
		for _, kind := range []string{"dynamic-ip-and-port", "dynamic-ip", "static-ip"} {
			if c := st.Child(kind); c != nil {
				r.SourceTranslation = kind
				r.BiDirectional = c.Child("bi-directional").TextOr("") == "yes"
				r.StaticAddress = c.Child("translated-address").TextOr("")
			}
		}
		for _, kind := range []string{"destination-translation", "dynamic-destination-translation"} {
			if e.Child(kind) != nil {
				r.DestinationTranslation = kind
			}
		}
		out = append(out, r)
	}
	return out
}
