package schema

import (
	"fmt"
	"strings"
)

// Reference is one declared target of a field: the kind of object it may name,
// and where that object lives.
//
// Targets come from the schema's memberof declarations. Observed forms:
//
//	#config/shared/address/entry/@name                        config object
//	##/predefined/region/entry/@name                          predefined content
//	#config/shared/address/entry[not(ip-wildcard)]/@name       conditional
//	#myentry(template)/variable/entry[type/ip-netmask]/@name   template variable
//	string('vlan')                                            a literal, not a reference
type Reference struct {
	Field      string // the field declaring the reference, e.g. source
	Scope      string // shared, or empty when the scope is implied by context
	Kind       string // address, address-group, region, ...
	Target     string // the raw declaration, kept for diagnostics
	Predicate  string // XPath predicate, when the target is conditional
	Predefined bool   // the target is predefined content, not configuration
	Template   bool   // the target is a template or template-stack variable
}

// ParseTarget turns one memberof declaration into a Reference. A literal such as
// string('vlan') is not a reference and returns an error.
func ParseTarget(raw string) (Reference, error) {
	ref := Reference{Target: raw}
	s := strings.TrimSpace(raw)
	switch {
	case s == "":
		return ref, fmt.Errorf("schema: empty reference target")
	case strings.HasPrefix(s, "string("):
		return ref, fmt.Errorf("schema: %q is a literal, not a reference", raw)
	case strings.HasPrefix(s, "#myentry("):
		ref.Template = true
		s = s[strings.Index(s, ")")+1:]
	case strings.HasPrefix(s, "##/"):
		ref.Predefined = true
		s = s[2:]
	case strings.HasPrefix(s, "#config"):
		s = s[len("#config"):]
	case strings.HasPrefix(s, "##"):
		ref.Predefined = true
		s = s[2:]
	case strings.HasPrefix(s, "#"):
		s = s[1:]
	}

	if i := strings.Index(s, "["); i >= 0 {
		if j := strings.LastIndex(s, "]"); j > i {
			ref.Predicate = s[i+1 : j]
			s = s[:i] + s[j+1:]
		}
	}
	s = strings.TrimSuffix(s, "/@name")
	s = strings.TrimSuffix(s, "/entry")
	segs := []string{}
	for _, seg := range strings.Split(s, "/") {
		if seg != "" && seg != "entry" {
			segs = append(segs, seg)
		}
	}
	if len(segs) == 0 {
		return ref, fmt.Errorf("schema: cannot read a kind from %q", raw)
	}
	ref.Kind = segs[len(segs)-1]
	if len(segs) > 1 {
		ref.Scope = segs[len(segs)-2]
	}
	if ref.Predefined && len(segs) > 1 {
		ref.Scope = ""
	}
	return ref, nil
}

// References returns every reference a subtree declares, with the declaring field
// recorded. Literals are skipped. Order follows the schema, so a caller sees the
// targets in the order PAN-OS lists them.
func References(n *Node) []Reference {
	var out []Reference
	for _, field := range n.Fields() {
		fieldName := field.Name
		field.Walk(func(cur *Node) {
			for _, raw := range cur.MemberOf {
				ref, err := ParseTarget(raw)
				if err != nil {
					continue
				}
				ref.Field = fieldName
				out = append(out, ref)
			}
		})
	}
	return out
}
