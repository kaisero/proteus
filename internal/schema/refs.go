package schema

import (
	"fmt"
	"strings"
)

// TargetForm is what a memberof declaration actually names.
//
// Counted over the 13,120 declarations in the 11.2.0 Panorama schema: 7,111 objects,
// 2,536 predefined, 1,069 template variables, 1,362 rule fields, 915 expressions and 127
// unrecognised. Only objects and predefined targets are index edges. The census test in
// internal/digest pins these.
//
// A firewall schema has no template variables at all, which stands to reason because a
// firewall has no templates. An earlier rule here treated every "#myentry(" anchor as
// one, discarding 1,413 real object references in the Panorama schema and 1,455 in the
// firewall schema, the zone targets of a security rule's from and to among them.
type TargetForm int

// The forms a memberof declaration takes.
const (
	FormUnknown     TargetForm = iota // unrecognised, and counted so it cannot grow unnoticed
	FormObject                        // #config/<scope>/<kind>/entry/@name
	FormPredefined                    // ##/predefined/<kind>/entry/@name
	FormTemplateVar                   // #myentry(template)/variable/entry/@name
	FormRuleField                     // ##/…/*/rules/entry/<field>/member
	FormExpression                    // string(…) or substring(…): computed, not a reference
)

var formNames = map[TargetForm]string{
	FormUnknown: "unknown", FormObject: "object", FormPredefined: "predefined",
	FormTemplateVar: "template-variable", FormRuleField: "rule-field",
	FormExpression: "expression",
}

func (f TargetForm) String() string {
	if s, ok := formNames[f]; ok {
		return s
	}
	return "unknown"
}

// ClassifyTarget decides what a raw memberof declaration names.
//
// A path-shaped target always starts with #. A computed expression never does:
// they begin string( or substring(, and 1,710 of the latter would slip past a
// leading-string( check. Testing the prefix rather than looking for parentheses
// also keeps a conditional reference intact, because its predicate contains
// them: #config/shared/address/entry[not(ip-wildcard)]/@name.
func ClassifyTarget(raw string) TargetForm {
	s := strings.TrimSpace(raw)
	if s == "" {
		return FormUnknown
	}
	if !strings.HasPrefix(s, "#") {
		if strings.ContainsAny(s, "()") {
			return FormExpression
		}
		return FormUnknown
	}
	switch {
	case isTemplateVariable(s):
		return FormTemplateVar
	case strings.Contains(withoutPredicate(s), "*"):
		return FormRuleField
	case strings.HasPrefix(s, "##"):
		return FormPredefined
	default:
		return FormObject
	}
}

// isTemplateVariable reports whether a target names a template variable.
//
// The anchor alone does not decide it. "#myentry(...)" is a scope-relative path
// meaning "the vsys, device or shared gateway this entry belongs to", and almost all of
// them are ordinary object references: #myentry(vsys)/zone/entry/@name names a zone.
// A template variable is specifically a variable under a template or a template stack.
//
// Counted over both shipped schemas: of 1,455 scope-relative targets in the firewall
// schema, none are template variables, which stands to reason because a firewall has no
// templates. Treating the anchor as sufficient therefore discarded every one of them,
// including the zone targets of a security rule's from and to fields.
func isTemplateVariable(s string) bool {
	for _, anchor := range []string{"#myentry(template)/", "#myentry(template-stack)/"} {
		if rest, ok := cutPrefix(s, anchor); ok && strings.HasPrefix(rest, "variable/") {
			return true
		}
	}
	return false
}

func cutPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	return s[len(prefix):], true
}

// withoutPredicate removes any [..] predicate, so a wildcard inside one is not
// mistaken for a rule-field target.
func withoutPredicate(s string) string {
	for {
		i := strings.Index(s, "[")
		if i < 0 {
			return s
		}
		j := strings.Index(s[i:], "]")
		if j < 0 {
			return s[:i]
		}
		s = s[:i] + s[i+j+1:]
	}
}

// Reference is one declared target of a field: the kind of object it may name,
// and where that object lives.
type Reference struct {
	Field      string     // the field declaring the reference, e.g. source
	Scope      string     // shared, or empty when the scope is implied by context
	Kind       string     // address, address-group, region, ...
	Target     string     // the raw declaration, kept for diagnostics
	Predicate  string     // XPath predicate, when the target is conditional
	Form       TargetForm // what the declaration names
	Predefined bool       // the target is predefined content, not configuration
	Template   bool       // the target is a template or template-stack variable
}

// ParseTarget turns one memberof declaration into a Reference. Only an object or
// predefined target is a reference; every other form returns an error naming what
// it is, so a caller can count the forms rather than guess.
func ParseTarget(raw string) (Reference, error) {
	form := ClassifyTarget(raw)
	ref := Reference{Target: raw, Form: form}
	switch form {
	case FormObject, FormPredefined:
	default:
		ref.Template = form == FormTemplateVar
		return ref, fmt.Errorf("schema: %q is a %s, not an object reference", raw, form)
	}
	ref.Predefined = form == FormPredefined

	s := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(s, "##/"):
		s = s[2:]
	case strings.HasPrefix(s, "#config"):
		s = s[len("#config"):]
	case strings.HasPrefix(s, "##"):
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

// FieldRefs is one field and the object kinds it may name.
type FieldRefs struct {
	Field      string
	Candidates []string // in the order the schema lists them
	Predefined []bool   // Predefined[i] reports whether Candidates[i] is predefined content
}

// References returns the reference fields of a subtree, grouped by field.
//
// A field often has more than one candidate: of 2,961 reference fields in
// cms-schema.xml, 1,034 declare two or more and the worst declares 153. A single
// resolved kind cannot be known from the schema alone, so the caller gets the
// candidates and resolves against the scope. TestReferenceFieldCensus pins the
// counts, because they moved when scope-relative targets started parsing.
func References(n *Node) []FieldRefs {
	var out []FieldRefs
	for _, field := range n.Fields() {
		fr := FieldRefs{Field: field.Name}
		seen := map[string]bool{}
		field.Walk(func(cur *Node) {
			for _, raw := range cur.MemberOf {
				ref, err := ParseTarget(raw)
				if err != nil || seen[ref.Kind] {
					continue
				}
				seen[ref.Kind] = true
				fr.Candidates = append(fr.Candidates, ref.Kind)
				fr.Predefined = append(fr.Predefined, ref.Predefined)
			}
		})
		if len(fr.Candidates) > 0 {
			out = append(out, fr)
		}
	}
	return out
}
