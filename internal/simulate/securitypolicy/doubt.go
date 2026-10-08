package securitypolicy

import (
	"fmt"
	"slices"
	"strings"
)

// Doubt names a candidate the check cannot decide, and why. It does not change
// which rules are candidates.
type Doubt struct {
	Position int    `json:"position"` // the rule's position in the effective order
	Rule     string `json:"rule"`
	Reason   string `json:"reason"` // "application not evaluated (quic)", "service application-default", ...
}

// fieldClass says how the check treats one child of a security rule entry.
type fieldClass int

const (
	// evaluated: a stage matches the flow on it. service and category are
	// evaluated only when the flow carries a port or a URL and the configuration
	// defines the value; otherwise a candidate naming them has a doubt.
	evaluated fieldClass = iota + 1
	// doubtful: a matching field no stage evaluates, so a candidate that sets it
	// to something other than any has a doubt.
	doubtful
	// notMatching: the device does not match a flow on it.
	notMatching
)

// ruleFields classifies every child of a security rule entry, in schema order.
// The schema says what a child holds, not whether the device matches a flow on it
// nor whether this check evaluates it, so the list is hand-modelled (R8,
// schema.HandModelled). A test fails when the schema has a child the list does not
// classify. Source for the matching fields: PAN-OS admin guide, "Security Policy
// Rule" (Source, Destination, Application, Service/URL Category tabs) and the
// schema's help tips.
var ruleFields = []struct {
	name  string
	class fieldClass
}{
	{"name", notMatching}, // the attribute that names the rule
	{"from", evaluated},
	{"to", evaluated},
	{"source", evaluated},
	{"source-user", doubtful},
	{"destination", evaluated},
	{"service", evaluated},
	{"category", evaluated},
	{"application", doubtful},
	{"source-imsi", doubtful},
	{"source-imei", doubtful},
	{"source-nw-slice", doubtful},
	{"source-hip", doubtful},
	{"destination-hip", doubtful},
	{"schedule", doubtful},
	{"tag", notMatching},
	{"negate-source", evaluated},
	{"negate-destination", evaluated},
	{"disabled", evaluated},
	{"description", notMatching},
	{"group-tag", notMatching},
	{"saas-user-list", doubtful},
	{"saas-tenant-list", doubtful},
	{"action", evaluated},
	{"icmp-unreachable", notMatching},
	{"disable-inspect", notMatching},
	{"rule-type", evaluated},
	{"option", notMatching},
	{"log-setting", notMatching},
	{"log-start", notMatching},
	{"log-end", notMatching},
	{"profile-setting", notMatching},
	{"qos", notMatching},
}

// doubtLabel is how a doubt names a field no stage evaluates.
var doubtLabel = map[string]string{"source-user": "user"}

// doubts lists the doubts of the current candidates, in rule order: per
// candidate, the fields it sets that no stage evaluates (spec §4.7).
func (s *state) doubts() []Doubt {
	var out []Doubt
	services := definedIn(s.target.Config, s.target.Index.Scope(), "service")
	categories := definedIn(s.target.Config, s.target.Index.Scope(), "category")
	for _, r := range s.verdict.Candidates {
		add := func(reason string) {
			out = append(out, Doubt{Position: r.Position, Rule: r.Name, Reason: reason})
		}
		for _, f := range ruleFields {
			switch {
			case f.name == "service":
				if why := s.serviceDoubt(r.Fields["service"], services); why != "" {
					add(why)
				}
			case f.name == "category":
				if why := s.categoryDoubt(r.Fields["category"], categories); why != "" {
					add(why)
				}
			case f.name == "source" || f.name == "destination":
				//nolint:gosec // a rule position cannot reach 2^32; a rulebase is capped far below that
				if why, ok := s.opaque[f.name][uint32(r.Position-1)]; ok {
					add(f.name + ": " + why)
				}
			case f.class != doubtful:
			case f.name == "schedule":
				if r.Schedule != "" {
					add(fmt.Sprintf("schedule not evaluated (%s)", r.Schedule))
				}
			default:
				if vs := notAny(r.Fields[f.name]); len(vs) > 0 {
					label := f.name
					if l, ok := doubtLabel[label]; ok {
						label = l
					}
					add(fmt.Sprintf("%s not evaluated (%s)", label, strings.Join(vs, ", ")))
				}
			}
		}
	}
	return out
}

// serviceDoubt says why a rule's service cannot be judged on this flow, or ""
// when it can: matchService evaluates a service the configuration defines,
// against a tcp, udp or sctp port.
func (s *state) serviceDoubt(vs []string, defined map[string]bool) string {
	if len(vs) == 0 {
		return "service absent"
	}
	vs = notAny(vs)
	if len(vs) == 0 {
		return ""
	}
	f := s.in.Flow
	if proto := strings.ToLower(f.Protocol); f.DestPort == 0 || (proto != "tcp" && proto != "udp" && proto != "sctp") {
		return fmt.Sprintf("service not evaluated without a tcp, udp or sctp port (%s)", strings.Join(vs, ", "))
	}
	if slices.Contains(vs, "application-default") {
		return "service application-default"
	}
	var unknown []string
	for _, v := range vs {
		if !defined[v] {
			unknown = append(unknown, v)
		}
	}
	if len(unknown) > 0 {
		return fmt.Sprintf("service predefined or not defined in the configuration (%s)", strings.Join(unknown, ", "))
	}
	return ""
}

// categoryDoubt says why a rule's URL category cannot be judged on this flow, or
// "" when it can. A rule without a category matches every URL, as any does.
func (s *state) categoryDoubt(vs []string, defined map[string]bool) string {
	vs = notAny(vs)
	if len(vs) == 0 {
		return ""
	}
	if s.in.Flow.URL == "" {
		return fmt.Sprintf("url category not evaluated without a URL (%s)", strings.Join(vs, ", "))
	}
	var unknown []string
	for _, v := range vs {
		if !defined[v] {
			unknown = append(unknown, v)
		}
	}
	if len(unknown) > 0 {
		return fmt.Sprintf("url category not defined in the configuration, such as a PAN-DB category (%s)", strings.Join(unknown, ", "))
	}
	return ""
}

// notAny returns the values other than any.
func notAny(vs []string) []string {
	var out []string
	for _, v := range vs {
		if v != "any" {
			out = append(out, v)
		}
	}
	return out
}
