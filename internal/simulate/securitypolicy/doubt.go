package securitypolicy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/rulebase"
)

// Doubt names a candidate the check cannot decide, and why. It does not change
// which rules are candidates. Most doubts have one reason; a rule naming several
// opaque addresses in one field has one per address. JSON writes
// {"position", "rule", "reasons": [{"code", "text"}]} (spec 2026-10-09 §12 C6).
type Doubt struct {
	Position int              `json:"position"` // the rule's position in the effective order
	Rule     string           `json:"rule"`
	Reasons  simulate.Reasons `json:"reasons"` // "application not evaluated (quic)", "service application-default", ...
}

// Text is the reasons as one line, as the output shows them.
func (d Doubt) Text() string { return d.Reasons.Text() }

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

// doubtCodes gives each doubtful field its code (spec §3.1, §12 C7, C8). A
// doubtful field missing here fails every test that reaches it.
var doubtCodes = map[string]reason.Code{
	"source-user":      "doubt.not-evaluated.user",
	"application":      "doubt.application",
	"source-imsi":      "doubt.imsi",
	"source-imei":      "doubt.imei",
	"source-nw-slice":  "doubt.nw-slice",
	"source-hip":       "doubt.hip",
	"destination-hip":  "doubt.hip",
	"saas-user-list":   "doubt.saas-user-list",
	"saas-tenant-list": "doubt.saas-tenant-list",
}

// doubts lists the doubts of the current candidates, in rule order: per
// candidate, the fields it sets that no stage evaluates (spec §4.7).
func (s *state) doubts() []Doubt {
	var out []Doubt
	services := rulebase.Defined(s.target.Config, s.idx.Scope(), resolve.Security, "service")
	categories := rulebase.Defined(s.target.Config, s.idx.Scope(), resolve.Security, "category")
	for _, r := range s.verdict.Candidates {
		add := func(why ...reason.Reason) {
			out = append(out, Doubt{Position: r.Position, Rule: r.Name, Reasons: why})
		}
		for _, f := range ruleFields {
			switch {
			case f.name == "service":
				if why := s.serviceDoubt(r.Fields["service"], services); why.Text != "" {
					add(why)
				}
			case f.name == "category":
				if why := s.categoryDoubt(r.Fields["category"], categories); why.Text != "" {
					add(why)
				}
			case f.name == "source" || f.name == "destination":
				//nolint:gosec // a rule position cannot reach 2^32; a rulebase is capped far below that
				if why, ok := s.opaque[f.name][uint32(r.Position-1)]; ok {
					add(simulate.Reasons(why).Prefixed(f.name + ": ")...)
				}
				switch m := s.fqdn[f.name]; {
				case m.rules == nil:
				case m.rules.Contains(uint32(r.Position - 1)): //nolint:gosec // as above
					add(reason.New("doubt.fqdn-resolution", fmt.Sprintf(
						"%s: %s matched only through an FQDN object; the firewall resolves this object itself; its addresses can differ from ours", f.name, m.name)))
				case m.negated.Contains(uint32(r.Position - 1)): //nolint:gosec // as above
					add(reason.New("doubt.fqdn-resolution", fmt.Sprintf(
						"%s: %s excluded from the negated field only through an FQDN object; the firewall resolves this object itself; its addresses can differ from ours", f.name, m.name)))
				}
			case f.class != doubtful:
			case f.name == "schedule":
				if r.Schedule != "" {
					add(reason.New("doubt.schedule", fmt.Sprintf("schedule not evaluated (%s)", r.Schedule)))
				}
			default:
				if vs := notAny(r.Fields[f.name]); len(vs) > 0 {
					label := f.name
					if l, ok := doubtLabel[label]; ok {
						label = l
					}
					add(reason.New(doubtCodes[f.name], fmt.Sprintf("%s not evaluated (%s)", label, strings.Join(vs, ", "))))
				}
			}
		}
	}
	return out
}

// serviceDoubt says why a rule's service cannot be judged on this flow, or the
// zero reason when it can: matchService evaluates a service the configuration defines,
// against a tcp, udp or sctp port.
func (s *state) serviceDoubt(vs []string, defined map[string]bool) reason.Reason {
	if len(vs) == 0 {
		return reason.New("doubt.service-absent", "service absent")
	}
	vs = notAny(vs)
	if len(vs) == 0 {
		return reason.Reason{}
	}
	// A port decides only a service the configuration defines. When every
	// value is application-default or not defined, no port helps, so that
	// doubt comes first and the answer asks for no port.
	judged := slices.ContainsFunc(vs, func(v string) bool { return v != "application-default" && defined[v] })
	f := s.in.Flow
	if proto := strings.ToLower(f.Protocol); judged && (f.DestPort == 0 || (proto != "tcp" && proto != "udp" && proto != "sctp")) {
		return reason.New("doubt.service-no-port",
			fmt.Sprintf("service not evaluated without a tcp, udp or sctp port (%s)", strings.Join(vs, ", ")))
	}
	if slices.Contains(vs, "application-default") {
		return reason.New("doubt.service-application-default", "service application-default")
	}
	var unknown []string
	for _, v := range vs {
		if !defined[v] {
			unknown = append(unknown, v)
		}
	}
	if len(unknown) > 0 {
		return reason.New("doubt.service-predefined",
			fmt.Sprintf("service predefined or not defined in the configuration (%s)", strings.Join(unknown, ", ")))
	}
	return reason.Reason{}
}

// categoryDoubt says why a rule's URL category cannot be judged on this flow, or
// the zero reason when it can. A rule without a category matches every URL, as
// any does.
func (s *state) categoryDoubt(vs []string, defined map[string]bool) reason.Reason {
	vs = notAny(vs)
	if len(vs) == 0 {
		return reason.Reason{}
	}
	// A URL decides only a category the configuration defines; when none is
	// defined (PAN-DB categories), no URL helps, so that doubt comes first.
	if s.in.Flow.URL == "" && slices.ContainsFunc(vs, func(v string) bool { return defined[v] }) {
		return reason.New("doubt.category-no-url",
			fmt.Sprintf("url category not evaluated without a URL (%s)", strings.Join(vs, ", ")))
	}
	var unknown []string
	for _, v := range vs {
		if !defined[v] {
			unknown = append(unknown, v)
		}
	}
	if len(unknown) > 0 {
		return reason.New("doubt.category-undefined",
			fmt.Sprintf("url category not defined in the configuration, such as a PAN-DB category (%s)", strings.Join(unknown, ", ")))
	}
	return reason.Reason{}
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
