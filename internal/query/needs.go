package query

import (
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// Need is an input that, given in a second call, can change an undecided or
// undermatched answer (spec 2026-10-09 §3.4). Code is the input's code, Input
// its name as a tool takes it, and Text says what to give and which rules it
// decides, in the tool's words.
type Need struct {
	Code  reason.Code `json:"code"`
	Input string      `json:"input"`
	Text  string      `json:"text"`
}

// cause is a reason code that held an answer back, and the rule it belongs
// to, when one does: its kind ("rule", "NAT rule") and name.
type cause struct {
	code reason.Code
	rule ruleName
}

type ruleName struct{ kind, name string }

// needKinds are the inputs a second call can give, in the order needs lists
// them, with what each decides.
var needKinds = []struct {
	code      reason.Code
	input     string
	give, why string
}{
	{"input.protocol", "protocol", "give the protocol: tcp, udp or sctp", "the service"},
	{"input.port", "port", "give the destination port", "the service"},
	{"input.url", "url", "give the URL", "the URL category"},
}

// needsOf is what the causes need from a second call, given the flow asked.
// A service judged without a port needs the port only for tcp, udp or sctp,
// and the protocol too when none was given (the tools have no protocol
// default); icmp or another protocol never needs a port. Every other code
// needs nothing a second call can give: a predefined category, an
// application, a user, a gap, a path, a zone or a default rule. The result is
// never nil, so an undecided answer prints [] when nothing helps.
func needsOf(flow simulate.Flow, causes []cause) []Need {
	rules := map[reason.Code][]ruleName{}
	given := map[reason.Code]bool{}
	add := func(c reason.Code, rule ruleName) {
		given[c] = true
		if rule.name != "" && !slices.Contains(rules[c], rule) {
			rules[c] = append(rules[c], rule)
		}
	}
	for _, c := range causes {
		switch c.code {
		case "doubt.service-no-port", "path.nat-no-port":
			proto := strings.ToLower(flow.Protocol)
			if proto == "" {
				add("input.protocol", c.rule)
			}
			if flow.DestPort == 0 && (proto == "" || proto == "tcp" || proto == "udp" || proto == "sctp") {
				add("input.port", c.rule)
			}
		case "doubt.category-no-url":
			if flow.URL == "" {
				add("input.url", c.rule)
			}
		}
	}
	out := []Need{}
	for _, k := range needKinds {
		if !given[k.code] {
			continue
		}
		text := k.give
		if rs := rules[k.code]; len(rs) > 0 {
			text += "; it decides " + k.why + " of " + ruleList(rs)
		}
		out = append(out, Need{Code: k.code, Input: k.input, Text: text})
	}
	return out
}

// ruleList names rules by kind, in the order they came: "rules a, b and NAT
// rule c".
func ruleList(rs []ruleName) string {
	var kinds []string
	names := map[string][]string{}
	for _, r := range rs {
		if names[r.kind] == nil {
			kinds = append(kinds, r.kind)
		}
		names[r.kind] = append(names[r.kind], r.name)
	}
	var parts []string
	for _, k := range kinds {
		label := k
		if len(names[k]) > 1 {
			label += "s"
		}
		parts = append(parts, label+" "+strings.Join(names[k], ", "))
	}
	return strings.Join(parts, " and ")
}

// holdsBack says whether an answer gets needs: its verdict is undecided or its
// fidelity is undermatch.
func holdsBack(undecided bool, f simulate.Fidelity) bool {
	return undecided || f.Level() == "undermatch"
}

// fidelityCauses are a fidelity's reasons as causes without a rule.
func fidelityCauses(f simulate.Fidelity) []cause {
	var out []cause
	for _, r := range f.Reasons() {
		out = append(out, cause{code: r.Code})
	}
	return out
}

// securityCauses are the doubts of the candidates before the first certain
// match: the ones that hold the verdict back.
func securityCauses(v *securitypolicy.Verdict) []cause {
	if v == nil {
		return nil
	}
	var out []cause
	for _, d := range v.Doubts {
		if v.Rule != nil && d.Position >= v.Rule.Position {
			continue
		}
		for _, r := range d.Reasons {
			out = append(out, cause{code: r.Code, rule: ruleName{"rule", d.Rule}})
		}
	}
	return out
}

// natCauses are NAT doubts: rules that may match instead of the one taken.
func natCauses(ds []nat.Doubt) []cause {
	var out []cause
	for _, d := range ds {
		for _, r := range d.Reasons {
			out = append(out, cause{code: r.Code, rule: ruleName{"NAT rule", d.Rule}})
		}
	}
	return out
}

// securityNeeds is a file answer's needs; nil when it is decided and exact
// enough.
func securityNeeds(flow simulate.Flow, verdict string, v *securitypolicy.Verdict, f simulate.Fidelity) []Need {
	if !holdsBack(verdict == string(securitypolicy.Undecided), f) {
		return nil
	}
	return needsOf(flow, append(securityCauses(v), fidelityCauses(f)...))
}

// pathNeeds is a path answer's needs: each undecided check's doubts and each
// hop's NAT doubts.
func pathNeeds(flow simulate.Flow, r pathpolicy.Result) []Need {
	if !holdsBack(r.Verdict == pathpolicy.VerdictUndecided, r.Fidelity) {
		return nil
	}
	causes := fidelityCauses(r.Fidelity)
	for _, h := range r.Hops {
		causes = append(causes, natCauses(h.Routing.NATDoubts)...)
		for _, c := range h.Checks {
			if c.Verdict == pathpolicy.Undecided {
				causes = append(causes, securityCauses(c.Security)...)
			}
		}
	}
	return needsOf(flow, causes)
}

// routingNeeds is a routing answer's needs. A hop whose NAT rule another rule
// may replace leaves the path undecided there.
func routingNeeds(flow simulate.Flow, p routing.Path, f simulate.Fidelity) []Need {
	var causes []cause
	for _, h := range p.Hops {
		causes = append(causes, natCauses(h.NATDoubts)...)
	}
	if !holdsBack(len(causes) > 0, f) {
		return nil
	}
	return needsOf(flow, append(causes, fidelityCauses(f)...))
}

// natNeeds is a NAT answer's needs. A rule that may match instead leaves the
// NAT rule undecided.
func natNeeds(flow simulate.Flow, r nat.Result, f simulate.Fidelity) []Need {
	if !holdsBack(len(r.Doubts) > 0, f) {
		return nil
	}
	return needsOf(flow, append(natCauses(r.Doubts), fidelityCauses(f)...))
}
