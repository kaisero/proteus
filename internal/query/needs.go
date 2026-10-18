package query

import (
	"slices"
	"strings"

	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/nat"
	"github.com/kaisero/proteus/internal/simulate/pathpolicy"
	"github.com/kaisero/proteus/internal/simulate/routing"
	"github.com/kaisero/proteus/internal/simulate/rulebase"
	"github.com/kaisero/proteus/internal/simulate/securitypolicy"
)

// Need is an input that, given in a second call, can change an undecided or
// undermatched answer (spec 2026-10-09 §3.4). Code is the input's code, Input
// its name as a tool takes it, and Text says what to give and which rules it
// decides, in the tool's words.
type Need struct {
	Code  reason.Code `json:"code" jsonschema:"the input's code: input.port, input.protocol, input.url, input.application, input.from-zone or input.to-zone"`
	Input string      `json:"input" jsonschema:"the input to give in a second call"`
	Text  string      `json:"text" jsonschema:"what to give and which rules it decides"`
}

// cause is a reason code that held an answer back, and the rule it belongs
// to, when one does: its kind ("rule", "NAT rule") and name. doubtCauses
// gives the input codes a rule's doubts need, judged with the flow of their
// run; needsOf takes such a code as it is.
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
	{"input.application", "application", "give the application", "the application"},
	{"input.from-zone", "from_zone", "give the source zone, with to_zone", "the rule-type"},
	{"input.to-zone", "to_zone", "give the destination zone, with from_zone", "the rule-type"},
}

// needsOf is what the causes need from a second call, given the flow asked.
// A service judged without a port needs the port only for tcp, udp or sctp,
// and the protocol too when none was given (the tools have no protocol
// default); icmp or another protocol never needs a port. A protocol given by
// number counts by its name. An application-default rule judged without a
// port or a protocol needs them the same way (spec 2026-10-16 §4.5). A NAT
// service whose port fits without a protocol needs the protocol. Derived
// zones that leave rule-type or the default rule open need both zones. A rule
// that names an application, or uses service application-default, needs the
// application when none was given and apps says the target has application
// data to decide it (C8). Every other code needs nothing a second call can
// give: a predefined category, an unknown application, a user, a gap, a path,
// a zone or a default rule. The result is never nil, so an undecided answer
// prints [] when nothing helps.
func needsOf(flow simulate.Flow, apps bool, causes []cause) []Need {
	rules := map[reason.Code][]ruleName{}
	given := map[reason.Code]bool{}
	add := func(c reason.Code, rule ruleName) {
		given[c] = true
		if rule.name != "" && !slices.Contains(rules[c], rule) {
			rules[c] = append(rules[c], rule)
		}
	}
	for _, c := range causes {
		if strings.HasPrefix(string(c.code), "input.") {
			add(c.code, c.rule) // judged by doubtCauses
			continue
		}
		switch c.code {
		case "doubt.application", "doubt.service-application-default":
			// With data, the application decides the rule's application and
			// the ports of its application-default service (spec 2026-10-16
			// §4.4, §4.8).
			if apps && flow.Application == "" {
				add("input.application", c.rule)
			}
		case "doubt.service-no-port", "path.nat-no-port", "doubt.app-port-open":
			proto := rulebase.Protocol(flow.Protocol)
			if proto == "" {
				add("input.protocol", c.rule)
			}
			if flow.DestPort == 0 && (proto == "" || proto == "tcp" || proto == "udp" || proto == "sctp") {
				add("input.port", c.rule)
			}
		case "path.nat-no-protocol":
			if flow.Protocol == "" {
				add("input.protocol", c.rule)
			}
		case "zone.derived", "default.zones-unknown":
			// Given zones settle rule-type and the default rule; one
			// configuration takes both or neither.
			if flow.FromZone == "" {
				add("input.from-zone", c.rule)
				add("input.to-zone", c.rule)
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
// match, in rule order, cut as doubtCauses cuts them. blocked says a doubt no
// input can fix was met. They are judged as the run judged the flow: with its
// protocol and its application data (runJudged).
func securityCauses(flow simulate.Flow, v *securitypolicy.Verdict) (out []cause, blocked bool) {
	if v == nil {
		return nil, false
	}
	flow, apps := runJudged(flow, v)
	ds := slices.Clone(v.Doubts)
	slices.SortStableFunc(ds, func(a, b securitypolicy.Doubt) int { return a.Position - b.Position })
	var before []ruleDoubt
	for _, d := range ds {
		if v.Rule != nil && d.Position >= v.Rule.Position {
			continue
		}
		before = append(before, ruleDoubt{d.Rule, d.Reasons})
	}
	return doubtCauses(flow, apps, "rule", before)
}

// runJudged is the flow as a security run judged it, and whether the run's
// target had application data. A flow with an application and no protocol
// runs with the protocol of the application's default (spec 2026-10-16
// §4.1), so a port need follows that protocol and not the open one.
func runJudged(flow simulate.Flow, v *securitypolicy.Verdict) (simulate.Flow, bool) {
	if v == nil {
		return flow, false
	}
	if v.Protocol != "" {
		flow.Protocol = v.Protocol
	}
	return flow, v.AppData
}

// natCauses are NAT doubts: rules that may match instead of the one taken.
// The NAT rulebase is first match too, and the doubts come in rule order, all
// above the rule taken, so they are cut as doubtCauses cuts them.
func natCauses(flow simulate.Flow, ds []nat.Doubt) (out []cause, blocked bool) {
	rds := make([]ruleDoubt, len(ds))
	for i, d := range ds {
		rds[i] = ruleDoubt{d.Rule, d.Reasons}
	}
	return doubtCauses(flow, false, "NAT rule", rds)
}

// ruleDoubt is a rule in doubt and why.
type ruleDoubt struct {
	rule    string
	reasons simulate.Reasons
}

// doubtCauses are the causes of rules in doubt, given in rule order, up to the
// first doubt no input can fix: past that rule no second call changes the
// verdict, so its doubts and the ones after it need nothing. blocked says such
// a doubt was met. A doubt with one reason an input settles does not block:
// that input can rule the rule out, so its fixable causes count and the walk
// goes on. Each cause is the input code a reason needs, judged here with the
// flow and apps of the rule's run, so the hops of a path keep their own.
func doubtCauses(flow simulate.Flow, apps bool, kind string, ds []ruleDoubt) (out []cause, blocked bool) {
	for _, d := range ds {
		var cs []cause
		for _, r := range d.reasons {
			for _, n := range needsOf(flow, apps, []cause{{code: r.Code}}) {
				cs = append(cs, cause{code: n.Code, rule: ruleName{kind, d.rule}})
			}
		}
		if len(cs) == 0 {
			return out, true
		}
		out = append(out, cs...)
	}
	return out, false
}

// securityNeeds is a file answer's needs; nil when it is decided and exact
// enough. A doubt no input can fix ends the list, fidelity reasons included.
func securityNeeds(flow simulate.Flow, verdict string, v *securitypolicy.Verdict, f simulate.Fidelity) []Need {
	if !holdsBack(verdict == string(securitypolicy.Undecided), f) {
		return nil
	}
	causes, blocked := securityCauses(flow, v)
	if !blocked {
		causes = append(causes, fidelityCauses(f)...)
	}
	flow, apps := runJudged(flow, v)
	return needsOf(flow, apps, causes)
}

// pathNeeds is a path answer's needs: each undecided check's doubts and each
// hop's NAT doubts; the fidelity's reasons too unless a check or a NAT rule met
// a doubt no input can fix. The path gives each hop's zones, so no zone is
// asked for.
func pathNeeds(flow simulate.Flow, r pathpolicy.Result) []Need {
	if !holdsBack(r.Verdict == pathpolicy.VerdictUndecided, r.Fidelity) {
		return nil
	}
	flow.FromZone, flow.ToZone = "path", "path"
	var causes []cause
	blocked := false
	for _, h := range r.Hops {
		cs, b := natCauses(flow, h.Routing.NATDoubts)
		causes, blocked = append(causes, cs...), blocked || b
		for _, c := range h.Checks {
			if c.Verdict == pathpolicy.Undecided {
				cs, b := securityCauses(flow, c.Security)
				causes, blocked = append(causes, cs...), blocked || b
			}
		}
	}
	if !blocked {
		causes = append(fidelityCauses(r.Fidelity), causes...)
	}
	return needsOf(flow, false, causes)
}

// routingNeeds is a routing answer's needs. A hop whose NAT rule another rule
// may replace leaves the path undecided there. So does a hop whose PBF rule may
// or may not take the flow: why it may not, such as a service without the
// port, is a cause an input can settle.
func routingNeeds(flow simulate.Flow, p routing.Path, f simulate.Fidelity) []Need {
	var causes []cause
	doubted, blocked := false, false
	for _, h := range p.Hops {
		cs, b := natCauses(flow, h.NATDoubts)
		causes, blocked = append(causes, cs...), blocked || b
		for _, r := range h.PBFDoubts {
			causes = append(causes, cause{code: r.Code})
		}
		doubted = doubted || len(h.NATDoubts) > 0 || len(h.PBFDoubts) > 0
	}
	if !holdsBack(doubted, f) {
		return nil
	}
	if !blocked {
		causes = append(causes, fidelityCauses(f)...)
	}
	return needsOf(flow, false, causes)
}

// natNeeds is a NAT answer's needs. A rule that may match instead leaves the
// NAT rule undecided.
func natNeeds(flow simulate.Flow, r nat.Result, f simulate.Fidelity) []Need {
	if !holdsBack(len(r.Doubts) > 0, f) {
		return nil
	}
	causes, blocked := natCauses(flow, r.Doubts)
	if !blocked {
		causes = append(causes, fidelityCauses(f)...)
	}
	return needsOf(flow, false, causes)
}
