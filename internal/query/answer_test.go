package query

import (
	"net/netip"
	"testing"

	"github.com/kaisero/proteus/internal/drift"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/nat"
	"github.com/kaisero/proteus/internal/simulate/pathpolicy"
	"github.com/kaisero/proteus/internal/simulate/routing"
	"github.com/kaisero/proteus/internal/simulate/securitypolicy"
)

// Each builder's lines, beside the ones the goldens show.
func TestAnswerLines(t *testing.T) {
	t.Parallel()
	addr := func(s string) simulate.Endpoint { return simulate.Addr(netip.MustParseAddr(s)) }
	flow := simulate.Flow{Source: addr("10.0.0.1"), Destination: addr("10.0.0.2"), DestPort: 80}
	rule := &nat.Rule{NATRule: resolve.NATRule{Rule: resolve.Rule{Name: "r"}}}
	for _, tc := range []struct{ got, want string }{
		{PathAnswer(pathpolicy.Result{Verdict: "allowed"}), "allowed"},
		{
			PathAnswer(pathpolicy.Result{Verdict: "undecided", At: &pathpolicy.Point{Reason: simulate.Reasons{reason.New("path.loop", "no hop")}}}),
			"undecided at hop 0: no hop",
		},
		{PathAnswer(path("undecided", "security", "")), "undecided at hop 1: fw01 / vsys1, why"},
		{PathAnswer(path("denied", "routing", "")), "denied at hop 1: no route to 10.0.0.9 on fw01"},
		{PathAnswer(path("denied", "security", "block")), "denied at hop 1: fw01 / vsys1, rule block (deny)"},
		{CheckAction(pathpolicy.CheckResult{Security: &securitypolicy.Verdict{DefaultAction: "deny"}}), "deny"},
		{CheckAction(pathpolicy.CheckResult{}), ""},
		{CheckAction(pathpolicy.CheckResult{Security: &securitypolicy.Verdict{Rule: &resolve.Rule{Action: "allow"}}}), "allow"},
		{FileAnswer(securitypolicy.Verdict{}), "no enabled rule matches"},
		{FileAnswer(securitypolicy.Verdict{Rule: &resolve.Rule{Name: "a", Action: "allow"}}), "first match: a (allow)"},
		{FileAnswer(securitypolicy.Verdict{Undecided: simulate.Reasons{reason.New("doubt.hip", "x")}}), "undecided: x"},
		{DecisionLine(securitypolicy.Verdict{Candidates: []resolve.Rule{{Name: "a"}}}, nil), ""},
		{DecisionLine(securitypolicy.Verdict{Undecided: simulate.Reasons{reason.New("doubt.hip", "x")}, Default: "d", DefaultAction: "deny", DefaultSource: "built-in"},
			func(s string) string { return "<" + s + ">" }), "first certain match: <d> (deny), default rule (built-in)"},
		{NATAnswer(nat.Result{MatchResult: nat.MatchResult{Dropped: "no route"}}, flow), "no NAT rule matches: no route"},
		{NATAnswer(nat.Result{}, flow), "no NAT rule matches"},
		{NATAnswer(nat.Result{MatchResult: nat.MatchResult{Rule: rule}}, flow), "r: no translation"},
		{NATAnswer(nat.Result{
			MatchResult: nat.MatchResult{Rule: rule},
			Source:      &nat.Translation{Candidates: []string{"1.1.1.1", "1.1.1.2"}, Port: nat.PortRuntime, Fallback: []string{"2.2.2.2"}},
			Destination: &nat.Translation{Port: nat.PortUnchanged, Others: []string{"3.3.3.3"}},
		}, flow), "r: source 10.0.0.1 -> 1.1.1.1, 1.1.1.2, port assigned at runtime; fallback 2.2.2.2; destination 10.0.0.2:80 -> (no address) (also 3.3.3.3, by distribution)"},
		{SourceTranslation("(no source)", &nat.Translation{Candidates: []string{"1.1.1.1"}, Port: nat.PortUnchanged}), "(no source) -> 1.1.1.1, port unchanged"},
		{DestinationTranslation(&nat.Translation{Address: netip.MustParseAddr("4.4.4.4"), Port: "443"}, 0), "4.4.4.4:443"},
		{EndpointText(simulate.Endpoint{}), "(no source)"},
		{PortNumber(0), "(any)"},
		{FindingAnswer(Target{Device: "fw01", Vsys: "vsys1"}, "address", "a", ""), "fw01/vsys1: address a"},
		{FindingAnswer(Target{Device: "fw01"}, "security rule", "r", "source"), "fw01: security rule r (source)"},
		{LookupAnswer(Target{Device: "fw01", Vsys: "vsys2"}, "address", "a"), "fw01/vsys2: address a"},
		{
			DiffAnswer("fw01", "shared", []drift.Change{{Op: drift.Added}, {Op: drift.Removed}, {Op: drift.Changed}, {Op: drift.Changed}}),
			"fw01/shared: 1 added, 1 removed, 2 changed",
		},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

// path is a one-hop path answer decided at its hop by check, with a NAT that
// moved the destination.
func path(verdict pathpolicy.Verdict, check, rule string) pathpolicy.Result {
	post := simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr("10.0.0.9"))}
	return pathpolicy.Result{
		Verdict: verdict,
		At:      &pathpolicy.Point{Hop: 1, Check: check, Rule: rule, Reason: simulate.Reasons{reason.New("doubt.hip", "why")}},
		Hops: []pathpolicy.Hop{{Index: 1, Routing: routing.Hop{Device: "fw01", Vsys: "vsys1", PostNAT: &post}, Checks: []pathpolicy.CheckResult{
			{Name: "security", Security: &securitypolicy.Verdict{Rule: &resolve.Rule{Name: rule, Action: "deny"}}},
		}}},
	}
}
