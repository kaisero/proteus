package query

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
	"github.com/okaiser/proteus/internal/store"
)

// codePattern finds every reason code in a result's JSON.
var codePattern = regexp.MustCompile(`"code":"([^"]+)"`)

// codes is the set of reason codes a result carries, needs left out.
func codes(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range codePattern.FindAllStringSubmatch(string(b), -1) {
		if c := m[1]; !slices.Contains(out, c) && c[:6] != "input." {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// needCodes are a result's need codes, in order; nil when it has no needs key.
func needCodes(ns []Need) []string {
	if ns == nil {
		return nil
	}
	out := []string{}
	for _, n := range ns {
		out = append(out, string(n.Code)+" "+n.Input)
	}
	return out
}

// file asks simulate policy on firewall-doubt.xml: from home to wan, or with
// dmz true from dmz to wan, or to the flow's to-zone when it names one.
func file(t *testing.T, dmz bool, f FlowInput) SecurityResult {
	t.Helper()
	to := cmp.Or(f.ToZone, "wan")
	f.Source, f.Destination, f.FromZone, f.ToZone = "198.18.1.68", "203.0.113.5", "home", to
	if dmz {
		f.Source, f.FromZone = "10.0.0.5", "dmz"
	}
	e, err := PolicyFile(context.Background(), Env{}, PolicyFileInput{Flow: f, Selection: Selection{File: fixture("firewall-doubt.xml")}})
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	return e.Results[0]
}

// Each row of spec 2026-10-09 §3.4 (C11 drops path.pbf-no-port): the needs a
// held-back answer lists, and that giving them changes the reason set.
func TestNeedsRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		dmz         bool
		ask, second FlowInput // second gives the needs; unused when there are none
		want        []string
	}{
		{"service without a port, udp", false, FlowInput{Protocol: "udp"}, FlowInput{Protocol: "udp", Port: "443"}, []string{"input.port port"}},
		{
			"service without a port or a protocol", false,
			FlowInput{},
			FlowInput{Port: "udp/443"},
			[]string{"input.protocol protocol", "input.port port"},
		},
		{
			"category without a URL", true,
			FlowInput{Protocol: "tcp", Port: "443", ToZone: "home"},
			FlowInput{Protocol: "tcp", Port: "443", ToZone: "home", URL: "shop.example.com"},
			[]string{"input.url url"},
		},
		// dmz-user's user doubt comes first; no input fixes it, so the URL
		// that decides the later categories is not asked for.
		{"a doubt no input fixes comes first", true, FlowInput{Protocol: "tcp", Port: "443"}, FlowInput{}, []string{}},
		{"a PAN-DB category needs nothing", true, FlowInput{Protocol: "tcp", Port: "443", URL: "other.example.com"}, FlowInput{}, []string{}},
		{"a user needs nothing", true, FlowInput{Protocol: "tcp", Port: "443", URL: "other.example.com", User: `corp\alice`}, FlowInput{}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := file(t, tc.dmz, tc.ask)
			if r.Verdict != "undecided" {
				t.Fatalf("verdict %s: %s", r.Verdict, r.Answer)
			}
			if got := needCodes(r.Needs); !slices.Equal(got, tc.want) {
				t.Fatalf("needs %v, want %v (%s)", got, tc.want, r.Answer)
			}
			for _, n := range r.Needs {
				if n.Text == "" || strings.Contains(n.Text, "--") {
					t.Errorf("need text %q", n.Text)
				}
			}
			if len(tc.want) == 0 {
				return
			}
			again := file(t, tc.dmz, tc.second)
			if slices.Equal(codes(t, r), codes(t, again)) {
				t.Errorf("the reason set did not change: %v", codes(t, r))
			}
		})
	}
}

// A decided answer has no needs key; the rule a port decides is named.
func TestNeedsOnlyHeldBack(t *testing.T) {
	t.Parallel()
	r := file(t, false, FlowInput{Protocol: "udp", Port: "443"})
	if r.Verdict == "undecided" || r.Needs != nil {
		t.Errorf("%s: %+v", r.Verdict, r.Needs)
	}
	r = file(t, false, FlowInput{Protocol: "udp"})
	if len(r.Needs) != 1 || r.Needs[0].Text != "give the destination port; it decides the service of rule block-udp-443" {
		t.Errorf("%+v", r.Needs)
	}
	// icmp never needs a port: a protocol without ports never matches the
	// custom service of block-udp-443 (spec 2026-10-16 P13), so the answer
	// decides.
	r = file(t, false, FlowInput{Protocol: "icmp"})
	if r.Verdict == "undecided" || r.Needs != nil {
		t.Errorf("icmp: %s: %+v (%s)", r.Verdict, r.Needs, r.Answer)
	}
}

// path.nat-no-port: a NAT rule that names a service needs the port, on simulate
// nat and on the routing hop that applies NAT; the port changes the reasons.
func TestNeedsNATPort(t *testing.T) {
	t.Parallel()
	ask := func(port string) NATResult {
		e, err := NAT(context.Background(), natEnv(t), NATInput{
			Flow:   FlowInput{Source: "198.18.1.10", Destination: "198.18.250.10", Protocol: "tcp", Port: port},
			Device: "fw01", Router: "default", FromZone: "transport",
		})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	r := ask("")
	if got := needCodes(r.Needs); !slices.Equal(got, []string{"input.port port"}) ||
		r.Needs[0].Text != "give the destination port; it decides the service of NAT rule t-dnat-port" {
		t.Errorf("nat needs %+v", r.Needs)
	}
	if again := ask("8443"); slices.Equal(codes(t, r), codes(t, again)) || again.Needs != nil {
		t.Errorf("nat with a port: %v, needs %+v", codes(t, again), again.Needs)
	}

	route := func(port string) RoutingResult {
		e, err := Routing(context.Background(), natEnv(t), RoutingInput{
			Source: "198.18.1.10", Destination: "198.18.250.10", Port: port, Device: "fw01", Router: "default",
		})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	rr := route("")
	if got := needCodes(rr.Needs); !slices.Equal(got, []string{"input.port port"}) {
		t.Errorf("routing needs %+v", rr.Needs)
	}
	if again := route("8443"); slices.Equal(codes(t, rr), codes(t, again)) {
		t.Errorf("routing with a port: %v", codes(t, again))
	}

	// Path policy reads the hop's NAT doubt as routing does: the path is
	// undecided, and the port is what decides it (C3).
	path := func(port string) PathResult {
		e, err := Policy(context.Background(), natEnv(t), PolicyInput{
			Flow:   FlowInput{Source: "198.18.1.10", Destination: "198.18.250.10", Protocol: "tcp", Port: port},
			Device: "fw01", Router: "default",
		})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	pr := path("")
	if pr.Verdict != "undecided" || !strings.Contains(pr.Answer, "nat rule t-dnat-port may match instead") ||
		!slices.Equal(needCodes(pr.Needs), needCodes(rr.Needs)) ||
		pr.Needs[0].Text != "give the destination port; it decides the service of NAT rule t-dnat-port" {
		t.Errorf("path: %s, needs %+v", pr.Answer, pr.Needs)
	}
	if again := path("8443"); slices.Contains(codes(t, again), "path.nat-undermatch") {
		t.Errorf("path with a port: %s, %v", again.Answer, codes(t, again))
	}
}

// path.nat-no-protocol: a port the NAT rule's service holds decides nothing
// without the protocol, so the protocol is what a second call gives. A
// protocol given by number decides as its name does.
func TestNeedsNATProtocol(t *testing.T) {
	t.Parallel()
	ask := func(proto string) NATResult {
		e, err := NAT(context.Background(), natEnv(t), NATInput{
			Flow:   FlowInput{Source: "198.18.1.10", Destination: "198.18.250.10", Protocol: proto, Port: "8443"},
			Device: "fw01", Router: "default", FromZone: "transport",
		})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	r := ask("")
	if got := needCodes(r.Needs); len(r.Doubts) != 1 || r.Doubts[0].Rule != "t-dnat-port" || !slices.Equal(got, []string{"input.protocol protocol"}) ||
		r.Needs[0].Text != "give the protocol: tcp, udp or sctp; it decides the service of NAT rule t-dnat-port" {
		t.Errorf("no protocol: %s, needs %+v", r.Answer, r.Needs)
	}
	for _, proto := range []string{"tcp", "6"} {
		if again := ask(proto); again.Rule == nil || again.Rule.Name != "t-dnat-port" || again.Needs != nil {
			t.Errorf("%s: %s, needs %+v", proto, again.Answer, again.Needs)
		}
	}
	if again := ask("udp"); again.Rule != nil && again.Rule.Name == "t-dnat-port" {
		t.Errorf("udp: %s", again.Answer)
	}
}

// A PBF rule that names a service and may take the lab flow on fw02 leaves the
// path undecided; without a port, the port is what decides whether it matches.
// tcp/22 takes it for sure, and tcp/443 passes it by.
func TestNeedsPBFPort(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.fetch(pathlab.FW01, pathlab.ConfigFile(pathlab.FW01))
	pbf := `</zone>
          <service><entry name="svc-ssh"><protocol><tcp><port>22</port></tcp></protocol></entry></service>
          <rulebase><pbf><rules><entry name="ssh-fwd">
            <from><zone><member>home</member></zone></from>
            <source><member>any</member></source><destination><member>any</member></destination>
            <service><member>svc-ssh</member></service>
            <action><forward><egress-interface>vlan.32</egress-interface></forward></action>
          </entry></rules></pbf></rulebase>`
	cfg := pathlab.Read(t, pathlab.ConfigFile(pathlab.FW02))
	if bytes.Count(cfg, []byte("</zone>")) != 1 {
		t.Fatal("fw02's configuration has not one zone list")
	}
	l.write(store.Meta{Device: pathlab.FW02, Host: "fw02.example.test"}, bytes.Replace(cfg, []byte("</zone>"), []byte(pbf), 1))
	env := l.env()
	ask := func(port string) PathResult {
		e, err := Policy(context.Background(), env, PolicyInput{
			Flow: FlowInput{Source: pathlab.Source, Destination: pathlab.Destination, Protocol: "tcp", Port: port},
		})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	r := ask("")
	if r.Verdict != "undecided" || !slices.Equal(needCodes(r.Needs), []string{"input.port port"}) || !slices.Contains(codes(t, r), "doubt.service-no-port") {
		t.Errorf("no port: %s, needs %+v, codes %v", r.Answer, r.Needs, codes(t, r))
	}
	if again := ask("22"); again.Verdict != "undecided" || slices.Contains(codes(t, again), "doubt.service-no-port") || len(again.Needs) != 0 {
		t.Errorf("tcp/22: %s, needs %+v, codes %v", again.Answer, again.Needs, codes(t, again))
	}
	if again := ask("443"); again.Verdict != "denied" || again.Needs != nil {
		t.Errorf("tcp/443: %s, needs %+v", again.Answer, again.Needs)
	}
	// simulate routing asks for the port too: it decides the PBF rule.
	route := func(port string) RoutingResult {
		e, err := Routing(context.Background(), env, RoutingInput{Source: pathlab.Source, Destination: pathlab.Destination, Protocol: "tcp", Port: port})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	if r := route(""); !slices.Equal(needCodes(r.Needs), []string{"input.port port"}) {
		t.Errorf("routing, no port: %s, needs %+v", r.Answer, r.Needs)
	}
	if r := route("443"); slices.Contains(needCodes(r.Needs), "input.port port") {
		t.Errorf("routing, tcp/443: %s, needs %+v", r.Answer, r.Needs)
	}
}

// Derived zones that leave rule-type or the default rule open need both zones:
// from inside to an address no interface holds, intra-inside and inter-inside
// are in doubt and the default rule depends on the zones. Given zones decide.
func TestNeedsZones(t *testing.T) {
	t.Parallel()
	ask := func(from, to string) SecurityResult {
		e, err := PolicyFile(context.Background(), Env{}, PolicyFileInput{
			Flow:      FlowInput{Source: "10.1.0.5", Destination: "8.8.8.8", Protocol: "tcp", Port: "443", FromZone: from, ToZone: to},
			Selection: Selection{File: fixture("firewall-ruletype.xml"), Vsys: []string{"vsys1"}},
		})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	r := ask("", "")
	if got := needCodes(r.Needs); r.Verdict != "undecided" || !slices.Equal(got, []string{"input.from-zone from_zone", "input.to-zone to_zone"}) ||
		r.Needs[0].Text != "give the source zone, with to_zone; it decides the rule-type of rules intra-inside, inter-inside" {
		t.Errorf("derived: %s, needs %+v", r.Answer, r.Needs)
	}
	if again := ask("inside", "out"); again.Verdict == "undecided" || again.Needs != nil {
		t.Errorf("given: %s, needs %+v", again.Answer, again.Needs)
	}
	// Without a rule, the default rule alone names no rule.
	ns := needsOf(simulate.Flow{}, []cause{{code: "default.zones-unknown"}})
	if len(ns) != 2 || ns[1].Text != "give the destination zone, with from_zone" {
		t.Errorf("default rule: %+v", ns)
	}
	if ns := needsOf(simulate.Flow{FromZone: "inside", ToZone: "out"}, []cause{{code: "zone.derived"}}); len(ns) != 0 {
		t.Errorf("given zones: %+v", ns)
	}
}

// securityCauses walks the doubts in rule order before the first certain
// match, and stops at the first doubt no input can fix.
func TestSecurityCausesStopAtAnUnfixableDoubt(t *testing.T) {
	t.Parallel()
	noPort := reason.New("doubt.service-no-port", "service not evaluated without a tcp, udp or sctp port (svc)")
	user := reason.New("doubt.not-evaluated.user", "user not evaluated (alice)")
	tcp := simulate.Flow{Protocol: "tcp"}
	if cs, blocked := securityCauses(tcp, nil); cs != nil || blocked {
		t.Errorf("nil verdict: %v %v", cs, blocked)
	}
	v := &securitypolicy.Verdict{Rule: &resolve.Rule{Position: 9}, Doubts: []securitypolicy.Doubt{
		{Position: 5, Rule: "late", Reasons: simulate.Reasons{user}},
		{Position: 2, Rule: "early", Reasons: simulate.Reasons{noPort}},
		{Position: 10, Rule: "after", Reasons: simulate.Reasons{user}},
	}}
	cs, blocked := securityCauses(tcp, v)
	if len(cs) != 1 || cs[0].rule.name != "early" || !blocked {
		t.Errorf("causes %+v, blocked %v", cs, blocked)
	}
	// A doubt with a fixable and an unfixable reason keeps its fixable cause:
	// the port can rule the rule out. The walk goes on past it.
	v.Doubts = []securitypolicy.Doubt{
		{Position: 2, Rule: "both", Reasons: simulate.Reasons{noPort, user}},
		{Position: 3, Rule: "next", Reasons: simulate.Reasons{noPort}},
	}
	cs, blocked = securityCauses(tcp, v)
	if len(cs) != 2 || cs[0].rule.name != "both" || cs[1].rule.name != "next" || blocked {
		t.Errorf("mixed: %+v %v", cs, blocked)
	}
	if ns := needsOf(tcp, cs); len(ns) != 1 || ns[0].Code != "input.port" {
		t.Errorf("mixed needs: %+v", ns)
	}
	v.Doubts = []securitypolicy.Doubt{{Position: 10, Rule: "after", Reasons: simulate.Reasons{user}}}
	if cs, blocked := securityCauses(tcp, v); len(cs) != 0 || blocked {
		t.Errorf("after the match: %+v %v", cs, blocked)
	}
}

// NAT doubts are cut like security doubts: in rule order, up to the first
// doubt no input can fix. A blocked walk drops the fidelity's causes.
func TestNATCausesStopAtAnUnfixableDoubt(t *testing.T) {
	t.Parallel()
	noPort := reason.New("path.nat-no-port", "service svc not known without a port: give the destination port")
	zone := reason.New("zone.missing", "the ingress zone is unknown")
	tcp := simulate.Flow{Protocol: "tcp"}
	ds := []nat.Doubt{
		{Rule: "early", Reasons: simulate.Reasons{noPort}},
		{Rule: "zone", Reasons: simulate.Reasons{zone}},
		{Rule: "late", Reasons: simulate.Reasons{noPort}},
	}
	cs, blocked := natCauses(tcp, ds)
	if len(cs) != 1 || cs[0].rule != (ruleName{"NAT rule", "early"}) || !blocked {
		t.Errorf("causes %+v, blocked %v", cs, blocked)
	}
	ds[1].Reasons = simulate.Reasons{zone, noPort}
	if cs, blocked := natCauses(tcp, ds); len(cs) != 3 || blocked {
		t.Errorf("mixed: %+v %v", cs, blocked)
	}
	// The fidelity's port cause goes with a blocked walk.
	under := simulate.UnderMatch(reason.New("doubt.service-no-port", "service not evaluated without a tcp, udp or sctp port (svc)"))
	if ns := natNeeds(tcp, nat.Result{MatchResult: nat.MatchResult{Doubts: []nat.Doubt{{Rule: "zone", Reasons: simulate.Reasons{zone}}}}}, under); len(ns) != 0 {
		t.Errorf("blocked needs: %+v", ns)
	}
	if ns := natNeeds(tcp, nat.Result{}, under); len(ns) != 1 || ns[0].Code != "input.port" {
		t.Errorf("unblocked needs: %+v", ns)
	}
}
