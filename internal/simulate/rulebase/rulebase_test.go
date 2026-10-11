package rulebase

import (
	"errors"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func routingVsys(t *testing.T) Vsys {
	t.Helper()
	cfg, _, err := config.Load("../../../testdata/config/firewall-routing.xml")
	if err != nil {
		t.Fatal(err)
	}
	v, ok := Load(func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }, "fw", "vsys1")
	if !ok {
		t.Fatal("vsys1")
	}
	return v
}

func TestLoad(t *testing.T) {
	t.Parallel()
	load := func(string, string) (simulate.Target, error) { return simulate.Target{}, errors.New("none") }
	if _, ok := Load(load, "fw", "vsys1"); ok {
		t.Error("a failing loader")
	}
	if _, ok := Load(nil, "fw", "vsys1"); ok {
		t.Error("no loader")
	}
	cfg, _, _ := config.Load("../../../testdata/config/firewall-routing.xml")
	ok := func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }
	if _, found := Load(ok, "fw", "vsys9"); found {
		t.Error("a vsys the configuration lacks")
	}
	if _, found := Load(ok, "fw", ""); found {
		t.Error("an unknown vsys")
	}
}

func pbf(t *testing.T, v Vsys, src, dst string, in simulate.Port) PBFMatch {
	t.Helper()
	return v.PBF(ip(src), ip(dst), "", 0, in)
}

func TestPBF(t *testing.T) {
	t.Parallel()
	v := routingVsys(t)
	branch := simulate.Port{Zone: "branch-vpn", Interface: "ethernet1/3"}
	if m := pbf(t, v, "10.20.5.5", "10.1.10.100", branch); !m.Found || m.Rule.Name != "branch-to-zscaler" ||
		m.Note != reason.New("path.pbf", "pbf rule branch-to-zscaler may forward this packet to tunnel.1 via 198.19.255.254") {
		t.Errorf("forward: %+v", m)
	}
	// By interface, destination negated: dc01 is excluded.
	if m := pbf(t, v, "10.99.0.5", "10.1.10.50", branch); m.Note != reason.New("path.pbf", "pbf rule lab-by-interface may drop this packet") {
		t.Errorf("discard: %q", m.Note)
	}
	if m := pbf(t, v, "10.99.0.5", "10.1.10.100", branch); m.Found {
		t.Error("the negated destination")
	}
	dc := simulate.Port{Zone: "datacenter", Interface: "ethernet1/2"}
	if m := pbf(t, v, "10.1.1.1", "10.30.0.9", dc); !m.Found || m.Note != (reason.Reason{}) || m.Rule.Name != "keep-routing" {
		t.Errorf("no-pbf: %+v", m)
	}
	sdwan := simulate.Port{Zone: "sdwan", Interface: "ethernet1/4"}
	if m := pbf(t, v, "10.30.0.7", "10.1.1.1", sdwan); m.Note != reason.New("path.pbf", "pbf rule sdwan-to-vsys2 may forward this packet to vsys2") {
		t.Errorf("to vsys: %q", m.Note)
	}
}

// A rulebase that cannot be indexed yields no rule and says so, never a silent
// "no rule": that would be a wrong answer that looks complete.
func TestAnUnbuildableIndexIsUnresolved(t *testing.T) {
	t.Parallel()
	bad := routingVsys(t)
	bad.Scope = config.Scope{Sort: config.ScopeVsys, Name: "vsys9"}
	bad.Indexes = index.NewSet(bad.Config).Provider(bad.Scope)
	noNegation := func(int) (bool, bool) { return false, false }
	s, d, un := bad.Sides(resolve.NAT, ip("1.1.1.1"), ip("1.1.1.1"), noNegation)
	if !s.IsEmpty() || !d.IsEmpty() || s == d || len(un) != 1 || !strings.Contains(un[0].Reason, "not checked") {
		t.Errorf("Sides: %v %v %v", s.ToArray(), d.ToArray(), un)
	}
	if m := bad.PBF(ip("1.1.1.1"), ip("1.1.1.1"), "tcp", 443, simulate.Port{}); m.Found || len(m.Unresolved) != 1 {
		t.Errorf("PBF: %+v", m)
	}
}

// A target without an index provider is a loader's mistake. It is reported the
// same way; the simulation never builds an index of its own.
func TestNoIndexProviderIsUnresolved(t *testing.T) {
	t.Parallel()
	v := routingVsys(t)
	v.Indexes = nil
	_, _, un := v.Sides(resolve.PBF, ip("1.1.1.1"), ip("1.1.1.1"), func(int) (bool, bool) { return false, false })
	if len(un) != 1 || un[0].Code != "gap.load-failed" || !strings.Contains(un[0].Reason, "no index provider") {
		t.Errorf("Sides: %v", un)
	}
}

// A provider of another vsys's indexes is a loader's mistake too: its rules are
// not this vsys's.
func TestAProviderOfAnotherVsysIsUnresolved(t *testing.T) {
	t.Parallel()
	v := routingVsys(t)
	v.Indexes = index.NewSet(v.Config).Provider(config.Scope{Sort: config.ScopeShared})
	_, _, un := v.Sides(resolve.Security, ip("1.1.1.1"), ip("1.1.1.1"), func(int) (bool, bool) { return false, false })
	if len(un) != 1 || !strings.Contains(un[0].Reason, "the index provider gives shared, not vsys:vsys1") {
		t.Errorf("Sides: %v", un)
	}
}

func TestSidesAndHolds(t *testing.T) {
	t.Parallel()
	v := routingVsys(t)
	src, dst, un := v.Sides(resolve.NAT, netip.Addr{}, ip("198.51.100.10"), func(int) (bool, bool) { return false, false })
	if len(un) != 0 || src.GetCardinality() != 4 || !dst.Contains(1) {
		t.Errorf("src %v, dst %v, unresolved %v", src.ToArray(), dst.ToArray(), un)
	}
	addrs := v.Addresses()
	if addrs["dc01"] != "10.1.10.100" {
		t.Errorf("Addresses()[dc01] = %q", addrs["dc01"])
	}
	if !addrs.Holds("dc01", ip("10.1.10.100")) || addrs.Holds("dc01", ip("10.1.10.101")) ||
		!addrs.Holds("10.0.0.0/8", ip("10.1.1.1")) || addrs.Holds("no-such-object", ip("10.1.1.1")) {
		t.Error("Holds")
	}
}

func TestFromFits(t *testing.T) {
	t.Parallel()
	if !FromFits(resolve.PBFRule{From: []string{"any"}}, simulate.Port{Zone: "x"}) ||
		!FromFits(resolve.PBFRule{FromKind: "interface", From: []string{"e1"}}, simulate.Port{}) ||
		FromFits(resolve.PBFRule{FromKind: "zone", From: []string{"a"}}, simulate.Port{Zone: "b"}) {
		t.Error("FromFits")
	}
}

func TestCertainty(t *testing.T) {
	t.Parallel()
	if f := Certainty(resolve.NAT, nil); f.String() != simulate.Exact.String() {
		t.Errorf("no unresolved value: %s", f)
	}
	f := Certainty(resolve.PBF, []index.Unresolved{{Value: "x", Reason: "y"}})
	if !strings.Contains(f.String(), "undermatch") || !strings.Contains(f.String(), "pbf rule") {
		t.Errorf("an unresolved value: %s", f)
	}
}

func TestWithoutGap(t *testing.T) {
	t.Parallel()
	// The gap is known by its code, not by its text: another entry with the same
	// text stays.
	un := []index.Unresolved{
		index.NewUnresolved("a", "", reason.New("gap.version", "gap")),
		index.NewUnresolved("b", "", reason.New("gap.object-unresolved", "gap")),
	}
	if got := withoutGap(un); len(got) != 1 || got[0].Value != "b" {
		t.Errorf("with a gap: %v", got)
	}
	if got := withoutGap(un[1:]); len(got) != 1 {
		t.Errorf("without a gap: %v", got)
	}
}

// withIndexes is a target over a vsys of cfg with its index provider, as a
// loader gives it.
func withIndexes(cfg *config.Config, vsys string) simulate.Target {
	sc := config.Scope{Sort: config.ScopeVsys, Name: vsys}
	return simulate.Target{Config: cfg, Indexes: index.NewSet(cfg).Provider(sc)}
}

func pbfServiceVsys(t *testing.T) Vsys {
	t.Helper()
	cfg, _, err := config.Load("../../../testdata/config/firewall-pbf-service.xml")
	if err != nil {
		t.Fatal(err)
	}
	v, ok := Load(func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }, "fw", "vsys1")
	if !ok {
		t.Fatal("vsys1")
	}
	return v
}

// PBF matches the service. As observed on fw02, PAN-OS 12.2.3 (L3): a no-pbf rule
// with service tcp/22 above a forward rule with service any takes tcp/22, and
// tcp/443 and udp/22 go on to the forward rule. A flow without a port cannot
// decide the no-pbf rule, so the scan goes past it.
func TestPBFMatchesTheService(t *testing.T) {
	t.Parallel()
	v := pbfServiceVsys(t)
	home := simulate.Port{Zone: "home"}
	for _, tc := range []struct {
		proto  string
		port   uint16
		rule   string
		sure   bool
		passed string
	}{
		{"tcp", 443, "home-out", true, ""},
		{"tcp", 22, "ssh-no-pbf", true, ""},
		{"udp", 22, "home-out", true, ""},
		{"TCP", 22, "ssh-no-pbf", true, ""},
		{"tcp", 0, "home-out", true, "no-pbf rule ssh-no-pbf may match (the rule names a service, and the flow has no port)"},
		{"icmp", 0, "home-out", true, "no-pbf rule ssh-no-pbf may match (the rule names a service, and the flow has no port)"},
	} {
		m := v.PBF(ip("10.88.3.5"), ip("10.88.9.5"), tc.proto, tc.port, home)
		var passed []string
		for _, p := range m.Passed {
			passed = append(passed, p.String())
		}
		if !m.Found || m.Rule.Name != tc.rule || strings.Contains(m.Note.Text, "if it matches") == tc.sure || strings.Join(passed, "; ") != tc.passed || len(m.Unresolved) != 0 {
			t.Errorf("%s/%d: %+v", tc.proto, tc.port, m)
		}
	}
	if m := v.PBF(ip("10.88.3.5"), ip("10.88.9.5"), "tcp", 22, home); m.Note != (reason.Reason{}) {
		t.Errorf("a no-pbf rule has no note: %q", m.Note)
	}
	if m := v.PBF(ip("10.88.3.5"), ip("10.88.9.5"), "tcp", 443, home); m.Note != reason.New("path.pbf",
		"pbf rule home-out may forward this packet to ethernet1/4 via 198.18.0.1") {
		t.Errorf("forward note: %q", m.Note)
	}
}

// A no-pbf rule that names an application only may match, so it does not end the
// scan; the next rule takes the flow and the passed rule is named.
func TestPBFGoesPastANoPBFRuleThatMayMatch(t *testing.T) {
	t.Parallel()
	v := pbfServiceVsys(t)
	m := v.PBF(ip("10.88.4.5"), ip("10.88.9.5"), "tcp", 22, simulate.Port{Zone: "lab"})
	if !m.Found || m.Rule.Name != "lab-out" || strings.Contains(m.Note.Text, "if it matches") || len(m.Passed) != 1 || m.Passed[0].Rule != "lab-app-no-pbf" ||
		m.Passed[0].Doubts[0].Code != "doubt.application" {
		t.Fatalf("%+v", m)
	}
	if got := PassedText(m.Passed); got != "; no-pbf rule lab-app-no-pbf may match (the rule names an application, which is not evaluated)" {
		t.Errorf("PassedText = %q", got)
	}
	if PassedText(nil) != "" {
		t.Error("no passed rule, no text")
	}
}

// A forward or discard rule that only may match still ends the scan; its note
// says why it only may.
func TestPBFADiscardThatMayMatchEndsTheScan(t *testing.T) {
	t.Parallel()
	v := pbfServiceVsys(t)
	dmz := simulate.Port{Zone: "dmz"}
	for _, port := range []uint16{443, 8443} {
		m := v.PBF(ip("10.88.5.5"), ip("10.88.9.5"), "tcp", port, dmz)
		if !m.Found || m.Rule.Name != "dmz-https" || m.Note != reason.New("path.pbf", "pbf rule dmz-https may drop this packet, "+
			"if it matches: the rule names a service the configuration does not define, such as a predefined one; "+
			"the snapshot holds no predefined services; a fetch with this release stores them when the device returns them") {
			t.Errorf("%d: %+v", port, m)
		}
	}
}

// The service judgement on its own: absent, any, no port, application-default,
// undefined, defined and not carrying the flow.
func TestPBFServiceJudge(t *testing.T) {
	t.Parallel()
	v := pbfServiceVsys(t)
	rules := v.Target.PBFRules()
	m := v.pbfServices(rules, "tcp", 443)
	for _, tc := range []struct {
		svc  []string
		fits bool
		code reason.Code
	}{
		{nil, true, "doubt.service-absent"},
		{[]string{"any"}, true, ""},
		{[]string{"application-default"}, true, "doubt.service-application-default"},
		{[]string{"service-https"}, true, "doubt.service-predefined"},
		{[]string{"svc-ssh"}, false, ""},
	} {
		why, fits := m.judge(len(rules), tc.svc) // a position no rule has
		code := reason.Code("")
		if len(why) > 0 {
			code = why[0].Code
		}
		if fits != tc.fits || code != tc.code {
			t.Errorf("%v: fits %v %v", tc.svc, fits, why)
		}
	}
	if why, fits := v.pbfServices(rules, "", 0).judge(0, []string{"svc-ssh"}); !fits || why[0].Code != "doubt.service-no-port" {
		t.Errorf("no port: %v %v", why, fits)
	}
	if got := v.pbfServices(nil, "tcp", 443); got.term != "" {
		t.Errorf("no rules: %+v", got)
	}
}

func TestServiceTerm(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		proto string
		port  uint16
		want  string
	}{{"tcp", 443, "tcp/443"}, {"UDP", 53, "udp/53"}, {"sctp", 9, "sctp/9"}, {"tcp", 0, ""}, {"icmp", 8, ""}, {"6", 443, "tcp/443"}, {"17", 53, "udp/53"}, {"132", 9, "sctp/9"}, {"1", 8, ""}} {
		got, ok := ServiceTerm(tc.proto, tc.port)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s/%d = %q %v", tc.proto, tc.port, got, ok)
		}
	}
}

// A PBF check does not evaluate the application or the source user: a rule that
// names either only may match.
func TestPBFNotEvaluated(t *testing.T) {
	t.Parallel()
	fields := map[string][]string{"application": {"any"}, "source-user": {`corp\ops`}}
	if got := notEvaluated(fields); len(got) != 1 || got[0].Code != "doubt.not-evaluated.user" {
		t.Errorf("user: %v", got)
	}
	fields["source-user"] = []string{"any"}
	if got := notEvaluated(fields); got != nil {
		t.Errorf("any: %v", got)
	}
}

// R1: a PBF rule field the configuration leaves out holds its schema default. The
// 11.2.0 digest gives "any" for the service, the application and the source user.
func TestPBFDefaultsComeFromTheSchema(t *testing.T) {
	t.Parallel()
	v := pbfServiceVsys(t)
	want := map[string]string{"service": "any", "application": "any", "source-user": "any"}
	if got := pbfDefaults(v.Config); !maps.Equal(got, want) {
		t.Errorf("defaults = %v", got)
	}
	got := withDefaults(map[string][]string{"service": {"svc-ssh"}}, map[string]string{"service": "any", "application": "any"})
	if strings.Join(got["service"], ",") != "svc-ssh" || strings.Join(got["application"], ",") != "any" || got["source-user"] != nil {
		t.Errorf("withDefaults = %v", got)
	}
}

// A no-pbf rule without service, application or source user holds their default,
// any, so it matches for sure and ends the scan.
func TestPBFNoPBFWithoutServiceEndsTheScan(t *testing.T) {
	t.Parallel()
	v := pbfServiceVsys(t)
	for _, port := range []uint16{443, 0} {
		m := v.PBF(ip("10.88.6.5"), ip("10.88.9.5"), "tcp", port, simulate.Port{Zone: "bare"})
		if !m.Found || m.Rule.Name != "bare-no-pbf" || m.Note != (reason.Reason{}) || len(m.Passed) != 0 {
			t.Errorf("tcp/%d: %+v", port, m)
		}
	}
}

func TestUndecidable(t *testing.T) {
	t.Parallel()
	defined := map[string]bool{"svc-ssh": true}
	for _, tc := range []struct {
		values []string
		want   bool
	}{
		{[]string{"any"}, false},
		{[]string{"any", "svc-ssh"}, false},
		{[]string{"svc-ssh", "service-https"}, true},
		{[]string{"application-default"}, true},
		{nil, false},
	} {
		if got := Undecidable(tc.values, defined, "application-default"); got != tc.want {
			t.Errorf("%v = %v", tc.values, got)
		}
	}
}

// PBF sees the predefined services too (L4): dmz-https takes tcp/443 for sure,
// and tcp/8443 goes on to dmz-out.
func TestPBFMatchesAPredefinedService(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/predefined/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	v, ok := Load(func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }, "fw", "vsys1")
	if !ok {
		t.Fatal("vsys1")
	}
	dmz := simulate.Port{Zone: "dmz"}
	if m := v.PBF(ip("10.88.5.5"), ip("10.88.9.5"), "tcp", 443, dmz); !m.Found || m.Rule.Name != "dmz-https" || strings.Contains(m.Note.Text, "if it matches") {
		t.Errorf("tcp/443: %+v", m)
	}
	if m := v.PBF(ip("10.88.5.5"), ip("10.88.9.5"), "tcp", 8443, dmz); !m.Found || m.Rule.Name != "dmz-out" || strings.Contains(m.Note.Text, "if it matches") {
		t.Errorf("tcp/8443: %+v", m)
	}
}

// The doubt of an undefined service says to fetch again only when the
// configuration came without the device's predefined services.
func TestUndefinedService(t *testing.T) {
	t.Parallel()
	with, _, err := config.Load("../../../testdata/predefined/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	without, _, err := config.Load("../../../testdata/config/firewall-pbf-service.xml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		cfg  *config.Config
		want string
	}{
		{with, "x"},
		{without, "x; the snapshot holds no predefined services; a fetch with this release stores them when the device returns them"},
		{nil, "x; the snapshot holds no predefined services; a fetch with this release stores them when the device returns them"},
	} {
		if r := UndefinedService(tc.cfg, "x"); r.Code != "doubt.service-predefined" || r.Text != tc.want {
			t.Errorf("%+v, want %q", r, tc.want)
		}
	}
}

// A given zone the scope does not define is a refusal in the command line's
// words, the tool's and plain words, listing the scope's zones; defined or
// empty zones are none (C15). The from zone is checked first.
func TestUndefinedZones(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-ruletype.xml")
	if err != nil {
		t.Fatal(err)
	}
	vsys1 := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	if r := UndefinedZones(cfg, vsys1, "inside", "out"); r != nil {
		t.Errorf("defined: %+v", r)
	}
	if r := UndefinedZones(cfg, vsys1, "", ""); r != nil {
		t.Errorf("none given: %+v", r)
	}
	r := UndefinedZones(cfg, vsys1, "inside", "nowhere")
	if r == nil || r.Choice.Question != "--to-zone nowhere is not a zone of vsys1 (its zones: dmz, inside, out)" ||
		r.Choice.ToolText != "to_zone nowhere is not a zone of vsys1 (its zones: dmz, inside, out)" ||
		r.Text != "the to zone nowhere is not a zone of vsys1 (its zones: dmz, inside, out)" || r.Choice.Kind != simulate.ChoiceZone {
		t.Errorf("undefined: %+v", r)
	}
	if r := UndefinedZones(cfg, vsys1, "here", "there"); r == nil || r.Text != "the from zone here is not a zone of vsys1 (its zones: dmz, inside, out)" {
		t.Errorf("from first: %+v", r)
	}
	r = UndefinedZones(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys9"}, "inside", "")
	if r == nil || r.Choice.Question != "--from-zone inside is not a zone of vsys9 (it defines no zone)" {
		t.Errorf("no zones: %+v", r)
	}
}

// serviceGroupVsys loads firewall-service-group.xml, with the predefined
// services of testdata/predefined next to it when predefined is set.
func serviceGroupVsys(t *testing.T, predefined bool) Vsys {
	t.Helper()
	path := "../../../testdata/config/firewall-service-group.xml"
	if predefined {
		dir := t.TempDir()
		for src, dst := range map[string]string{path: "config.xml", "../../../testdata/predefined/predefined.xml": config.PredefinedFile} {
			b, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, dst), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		path = filepath.Join(dir, "config.xml")
	}
	cfg, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := Load(func(_, vsys string) (simulate.Target, error) { return withIndexes(cfg, vsys), nil }, "fw", "vsys1")
	if !ok {
		t.Fatal("vsys1")
	}
	return v
}

// A group counts as defined only when every member does, through nested
// groups. A member on a cycle adds nothing, so a group that holds only a
// cycle, or nothing, is not defined. web holds service-https, which a
// snapshot without the predefined services does not define.
func TestDefinedCountsAGroupWhenEveryMemberIsDefined(t *testing.T) {
	t.Parallel()
	for _, predefined := range []bool{false, true} {
		v := serviceGroupVsys(t, predefined)
		got := Defined(v.Config, v.Scope, resolve.PBF, "service")
		want := map[string]bool{
			"svc-8443": true, "svc-ssh": true, "inner-ssh": true, "ssh-set": true, "loop-a": true, "loop-b": true,
			"web": predefined, "inner-web": predefined, "nested": predefined, "service-https": predefined,
			"ring-a": false, "ring-b": false, "empty": false,
		}
		for name, w := range want {
			if got[name] != w {
				t.Errorf("predefined %v: %s defined %v, want %v", predefined, name, got[name], w)
			}
		}
	}
}

// A PBF rule naming a group with an undefined member only may match a flow
// the defined members miss; a flow a defined member holds decides it. With
// the predefined services, tcp/443 decides it too.
func TestPBFAGroupWithAnUndefinedMemberMayMatch(t *testing.T) {
	t.Parallel()
	dmz := simulate.Port{Zone: "dmz"}
	for _, tc := range []struct {
		predefined bool
		port       uint16
		note       string
	}{
		{false, 443, "pbf rule web-discard may drop this packet, if it matches: the rule names a service the configuration does not define, " +
			"such as a predefined one; the snapshot holds no predefined services; a fetch with this release stores them when the device returns them"},
		{false, 8443, "pbf rule web-discard may drop this packet"},
		{true, 443, "pbf rule web-discard may drop this packet"},
		{true, 8443, "pbf rule web-discard may drop this packet"},
	} {
		m := serviceGroupVsys(t, tc.predefined).PBF(ip("10.88.5.5"), ip("10.88.9.5"), "tcp", tc.port, dmz)
		if !m.Found || m.Rule.Name != "web-discard" || m.Note != reason.New("path.pbf", tc.note) {
			t.Errorf("predefined %v, tcp/%d: %+v", tc.predefined, tc.port, m)
		}
	}
	// Without the predefined services, service-https may hold any port.
	if m := serviceGroupVsys(t, false).PBF(ip("10.88.5.5"), ip("10.88.9.5"), "tcp", 22, dmz); !m.Found || !strings.Contains(m.Note.Text, "if it matches") {
		t.Errorf("tcp/22 without the predefined services: %+v", m)
	}
	if m := serviceGroupVsys(t, true).PBF(ip("10.88.5.5"), ip("10.88.9.5"), "tcp", 22, dmz); m.Found {
		t.Errorf("tcp/22, which no member holds: %+v", m)
	}
}
