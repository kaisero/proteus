package securitypolicy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/schema"
	"github.com/okaiser/proteus/internal/simulate"
)

// R1, R8: every child of a security rule entry in the schema is in exactly one
// class, and every classified name is such a child. A schema that gains a field
// fails here until the field is classified.
func TestRuleFieldsCoverTheSchema(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../../testdata/config/firewall-doubt.xml")
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.Digest()
	for _, seg := range []string{"devices", "entry", "vsys", "entry", "rulebase", "security", "rules", "entry"} {
		n = n.Child(seg)
	}
	if n == nil {
		t.Fatal("the digest has no security rule entry")
	}
	var children []string
	for _, c := range n.Children {
		children = append(children, c.Name)
	}
	classes := map[string]int{}
	for _, f := range ruleFields {
		classes[f.name]++
		if f.class < evaluated || f.class > notMatching {
			t.Errorf("%s has no class", f.name)
		}
		if !slices.Contains(children, f.name) {
			t.Errorf("%s is classified but is not a child of the security rule entry", f.name)
		}
	}
	for _, c := range children {
		switch classes[c] {
		case 0:
			t.Errorf("the schema's %s is in no class", c)
		case 1:
		default:
			t.Errorf("the schema's %s is in %d classes", c, classes[c])
		}
	}
	declared := false
	for _, h := range schema.HandModelled() {
		declared = declared || h.Path == "/config/devices/entry/vsys/entry/rulebase/security/rules/entry" && h.Owner == "internal/simulate/securitypolicy"
	}
	if !declared {
		t.Error("the classification is not registered in schema.HandModelled")
	}
}

func doubtList(v Verdict) string {
	var out []string
	for _, d := range v.Doubts {
		out = append(out, fmt.Sprintf("%d %s: %s", d.Position, d.Rule, d.Text()))
	}
	return strings.Join(out, "\n")
}

// doubtCodeList lists each doubt's codes: "3 doubt.application".
func doubtCodeList(v Verdict) []string {
	var out []string
	for _, d := range v.Doubts {
		for _, r := range d.Reasons {
			out = append(out, fmt.Sprintf("%d %s", d.Position, r.Code))
		}
	}
	return out
}

// Each candidate's doubts, in rule order: a field no stage evaluates, set to
// something other than any, is a doubt; any, absent and non-matching fields are not.
func TestDoubts(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-doubt.xml", false)
	flow := func(port uint16, proto, url string) simulate.Flow {
		return simulate.Flow{
			Source: ep("10.0.0.5"), Destination: ep("203.0.113.5"), FromZone: "dmz", ToZone: "wan",
			Protocol: proto, DestPort: port, URL: url,
		}
	}
	for _, c := range []struct {
		name string
		flow simulate.Flow
		want []string
	}{
		{"port, no URL", flow(443, "tcp", ""), []string{
			"3 app-one: service application-default",
			"3 app-one: application not evaluated (dropbox)",
			"4 app-two: service application-default",
			"4 app-two: application not evaluated (zoom)",
			`7 dmz-user: user not evaluated (corp\alice)`,
			"7 dmz-user: destination-hip not evaluated (hip-a)",
			"8 dmz-schedule: schedule not evaluated (work-hours)",
			"9 dmz-pandb: url category not defined in the configuration, such as a PAN-DB category (news)",
			"10 dmz-custom: url category not evaluated without a URL (my-cat)",
			"11 dmz-predefined: service predefined or not defined in the configuration (service-https); the snapshot holds no predefined services; a fetch with this release stores them when the device returns them",
			"12 dmz-no-service: service absent",
		}},
		{"port and URL", flow(443, "tcp", "shop.example.com"), []string{
			"3 app-one: service application-default",
			"3 app-one: application not evaluated (dropbox)",
			"4 app-two: service application-default",
			"4 app-two: application not evaluated (zoom)",
			`7 dmz-user: user not evaluated (corp\alice)`,
			"7 dmz-user: destination-hip not evaluated (hip-a)",
			"8 dmz-schedule: schedule not evaluated (work-hours)",
			"9 dmz-pandb: url category not defined in the configuration, such as a PAN-DB category (news)",
			"11 dmz-predefined: service predefined or not defined in the configuration (service-https); the snapshot holds no predefined services; a fetch with this release stores them when the device returns them",
			"12 dmz-no-service: service absent",
		}},
		{"no port", flow(0, "icmp", ""), []string{
			"3 app-one: service application-default",
			"3 app-one: application not evaluated (dropbox)",
			"4 app-two: service application-default",
			"4 app-two: application not evaluated (zoom)",
			`7 dmz-user: user not evaluated (corp\alice)`,
			"7 dmz-user: destination-hip not evaluated (hip-a)",
			"8 dmz-schedule: schedule not evaluated (work-hours)",
			"9 dmz-pandb: url category not defined in the configuration, such as a PAN-DB category (news)",
			"10 dmz-custom: url category not evaluated without a URL (my-cat)",
			"11 dmz-predefined: service predefined or not defined in the configuration (service-https); the snapshot holds no predefined services; a fetch with this release stores them when the device returns them",
			"12 dmz-no-service: service absent",
		}},
	} {
		_, v := run(t, e, c.flow)
		if got, want := doubtList(v), strings.Join(c.want, "\n"); got != want {
			t.Errorf("%s: doubts\n%s\nwant\n%s\ncandidates %s", c.name, got, want, ruleNames(v))
		}
	}
	// Each doubt has the code of its kind (spec §3.1, §12 C7, C8).
	codes := map[string][]string{
		"port, no URL": {
			"3 doubt.service-application-default", "3 doubt.application",
			"4 doubt.service-application-default", "4 doubt.application",
			"7 doubt.not-evaluated.user", "7 doubt.hip", "8 doubt.schedule",
			"9 doubt.category-undefined", "10 doubt.category-no-url",
			"11 doubt.service-predefined", "12 doubt.service-absent",
		},
		"port and URL": {
			"3 doubt.service-application-default", "3 doubt.application",
			"4 doubt.service-application-default", "4 doubt.application",
			"7 doubt.not-evaluated.user", "7 doubt.hip", "8 doubt.schedule",
			"9 doubt.category-undefined", "11 doubt.service-predefined", "12 doubt.service-absent",
		},
		"no port": {
			"3 doubt.service-application-default", "3 doubt.application",
			"4 doubt.service-application-default", "4 doubt.application",
			"7 doubt.not-evaluated.user", "7 doubt.hip", "8 doubt.schedule",
			"9 doubt.category-undefined", "10 doubt.category-no-url",
			"11 doubt.service-predefined", "12 doubt.service-absent",
		},
	}
	for name, want := range codes {
		var f simulate.Flow
		switch name {
		case "port, no URL":
			f = flow(443, "tcp", "")
		case "port and URL":
			f = flow(443, "tcp", "shop.example.com")
		default:
			f = flow(0, "icmp", "")
		}
		if _, v := run(t, e, f); !slices.Equal(doubtCodeList(v), want) {
			t.Errorf("%s: codes %v\nwant %v", name, doubtCodeList(v), want)
		}
	}
	// A rule whose fields are all evaluated, or any, has no doubt.
	_, v := run(t, e, simulate.Flow{Source: ep("198.18.1.10"), Destination: ep("198.18.10.100"), FromZone: "home", ToZone: "labor", DestPort: 443})
	if first(v) != "to-labor" || len(v.Doubts) != 0 {
		t.Errorf("got %s, doubts %v", first(v), v.Doubts)
	}
	// A service the configuration defines is evaluated on a udp port.
	_, v = run(t, e, simulate.Flow{Source: ep("198.18.1.68"), Destination: ep("192.0.2.1"), FromZone: "home", ToZone: "wan", Protocol: "udp", DestPort: 443})
	if first(v) != "block-udp-443" || len(v.Doubts) == 0 || v.Doubts[0].Position != 3 {
		t.Errorf("got %s, doubts %v", first(v), v.Doubts)
	}
}

// A rule naming an external list, a region or a dynamic group stays a candidate
// with a doubt, negated or not, unless a known path decides it (spec E23).
func TestOpaqueAddressesStayInDoubt(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-opaque.xml", false)
	flow := func(src string) simulate.Flow {
		return simulate.Flow{Source: ep(src), Destination: ep("10.1.0.5"), FromZone: "outside", ToZone: "inside", DestPort: 443}
	}
	r, v := run(t, e, flow("10.1.0.10"))
	if got := ruleNames(v); got != "from-edl,from-country,from-dag,from-group,not-from-edl,to-builtin,from-region,plain" {
		t.Errorf("candidates %s", got)
	}
	want := strings.Join([]string{
		"1 from-edl: source: external list (edl-bad)",
		"2 from-country: source: region (AT)",
		"3 from-dag: source: members registered at runtime are not known (dag-web)",
		"5 not-from-edl: source: external list (edl-bad)",
		"6 to-builtin: destination: external list (panw-highrisk-ip-list)",
		"7 from-region: source: region (my-region)",
	}, "\n")
	if got := doubtList(v); got != want {
		t.Errorf("doubts\n%s\nwant\n%s", got, want)
	}
	wantCodes := []string{"1 doubt.edl", "2 doubt.region", "3 doubt.dynamic-group", "5 doubt.edl", "6 doubt.edl", "7 doubt.region"}
	if got := doubtCodeList(v); !slices.Equal(got, wantCodes) {
		t.Errorf("codes %v, want %v", got, wantCodes)
	}
	if d := stage(r, "resolve-source").Detail; !strings.Contains(d, "5 kept naming addresses the configuration does not hold") {
		t.Errorf("resolve-source: %s", d)
	}
	// The tagged address is a known member of dag-web, and not of g-mixed.
	_, v = run(t, e, flow("10.1.0.20"))
	if got := doubtList(v); !strings.Contains(got, "4 from-group: source: external list (edl-bad, in group g-mixed)") || strings.Contains(got, "from-dag") {
		t.Errorf("doubts\n%s", got)
	}
}

// A doubt with several reasons reads as one line; JSON keeps each with its
// code (spec 2026-10-09 §12 C6).
func TestADoubtJoinsItsReasons(t *testing.T) {
	t.Parallel()
	d := Doubt{Position: 2, Rule: "r", Reasons: simulate.Reasons{
		reason.New("doubt.edl", "source: external list (a)"), reason.New("doubt.region", "region (AT)"),
	}}
	b, err := json.Marshal(d)
	if err != nil || d.Text() != "source: external list (a); region (AT)" ||
		string(b) != `{"position":2,"rule":"r","reasons":[{"code":"doubt.edl","text":"source: external list (a)"},{"code":"doubt.region","text":"region (AT)"}]}` {
		t.Errorf("json = %s, %v", b, err)
	}
}

// Relevance writes its reason's code and text beside what it says.
func TestRelevanceJSON(t *testing.T) {
	t.Parallel()
	r := Relevance{Known: true, Relevant: true, Reason: reason.New("verdict.relevant-route", "10.0.0.0/8 via default covers 10.0.0.1")}
	b, err := json.Marshal(r)
	if err != nil || string(b) != `{"known":true,"relevant":true,"code":"verdict.relevant-route","text":"10.0.0.0/8 via default covers 10.0.0.1"}` {
		t.Errorf("json = %s, %v", b, err)
	}
}

// A rule that a resolved FQDN reaches only through an FQDN object is in doubt,
// and an earlier such rule with another action leaves the flow undecided (spec
// 2026-10-09 §3.8, E20). A rule an address reaches, a field of any and a
// negated rule are not.
func TestFQDNResolutionDoubt(t *testing.T) {
	t.Parallel()
	e := env(t, "firewall-fqdn.xml", false)
	dst := func(a string) simulate.Endpoint {
		return simulate.Endpoint{Name: "www.example.com", Addrs: []netip.Addr{netip.MustParseAddr(a)}, Resolved: true}
	}
	want := func(rule string) string {
		return rule + ": destination: www.example.com matched only through an FQDN object; the firewall resolves this object itself; its addresses can differ from ours"
	}
	negated := "not-web: destination: www.example.com excluded from the negated field only through an FQDN object; the firewall resolves this object itself; its addresses can differ from ours"
	for _, tc := range []struct {
		name, addr string
		doubts     []string
		first      string
	}{
		{"name only", "198.51.100.7", []string{want("block-web-by-name"), want("allow-web"), negated}, "rest"},
		{"name and address", "203.0.113.10", []string{want("block-web-by-name"), negated}, "allow-web"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: dst(tc.addr)})
			var got []string
			for _, d := range v.Doubts {
				if len(d.Reasons) != 1 || d.Reasons[0].Code != "doubt.fqdn-resolution" {
					t.Errorf("doubt %v", d.Reasons)
				}
				got = append(got, d.Rule+": "+d.Text())
			}
			if !slices.Equal(got, tc.doubts) {
				t.Errorf("doubts = %q, want %q", got, tc.doubts)
			}
			// An object named like the FQDN is not reached by the name.
			for _, r := range v.Candidates {
				if r.Name == "block-lookalike" {
					t.Errorf("block-lookalike is a candidate")
				}
			}
			if first(v) != tc.first {
				t.Errorf("first certain match = %s, want %s", first(v), tc.first)
			}
			out, why := v.Decision()
			if out != Undecided || why[0].Code != "doubt.fqdn-resolution" ||
				!strings.HasPrefix(why.Text(), "block-web-by-name (deny) at position 2 may match first: destination: www.example.com") {
				t.Errorf("decision = %s, %+v", out, why)
			}
		})
	}
	// The network object named like the FQDN matches by its address, with no
	// FQDN doubt.
	_, v := run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: dst("192.0.2.9")})
	if out, _ := v.Decision(); first(v) != "block-lookalike" || out != Stop || slices.ContainsFunc(v.Doubts, func(d Doubt) bool { return d.Rule == "block-lookalike" }) {
		t.Errorf("lookalike: doubts %v, first %s, %s", v.Doubts, first(v), out)
	}
	// An address alone reaches no rule through the FQDN object.
	_, v = run(t, e, simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("203.0.113.10")})
	if len(v.Doubts) != 0 || first(v) != "allow-web" {
		t.Errorf("an address: doubts %v, first %s", v.Doubts, first(v))
	}
}

// A rule naming service-https decides once the predefined services are stored
// (L4): tcp/443 hits it, tcp/80 goes on. A snapshot without them keeps the rule
// in doubt and says that a fetch stores them.
func TestPredefinedServicesDecideTheServiceStage(t *testing.T) {
	t.Parallel()
	flow := func(port uint16) simulate.Flow {
		return simulate.Flow{Source: ep("10.88.1.5"), Destination: ep("10.88.10.100"), FromZone: "home", ToZone: "wan", DestPort: port}
	}
	e := envPath(t, "../../../testdata/predefined/config.xml", false)
	r, v := run(t, e, flow(443))
	if first(v) != "web-https" || len(v.Doubts) != 0 || len(v.Undecided) != 0 || stage(r, "match-service").Fidelity.Level() != "exact" {
		t.Errorf("tcp/443: rule %s, doubts %s, undecided %v, service stage %s", first(v), doubtList(v), v.Undecided, stage(r, "match-service").Fidelity)
	}
	if _, v := run(t, e, flow(80)); first(v) != "web-rest" || len(v.Doubts) != 0 {
		t.Errorf("tcp/80: rule %s, doubts %s", first(v), doubtList(v))
	}
	b, err := os.ReadFile("../../../testdata/predefined/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, v = run(t, envPath(t, path, false), flow(443))
	if got := doubtList(v); got != "1 web-https: service predefined or not defined in the configuration (service-https); the snapshot holds no predefined services; a fetch with this release stores them when the device returns them" {
		t.Errorf("without predefined.xml: %s", got)
	}
}

// As observed on fw02, PAN-OS 12.2.3 (L9): a service name resolves by scope
// first and kind second, in the security policy as in NAT. vsys1's service
// group service-https (tcp/8443) hides the predefined service-https (tcp/443),
// and vsys1's service web (tcp/8081) hides shared's service group web
// (tcp/9080).
func TestAServiceNameResolvesByScopeFirst(t *testing.T) {
	t.Parallel()
	e := envPath(t, "../../../testdata/predefined-cross-kind/config.xml", false)
	for _, tc := range []struct {
		port uint16
		rule string
	}{
		{8443, "sec-https"},
		{443, "rest"},
		{80, "rest"},
		{8081, "sec-web"},
		{9080, "rest"},
	} {
		r, v := run(t, e, simulate.Flow{Source: ep("10.88.1.5"), Destination: ep("10.88.10.100"), FromZone: "home", ToZone: "wan", DestPort: tc.port})
		if first(v) != tc.rule || len(v.Doubts) != 0 || len(v.Undecided) != 0 || stage(r, "match-service").Fidelity.Level() != "exact" {
			t.Errorf("tcp/%d: rule %s, want %s; doubts %s, undecided %v, service stage %s",
				tc.port, first(v), tc.rule, doubtList(v), v.Undecided, stage(r, "match-service").Fidelity)
		}
	}
}
