package securitypolicy

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
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
		out = append(out, fmt.Sprintf("%d %s: %s", d.Position, d.Rule, d.Reason))
	}
	return strings.Join(out, "\n")
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
			"9 dmz-pandb: url category not evaluated without a URL (news)",
			"10 dmz-custom: url category not evaluated without a URL (my-cat)",
			"11 dmz-predefined: service predefined or not defined in the configuration (service-https)",
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
			"11 dmz-predefined: service predefined or not defined in the configuration (service-https)",
			"12 dmz-no-service: service absent",
		}},
		{"no port", flow(0, "icmp", ""), []string{
			"3 app-one: service not evaluated without a tcp, udp or sctp port (application-default)",
			"3 app-one: application not evaluated (dropbox)",
			"4 app-two: service not evaluated without a tcp, udp or sctp port (application-default)",
			"4 app-two: application not evaluated (zoom)",
			`7 dmz-user: user not evaluated (corp\alice)`,
			"7 dmz-user: destination-hip not evaluated (hip-a)",
			"8 dmz-schedule: schedule not evaluated (work-hours)",
			"9 dmz-pandb: url category not evaluated without a URL (news)",
			"10 dmz-custom: url category not evaluated without a URL (my-cat)",
			"11 dmz-predefined: service not evaluated without a tcp, udp or sctp port (service-https)",
			"12 dmz-no-service: service absent",
		}},
	} {
		_, v := run(t, e, c.flow)
		if got, want := doubtList(v), strings.Join(c.want, "\n"); got != want {
			t.Errorf("%s: doubts\n%s\nwant\n%s\ncandidates %s", c.name, got, want, ruleNames(v))
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
	if d := stage(r, "resolve-source").Detail; !strings.Contains(d, "5 kept naming addresses the configuration does not hold") {
		t.Errorf("resolve-source: %s", d)
	}
	// The tagged address is a known member of dag-web, and not of g-mixed.
	_, v = run(t, e, flow("10.1.0.20"))
	if got := doubtList(v); !strings.Contains(got, "4 from-group: source: external list (edl-bad, in group g-mixed)") || strings.Contains(got, "from-dag") {
		t.Errorf("doubts\n%s", got)
	}
}
