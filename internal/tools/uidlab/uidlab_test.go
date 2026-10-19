package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/tools/labkit"
)

// root is the repository root, seen from this package.
const root = "../../.."

const header = "case\tfact\tcheck\tfrom\tto\tsource\tdestination\tuser\tsubject\texpected\n"

func TestReadFlowsFillsPlaceholders(t *testing.T) {
	t.Parallel()
	vars := map[string]string{
		"USER_A": `example.com\alice`, "UPN_A": "alice@example.com", "IP_A": "198.51.100.11",
		"IP_U": "198.51.100.99", "GROUP": "cn=domain users,cn=users,dc=example,dc=com",
	}
	in := "# comment\n" + header +
		"p1\tN1,§5.1/given\tpolicy\tzone-a\tzone-b\t${IP_U}\t192.0.2.10\t${USER_A}\t-\t-\n" +
		"p2\tN3\tpolicy\tzone-a\tzone-b\t${IP_U}\t192.0.2.10\t${UPN_A}\t${USER_A}\tresolved\n" +
		"p3\tM4\tpolicy\tzone-a\tzone-b\t${IP_U}\t192.0.2.17\t-\t-\tunknown-inferred\n" +
		"p4\tD1\tpolicy\tzone-a\tzone-b\t${IP_U}\t192.0.2.29\t${USER_A}\t-\tdoubt\n" +
		"u1\tN5\tuser\t-\t-\t-\t-\t${USER_A}\t${UPN_A}\t-\n" +
		"i1\tN4\tip\t-\t-\t-\t-\t-\t${IP_A}\t-\n" +
		"g1\tU4\tgroup\t-\t-\t-\t-\t-\t${GROUP}\t-\n"
	flows, err := ReadFlows(strings.NewReader(in), vars)
	if err != nil {
		t.Fatal(err)
	}
	policy := Flow{Check: "policy", From: "zone-a", To: "zone-b", Source: "198.51.100.99", Destination: "192.0.2.10"}
	want := []Flow{
		with(policy, func(f *Flow) { f.Case, f.Fact, f.User = "p1", "N1,§5.1/given", `example.com\alice` }),
		with(policy, func(f *Flow) {
			f.Case, f.Fact, f.User, f.Subject, f.Expect = "p2", "N3", "alice@example.com", `example.com\alice`, "resolved"
		}),
		with(policy, func(f *Flow) { f.Case, f.Fact, f.Destination, f.Expect = "p3", "M4", "192.0.2.17", "unknown-inferred" }),
		with(policy, func(f *Flow) {
			f.Case, f.Fact, f.Destination, f.User, f.Expect = "p4", "D1", "192.0.2.29", `example.com\alice`, "doubt"
		}),
		{Case: "u1", Fact: "N5", Check: "user", User: `example.com\alice`, Subject: "alice@example.com"},
		{Case: "i1", Fact: "N4", Check: "ip", Subject: "198.51.100.11"},
		{Case: "g1", Fact: "U4", Check: "group", Subject: "cn=domain users,cn=users,dc=example,dc=com"},
	}
	if !slices.Equal(flows, want) {
		t.Errorf("flows =\n%+v\nwant\n%+v", flows, want)
	}

	row := func(fields ...string) string { return header + strings.Join(fields, "\t") + "\n" }
	pol := func(user, subject, expect string) string {
		return row("c", "M1", "policy", "z", "z", "${IP_U}", "192.0.2.10", user, subject, expect)
	}
	for name, bad := range map[string]string{
		"unknown placeholder":       pol("${USER_Z}", "-", "-"),
		"no header":                 "c\tM1\tpolicy\tz\tz\ta\tb\t-\t-\t-\n",
		"short row":                 row("c", "M1", "policy", "z"),
		"bad check":                 row("c", "M1", "route", "z", "z", "s", "d", "-", "-", "-"),
		"bad expected":              pol("-", "-", "maybe"),
		"resolved without subject":  pol("${UPN_A}", "-", "resolved"),
		"resolved without user":     pol("-", "${USER_A}", "resolved"),
		"subject without resolved":  pol("${USER_A}", "${USER_A}", "-"),
		"unknown-inferred, a user":  pol("${USER_A}", "-", "unknown-inferred"),
		"policy without zone":       row("c", "M1", "policy", "-", "z", "s", "d", "-", "-", "-"),
		"user without subject":      row("c", "N5", "user", "-", "-", "-", "-", "${USER_A}", "-", "-"),
		"user without user":         row("c", "N5", "user", "-", "-", "-", "-", "-", "${UPN_A}", "-"),
		"user with a source":        row("c", "N5", "user", "-", "-", "${IP_U}", "-", "${USER_A}", "${UPN_A}", "-"),
		"ip without subject":        row("c", "N4", "ip", "-", "-", "-", "-", "-", "-", "-"),
		"ip with a user":            row("c", "N4", "ip", "-", "-", "-", "-", "${USER_A}", "${IP_A}", "-"),
		"group with an expectation": row("c", "U4", "group", "-", "-", "-", "-", "-", "${GROUP}", "doubt"),
		"empty fact":                row("c", "", "ip", "-", "-", "-", "-", "-", "${IP_A}", "-"),
		"unsafe case":               row("c/1", "N4", "ip", "-", "-", "-", "-", "-", "${IP_A}", "-"),
		"duplicate case":            pol("-", "-", "-") + "c\tM1\tpolicy\tz\tz\ts\td\t-\t-\t-\n",
	} {
		if _, err := ReadFlows(strings.NewReader(bad), vars); err == nil {
			t.Errorf("%s: ReadFlows gave no error", name)
		}
	}
	if _, err := ReadFlows(strings.NewReader(""), vars); err == nil {
		t.Error("an empty flow list gave no error")
	}
}

func with(f Flow, change func(*Flow)) Flow {
	change(&f)
	return f
}

func TestDeviceCmds(t *testing.T) {
	t.Parallel()
	policy := Flow{Check: "policy", From: "zone-a", To: "zone-b", Source: "198.51.100.11", Destination: "192.0.2.10", User: `example.com\alice`}
	base := "<test><security-policy-match><from>zone-a</from><to>zone-b</to><source>198.51.100.11</source>" +
		"<destination>192.0.2.10</destination><protocol>6</protocol><destination-port>443</destination-port>"
	for name, c := range map[string]struct {
		f    Flow
		want []string
	}{
		"policy with a user": {policy, []string{base + `<source-user>example.com\alice</source-user></security-policy-match></test>`}},
		"policy without a user": {
			with(policy, func(f *Flow) { f.User = "" }),
			[]string{base + "</security-policy-match></test>"},
		},
		// N3: the test command does not resolve a UPN, so the device gets
		// the primary name.
		"resolved": {
			with(policy, func(f *Flow) { f.User, f.Subject, f.Expect = "alice@example.com", `example.com\alice`, "resolved" }),
			[]string{base + `<source-user>example.com\alice</source-user></security-policy-match></test>`},
		},
		// U8, N5: user-attributes by the UPN, match-user by the primary name.
		"user": {
			Flow{Check: "user", User: `example.com\alice`, Subject: "alice@example.com"},
			[]string{
				"<show><user><user-attributes><user>alice@example.com</user></user-attributes></user></show>",
				`<show><user><user-ids><match-user>example.com\alice</match-user></user-ids></user></show>`,
			},
		},
		"ip": {
			Flow{Check: "ip", Subject: "198.51.100.11"},
			[]string{"<show><user><ip-user-mapping-mp><ip>198.51.100.11</ip></ip-user-mapping-mp></user></show>"},
		},
		"group": {
			Flow{Check: "group", Subject: "R&D <lab>"},
			[]string{"<show><user><group><name>R&amp;D &lt;lab&gt;</name></group></user></show>"},
		},
		"unknown check": {Flow{Check: "route"}, nil},
	} {
		got := DeviceCmds(c.f)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: DeviceCmds =\n%q\nwant\n%q", name, got, c.want)
		}
		for _, cmd := range got {
			if err := labkit.CheckOp(cmd); err != nil {
				t.Errorf("%s: the guard refuses %s: %v", name, cmd, err)
			}
		}
	}
}

func TestProteusArgs(t *testing.T) {
	t.Parallel()
	file := []string{"--file", "/tmp/x/config.xml", "--vsys", "vsys1", "--output", "json"}
	policy := Flow{Check: "policy", From: "zone-a", To: "zone-b", Source: "198.51.100.11", Destination: "192.0.2.10"}
	simulate := []string{
		"simulate", "policy", "198.51.100.11", "192.0.2.10", "--file", "/tmp/x/config.xml", "--vsys", "vsys1",
		"--from-zone", "zone-a", "--to-zone", "zone-b", "--protocol", "6", "--port", "443", "--no-dns", "--output", "json",
	}
	for name, c := range map[string]struct {
		f    Flow
		want []string
	}{
		"policy":           {policy, simulate},
		"policy with user": {with(policy, func(f *Flow) { f.User = "alice@example.com" }), append(slices.Clone(simulate), "--user", "alice@example.com")},
		// A flow marked resolved gives proteus the user as written (§5.2).
		"resolved": {
			with(policy, func(f *Flow) { f.User, f.Subject, f.Expect = "alice@example.com", `example.com\alice`, "resolved" }),
			append(slices.Clone(simulate), "--user", "alice@example.com"),
		},
		"user": {
			Flow{Check: "user", User: `example.com\alice`, Subject: "alice@example.com"},
			append([]string{"lookup", `example.com\alice`, "--kind", "identity-user"}, file...),
		},
		"ip":    {Flow{Check: "ip", Subject: "198.51.100.11"}, append([]string{"search", "198.51.100.11"}, file...)},
		"group": {Flow{Check: "group", Subject: "uid-lab-xmlapi"}, append([]string{"lookup", "uid-lab-xmlapi", "--kind", "identity-group", "--full"}, file...)},
		"other": {Flow{Check: "route"}, nil},
	} {
		if got := ProteusArgs(c.f, "/tmp/x/config.xml", "vsys1"); !slices.Equal(got, c.want) {
			t.Errorf("%s: args =\n%q\nwant\n%q", name, got, c.want)
		}
	}
}

// identityAnswer reads one device answer of testdata/identity.
func identityAnswer(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "testdata", "identity", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// u8Alice is the answer of U8 by the UPN of alice: her block only.
const u8Alice = "<response status=\"success\"><result>\nPrimary: example.com\\alice\tEmail: alice@example.com\n" +
	"Alt User Names: \n1) Alice@example.com\n2) example.com\\alice\n\n</result></response>"

func TestParseDevice(t *testing.T) {
	t.Parallel()
	policy := Flow{Case: "p", Check: "policy"}
	rule := `<response cmd="status" status="success"><result><rules><entry name='uid-lab-user'><index>1</index><action>allow</action></entry></rules></result></response>`
	if a, err := ParseDevice(policy, [][]byte{[]byte(rule)}); err != nil || a.Rule != "uid-lab-user" || a.Action != "allow" {
		t.Errorf("a rule: %+v, %v", a, err)
	}
	// The test command never lists a default rule (I6): no rule.
	if a, err := ParseDevice(policy, [][]byte{[]byte(`<response status="success"><result/></response>`)}); err != nil || a.Rule != "" {
		t.Errorf("no rule: %+v, %v", a, err)
	}

	// U8 and U3 match-user (U8, N5, X1).
	user := Flow{Case: "u", Check: "user"}
	a, err := ParseDevice(user, [][]byte{[]byte(u8Alice), identityAnswer(t, "answer-user-ids-match.xml")})
	if err != nil {
		t.Fatal(err)
	}
	wantGroups := []string{"cn=domain users,cn=users,dc=example,dc=com", "engineering", "dug-a", "dug-ab", "custom-a"}
	if a.Name != `example.com\alice` || !slices.Equal(a.Names, []string{"Alice@example.com", `example.com\alice`, "alice@example.com"}) ||
		!slices.Equal(a.Groups, wantGroups) {
		t.Errorf("user: %+v", a)
	}
	// U8 by the primary name answers nothing (N5): no user.
	if a, err := ParseDevice(user, [][]byte{[]byte(`<response status="success"><result></result></response>`), identityAnswer(t, "answer-user-ids-match.xml")}); err != nil || a.Name != "" {
		t.Errorf("an empty U8: %+v, %v", a, err)
	}

	// U1 by address: a mapping, and no mapping.
	ip := Flow{Case: "i", Check: "ip"}
	if a, err := ParseDevice(ip, [][]byte{identityAnswer(t, "answer-mapping-ip.xml")}); err != nil ||
		a.Name != `example.com\alice` || a.Source != "XMLAPI" || !slices.Equal(a.IPs, []string{"198.51.100.11"}) {
		t.Errorf("a mapping: %+v, %v", a, err)
	}
	if a, err := ParseDevice(ip, [][]byte{identityAnswer(t, "answer-mapping-ip-none.xml")}); err != nil || a.Name != "" || a.IPs != nil {
		t.Errorf("no mapping: %+v, %v", a, err)
	}

	// U4: an LDAP group, a DUG, an XML API group and a group without members.
	group := Flow{Case: "g", Check: "group"}
	if a, err := ParseDevice(group, [][]byte{identityAnswer(t, "answer-group-name.xml")}); err != nil || a.Source != "ldap:example.com" ||
		!slices.Equal(a.Names, []string{`example.com\alice`, `example.com\bob`, `example.com\carol`}) {
		t.Errorf("a group: %+v, %v", a, err)
	}
	u4 := func(body string) [][]byte {
		return [][]byte{[]byte(`<response status="success"><result><![CDATA[` + body + `]]></result></response>`)}
	}
	if a, err := ParseDevice(group, u4("\nsource type: xmlapi\nGroup type: Dynamic\n\n[1     ] example.com\\carol\n")); err != nil || a.Source != "dug" {
		t.Errorf("a DUG: %+v, %v", a, err)
	}
	if a, err := ParseDevice(group, u4("\n\n\nsource type: xmlapi\n\n[1     ] other\\ghost\n")); err != nil || a.Source != "xmlapi" {
		t.Errorf("an XML API group: %+v, %v", a, err)
	}
	if a, err := ParseDevice(group, u4("\nsource type: ldap\n\n[1     ] example.com\\carol\n")); err != nil || a.Source != "ldap" {
		t.Errorf("an LDAP group without its profile: %+v, %v", a, err)
	}
	if a, err := ParseDevice(group, u4("\nUser group 'cn=empty' does not exist or does not have members\n")); err != nil || a.Source != "" || a.Names != nil {
		t.Errorf("a group without members: %+v, %v", a, err)
	}

	for name, c := range map[string]struct {
		f       Flow
		answers [][]byte
	}{
		"policy error":      {policy, [][]byte{[]byte(`<response status="error"><msg><line>invalid zone</line></msg></response>`)}},
		"two U8 blocks":     {user, [][]byte{identityAnswer(t, "answer-user-attributes.xml"), identityAnswer(t, "answer-user-ids-match.xml")}},
		"two users":         {user, [][]byte{[]byte(u8Alice), identityAnswer(t, "answer-user-ids.xml")}},
		"broken U8":         {user, [][]byte{[]byte("not xml"), identityAnswer(t, "answer-user-ids-match.xml")}},
		"broken match-user": {user, [][]byte{[]byte(u8Alice), []byte("not xml")}},
		"one user answer":   {user, [][]byte{[]byte(u8Alice)}},
		"two mappings":      {ip, [][]byte{identityAnswer(t, "answer-mappings-2.xml")}},
		"broken mapping":    {ip, [][]byte{[]byte("not xml")}},
		"broken group":      {group, u4("\nno such line\n")},
		"unknown check":     {Flow{Case: "x", Check: "route"}, nil},
	} {
		if _, err := ParseDevice(c.f, c.answers); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestParseProteus(t *testing.T) {
	t.Parallel()
	policy := Flow{Case: "p", Check: "policy"}
	decided := `{"results":[{"verdict":"pass","rule":"uid-lab-user","default":"","fidelity":{"level":"exact"},
		"first_match":{"name":"uid-lab-user","action":"allow"}}],"notes":[]}`
	if a, err := ParseProteus(policy, []byte(decided), 0); err != nil || a.Rule != "uid-lab-user" || a.Action != "allow" || a.Inferred || a.Doubt || a.Default {
		t.Errorf("decided: %+v, %v", a, err)
	}
	def := `{"results":[{"verdict":"stop","rule":"interzone-default","default":"interzone-default","default_action":"deny","first_match":null}]}`
	if a, err := ParseProteus(policy, []byte(def), 0); err != nil || a.Rule != "interzone-default" || a.Action != "deny" || !a.Default {
		t.Errorf("default: %+v, %v", a, err)
	}
	// Undecided, with the CIE doubt (§5.6), exits 3.
	undecided := `{"results":[{"verdict":"undecided","rule":"","fidelity":{"level":"overmatch","reasons":[
		{"code":"doubt.user-cie-group","text":"kept rules"}]}}]}`
	if a, err := ParseProteus(policy, []byte(undecided), 3); err != nil || a.Rule != "" || !a.Doubt {
		t.Errorf("undecided: %+v, %v", a, err)
	}
	inferred := `{"results":[{"verdict":"stop","rule":"uid-lab-catch","fidelity":{"level":"inferred"},
		"first_match":{"name":"uid-lab-catch","action":"deny"}}],
		"notes":[{"code":"note.user-unknown-inferred","text":"no user"}]}`
	if a, err := ParseProteus(policy, []byte(inferred), 0); err != nil || !a.Inferred || a.Rule != "uid-lab-catch" {
		t.Errorf("inferred: %+v, %v", a, err)
	}
	// Inferred without the note is not the mark's answer.
	noNote := strings.Replace(inferred, "note.user-unknown-inferred", "note.user-resolved", 1)
	if a, err := ParseProteus(policy, []byte(noNote), 0); err != nil || a.Inferred {
		t.Errorf("inferred without the note: %+v, %v", a, err)
	}

	// A card of lookup (§6.2).
	userCard := `{"results":[{"card":{"kind":"identity-user","name":"example.com\\alice","sections":[
		{"title":"primary","rows":[{"label":"","text":"example.com\\alice"}]},
		{"title":"alternate names","rows":[{"label":"","items":[{"name":"alice@example.com"}]}]},
		{"title":"email","rows":[{"label":"","text":"alice@example.com"}]},
		{"title":"groups","rows":[{"label":"","items":[{"name":"cn=domain users,cn=users,dc=example,dc=com","value":"ldap:example.com"}]}]},
		{"title":"mapped addresses","rows":[]},{"title":"tags","rows":[]}]}}]}`
	a, err := ParseProteus(Flow{Check: "user"}, []byte(userCard), 0)
	if err != nil || a.Name != `example.com\alice` || !slices.Equal(a.Names, []string{"alice@example.com", "alice@example.com"}) ||
		!slices.Equal(a.Groups, []string{"cn=domain users,cn=users,dc=example,dc=com"}) {
		t.Errorf("a user card: %+v, %v", a, err)
	}
	groupCard := `{"results":[{"card":{"kind":"identity-group","name":"uid-lab-xmlapi","sections":[
		{"title":"source","rows":[{"label":"","text":"xmlapi"}]},
		{"title":"members","rows":[{"label":"","text":"2 members"},{"label":"","items":[{"name":"example.com\\xavier"},{"name":"other\\ghost"}]}]}]}}]}`
	a, err = ParseProteus(Flow{Check: "group"}, []byte(groupCard), 0)
	if err != nil || a.Source != "xmlapi" || !slices.Equal(a.Names, []string{`example.com\xavier`, `other\ghost`}) {
		t.Errorf("a group card: %+v, %v", a, err)
	}
	// No card: the identity data does not know the name.
	if a, err := ParseProteus(Flow{Check: "group"}, []byte(`{"results":[]}`), 0); err != nil || a.Source != "" {
		t.Errorf("no card: %+v, %v", a, err)
	}

	// A finding of search (§6.1): the mapping, next to other findings.
	finding := `{"results":[{"kind":"address","name":"uid-lab-src","via":"198.51.100.0/24"},
		{"kind":"mapping","name":"198.51.100.11","via":"user example.com\\alice, XMLAPI, timeout 14400 s"}]}`
	a, err = ParseProteus(Flow{Check: "ip"}, []byte(finding), 0)
	if err != nil || a.Name != `example.com\alice` || a.Source != "XMLAPI" || !slices.Equal(a.IPs, []string{"198.51.100.11"}) {
		t.Errorf("a mapping finding: %+v, %v", a, err)
	}
	if a, err := ParseProteus(Flow{Check: "ip"}, []byte(`{"results":[]}`), 0); err != nil || a.Name != "" {
		t.Errorf("no mapping: %+v, %v", a, err)
	}

	for name, c := range map[string]struct {
		f    Flow
		b    string
		exit int
	}{
		"failure":         {policy, `{"format":2,"exit":1,"error":"boom"}`, 1},
		"usage":           {policy, `{"format":2,"exit":2,"error":"--user unknown: a keyword"}`, 2},
		"broken json":     {policy, `{`, 0},
		"no result":       {policy, `{"results":[]}`, 0},
		"no first match":  {policy, `{"results":[{"verdict":"pass","rule":"r","first_match":null}]}`, 0},
		"broken card":     {Flow{Check: "user"}, `{"results":[{"card":7}]}`, 0},
		"broken finding":  {Flow{Check: "ip"}, `{"results":[{"kind":"mapping","name":"198.51.100.11","via":"no user"}]}`, 0},
		"two mappings":    {Flow{Check: "ip"}, `{"results":[{"kind":"mapping","name":"a","via":"user u, T, timeout 1 s"},{"kind":"mapping","name":"b","via":"user u, T, timeout 1 s"}]}`, 0},
		"broken search":   {Flow{Check: "ip"}, `[`, 0},
		"unknown check":   {Flow{Check: "route"}, `{}`, 0},
		"user exit error": {Flow{Check: "user"}, "proteus: bad\n", 1},
	} {
		if _, err := ParseProteus(c.f, []byte(c.b), c.exit); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()
	allow := Answer{Rule: "uid-lab-user", Action: "allow"}
	catch := Answer{Rule: "uid-lab-catch", Action: "deny"}
	def := Answer{Rule: "interzone-default", Action: "deny", Default: true}
	inferred := Answer{Rule: "uid-lab-catch", Action: "deny", Inferred: true}
	alice := Answer{
		Name: `example.com\alice`, Names: []string{"alice@example.com", `example.com\alice`},
		Groups: []string{"cn=domain users,cn=users,dc=example,dc=com", "dug-a"},
	}
	mapping := Answer{Name: `example.com\alice`, Source: "XMLAPI", IPs: []string{"198.51.100.11"}}
	group := Answer{Source: "ldap:example.com", Names: []string{`example.com\alice`, `example.com\bob`}}
	for _, c := range []struct {
		name            string
		f               Flow
		device, proteus Answer
		ok              bool
	}{
		// A policy flow without a mark: the rule and the action agree.
		{"same rule", Flow{Check: "policy"}, allow, allow, true},
		{"other rule", Flow{Check: "policy"}, allow, catch, false},
		{"other action", Flow{Check: "policy"}, allow, Answer{Rule: "uid-lab-user", Action: "deny"}, false},
		{"no device rule and a default rule", Flow{Check: "policy"}, Answer{}, def, true},
		{"no device rule and a rule", Flow{Check: "policy"}, Answer{}, allow, false},
		{"a device rule and a default rule", Flow{Check: "policy"}, allow, def, false},
		{"undecided without a mark", Flow{Check: "policy"}, allow, Answer{}, false},
		// resolved: proteus with User, the device with Subject (N3).
		{"resolved, same", Flow{Check: "policy", Expect: "resolved"}, allow, allow, true},
		{"resolved, other", Flow{Check: "policy", Expect: "resolved"}, allow, catch, false},
		// unknown-inferred: the device answer is recorded only (M4).
		{"unknown-inferred", Flow{Check: "policy", Expect: "unknown-inferred"}, Answer{Rule: "uid-lab-known", Action: "allow"}, inferred, true},
		{"unknown-inferred, exact", Flow{Check: "policy", Expect: "unknown-inferred"}, catch, catch, false},
		{"unknown-inferred, undecided", Flow{Check: "policy", Expect: "unknown-inferred"}, catch, Answer{Inferred: true}, false},
		// doubt: a CIE group (§5.6).
		{"doubt, undecided", Flow{Check: "policy", Expect: "doubt"}, catch, Answer{}, true},
		{"doubt, kept with the doubt", Flow{Check: "policy", Expect: "doubt"}, catch, Answer{Rule: "uid-lab-cie", Action: "allow", Doubt: true}, true},
		{"doubt, decided", Flow{Check: "policy", Expect: "doubt"}, catch, catch, false},
		// user: names, email and groups, in any case.
		{"user, same", Flow{Check: "user"}, alice, alice, true},
		{"user, other case", Flow{Check: "user"}, alice, Answer{
			Name: `EXAMPLE.COM\alice`, Names: []string{`example.com\ALICE`, "Alice@Example.com"},
			Groups: []string{"dug-a", "CN=DOMAIN USERS,CN=USERS,DC=EXAMPLE,DC=COM", "dug-a"},
		}, true},
		{"user, other primary", Flow{Check: "user"}, alice, with2(alice, func(a *Answer) { a.Name = `example\alice` }), false},
		{"user, other names", Flow{Check: "user"}, alice, with2(alice, func(a *Answer) { a.Names = a.Names[:1] }), false},
		{"user, other groups", Flow{Check: "user"}, alice, with2(alice, func(a *Answer) { a.Groups = nil }), false},
		{"user, unknown to the device", Flow{Check: "user"}, Answer{}, alice, false},
		// ip: the mapped user and the type.
		{"ip, same", Flow{Check: "ip"}, mapping, mapping, true},
		{"ip, no mapping on both", Flow{Check: "ip"}, Answer{}, Answer{}, true},
		{"ip, other user", Flow{Check: "ip"}, mapping, with2(mapping, func(a *Answer) { a.Name = `example\alice` }), false},
		{"ip, other type", Flow{Check: "ip"}, mapping, with2(mapping, func(a *Answer) { a.Source = "AD" }), false},
		{"ip, no mapping in proteus", Flow{Check: "ip"}, mapping, Answer{}, false},
		// group: the source and the member set.
		{"group, same", Flow{Check: "group"}, group, group, true},
		{"group, members in another order and case", Flow{Check: "group"}, group, with2(group, func(a *Answer) {
			a.Names = []string{`EXAMPLE.COM\bob`, `example.com\alice`}
		}), true},
		{"group, other source", Flow{Check: "group"}, group, with2(group, func(a *Answer) { a.Source = "xmlapi" }), false},
		{"group, other members", Flow{Check: "group"}, group, with2(group, func(a *Answer) { a.Names = a.Names[:1] }), false},
		// U4 names no source for a group without members: the members decide.
		{"group without members", Flow{Check: "group"}, Answer{}, Answer{Source: "ldap:example.com"}, true},
		{"group without members on the device only", Flow{Check: "group"}, Answer{}, group, false},
		{"unknown check", Flow{Check: "route"}, Answer{}, Answer{}, false},
	} {
		c.f.Case = "c"
		err := Compare(c.f, c.device, c.proteus)
		if (err == nil) != c.ok {
			t.Errorf("%s: Compare = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

func with2(a Answer, change func(*Answer)) Answer {
	a.Names, a.Groups, a.IPs = slices.Clone(a.Names), slices.Clone(a.Groups), slices.Clone(a.IPs)
	change(&a)
	return a
}

func TestDescribe(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		f    Flow
		a    Answer
		want string
	}{
		{Flow{Check: "policy"}, Answer{}, "no rule"},
		{Flow{Check: "policy"}, Answer{Rule: "r", Action: "allow"}, "r (allow)"},
		{Flow{Check: "policy"}, Answer{Rule: "d", Action: "deny", Default: true, Inferred: true, Doubt: true}, "d (deny, default rule, inferred, CIE doubt)"},
		{Flow{Check: "user"}, Answer{Name: "u", Names: []string{"a"}, Groups: []string{"g", "h"}}, "u, 1 names, 2 groups"},
		{Flow{Check: "user"}, Answer{}, "no user"},
		{Flow{Check: "ip"}, Answer{Name: "u", Source: "XMLAPI"}, "u (XMLAPI)"},
		{Flow{Check: "ip"}, Answer{}, "no mapping"},
		{Flow{Check: "group"}, Answer{Source: "dug", Names: []string{"a"}}, "dug, 1 members"},
		{Flow{Check: "group"}, Answer{}, "no source, 0 members"},
		{Flow{Check: "route"}, Answer{}, ""},
	} {
		if got := describe(c.f, c.a); got != c.want {
			t.Errorf("describe(%s, %+v) = %q, want %q", c.f.Check, c.a, got, c.want)
		}
	}
}

// labFile reads one file of docs/lab.
func labFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// node is a parsed XML element.
type node struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Text    string     `xml:",chardata"`
	Nodes   []node     `xml:",any"`
}

func (n node) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n node) child(name string) *node {
	for i := range n.Nodes {
		if n.Nodes[i].XMLName.Local == name {
			return &n.Nodes[i]
		}
	}
	return nil
}

func (n *node) members() []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, c := range n.Nodes {
		if c.XMLName.Local == "member" {
			out = append(out, c.Text)
		}
	}
	return out
}

// walk calls fn for every element below n, n too.
func (n node) walk(fn func(node)) {
	fn(n)
	for _, c := range n.Nodes {
		c.walk(fn)
	}
}

// setEntry is one line of the set file.
type setEntry struct {
	xpath, kind, name string
	elem              node
}

func readSetFile(t *testing.T) []setEntry {
	t.Helper()
	var out []setEntry
	for i, line := range strings.Split(labFile(t, SetFile), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		xpath, elem, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("set line %d has no tab", i+1)
		}
		kind, ok := strings.CutPrefix(xpath, labkit.VsysXPath+"/")
		if !ok {
			t.Fatalf("set line %d: xpath %s is not below %s", i+1, xpath, labkit.VsysXPath)
		}
		var n node
		if err := xml.Unmarshal([]byte(elem), &n); err != nil {
			t.Fatalf("set line %d: %v", i+1, err)
		}
		e := setEntry{xpath: xpath, kind: kind, elem: n, name: n.attr("name")}
		if n.XMLName.Local != "entry" || len(n.Attrs) != 1 || e.name == "" {
			t.Fatalf("set line %d: the element is not one named entry", i+1)
		}
		out = append(out, e)
	}
	return out
}

const ruleKind = "rulebase/security/rules"

// rulesByDestination maps the destination of each lab rule to the rule.
func rulesByDestination(entries []setEntry) map[string]setEntry {
	out := map[string]setEntry{}
	for _, e := range entries {
		if e.kind == ruleKind {
			out[e.elem.child("destination").members()[0]] = e
		}
	}
	return out
}

// readMessage reads a User-ID message file: the children of its payload.
func readMessage(t *testing.T, name string) []node {
	t.Helper()
	var msg node
	if err := xml.Unmarshal([]byte(labFile(t, name)), &msg); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	payload := msg.child("payload")
	if msg.XMLName.Local != "uid-message" || payload == nil {
		t.Fatalf("%s is no uid-message with a payload", name)
	}
	return payload.Nodes
}

// xmlapiMembers are the members of the lab XML API groups of the login file.
func xmlapiMembers(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for _, part := range readMessage(t, LoginFile) {
		if part.XMLName.Local != "groups" {
			continue
		}
		for _, g := range part.Nodes {
			for _, m := range g.child("members").Nodes {
				out[g.attr("name")] = append(out[g.attr("name")], m.attr("name"))
			}
		}
	}
	return out
}

// The lab configuration touches only its own objects (spec 2026-10-17 §10.4).
func TestLabConfigIsIsolated(t *testing.T) {
	t.Parallel()
	entries := readSetFile(t)
	kinds := map[string]bool{"address": true, "tag": true, "dynamic-user-group": true, ruleKind: true}
	// The XML API groups come from the login file, not from the set file.
	defined := map[string]bool{}
	for g := range xmlapiMembers(t) {
		defined[g] = true
	}
	lab := netip.MustParsePrefix("192.0.2.0/24")
	rules := 0
	for i, e := range entries {
		if !kinds[e.kind] {
			t.Errorf("%s: kind %s is not a lab kind", e.name, e.kind)
		}
		if !strings.HasPrefix(e.name, "uid-lab-") {
			t.Errorf("%s: the name does not start with uid-lab-", e.name)
		}
		// Every uid-lab- name an entry names is an entry set before it.
		e.elem.walk(func(n node) {
			if n.XMLName.Local == "member" && strings.HasPrefix(n.Text, "uid-lab-") && !defined[n.Text] {
				t.Errorf("%s names %s before it is set", e.name, n.Text)
			}
		})
		defined[e.name] = true
		if e.kind != ruleKind {
			if rules > 0 {
				t.Errorf("%s: the rules come last", e.name)
			}
			continue
		}
		rules++
		for _, f := range []string{"from", "to"} {
			if got := e.elem.child(f).members(); !slices.Equal(got, []string{"any"}) {
				t.Errorf("rule %s: %s %v, want any", e.name, f, got)
			}
		}
		if got := e.elem.child("source").members(); !slices.Equal(got, []string{"uid-lab-src"}) {
			t.Errorf("rule %s: source %v, want uid-lab-src", e.name, got)
		}
		dst := e.elem.child("destination").members()
		p, err := netip.ParsePrefix(strings.Join(dst, ""))
		if a, aerr := netip.ParseAddr(strings.Join(dst, "")); aerr == nil {
			p, err = a.Prefix(32)
		}
		if len(dst) != 1 || err != nil || !lab.Contains(p.Addr()) || p.Bits() < lab.Bits() {
			t.Errorf("rule %s: destination %v, want one in %s", e.name, dst, lab)
		}
		if e.name == "uid-lab-catch" {
			if i != len(entries)-1 {
				t.Errorf("uid-lab-catch is entry %d of %d, want the last", i+1, len(entries))
			}
			if a := e.elem.child("action"); a == nil || a.Text != "deny" || dst[0] != lab.String() {
				t.Errorf("uid-lab-catch: want a deny for all of %s", lab)
			}
		}
	}
	if rules == 0 || entries[len(entries)-1].name != "uid-lab-catch" {
		t.Error("the set file does not end with the rule uid-lab-catch")
	}
	if src := entries[0]; src.name != "uid-lab-src" || src.elem.child("ip-netmask") == nil || src.elem.child("ip-netmask").Text != "${SRC_NET}" {
		t.Errorf("the first entry is %s, want the address uid-lab-src with ${SRC_NET}", src.name)
	}

	// The delete file removes every entry, in the reverse order.
	var want []string
	for _, e := range slices.Backward(entries) {
		want = append(want, e.xpath+"/entry[@name='"+e.name+"']")
	}
	var got []string
	for _, line := range strings.Split(labFile(t, DeleteFile), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			got = append(got, line)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("the delete file is not the set file's entries in reverse:\ngot  %q\nwant %q", got, want)
	}
}

// placeholder is ${KEY} in a lab file, as labkit.Fill reads it.
var placeholder = regexp.MustCompile(`\$\{([A-Z][A-Z0-9_]*)\}`)

// labFlows reads the flow list with each placeholder filled by itself.
func labFlows(t *testing.T) []Flow {
	t.Helper()
	text := labFile(t, FlowsFile)
	vars := map[string]string{}
	for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[0]
	}
	flows, err := ReadFlows(strings.NewReader(text), vars)
	if err != nil {
		t.Fatal(err)
	}
	return flows
}

// The facts of spec 2026-10-17 §10.3 that the flow list covers: M1-M9,
// M11-M17, N1-N5 and the rows of §5.1 and §5.3. M10 and M18 are waits of the
// tool, not flows.
func wantFacts() []string {
	var out []string
	for i := 1; i <= 17; i++ {
		if i != 10 {
			out = append(out, fmt.Sprintf("M%d", i))
		}
	}
	for i := 1; i <= 5; i++ {
		out = append(out, fmt.Sprintf("N%d", i))
	}
	for _, row := range []string{"given", "mapped", "both", "none"} {
		out = append(out, "§5.1/"+row)
	}
	for _, row := range []string{"any", "absent", "known-user", "unknown", "pre-logon", "user", "group", "dug", "cie", "local", "no-group"} {
		out = append(out, "§5.3/"+row)
	}
	return out
}

func TestFlowListCoversTheFacts(t *testing.T) {
	t.Parallel()
	flows := labFlows(t)
	facts := map[string]bool{}
	checks := map[string]bool{}
	for _, f := range flows {
		checks[f.Check] = true
		for _, fact := range strings.Split(f.Fact, ",") {
			facts[fact] = true
		}
	}
	for _, fact := range wantFacts() {
		if !facts[fact] {
			t.Errorf("no flow for %s", fact)
		}
	}
	for _, c := range []string{"policy", "user", "ip", "group"} {
		if !checks[c] {
			t.Errorf("no %s check", c)
		}
	}

	// Each policy flow reaches one lab rule, from a mapped or an unmapped
	// source of the lab range.
	byDst := rulesByDestination(readSetFile(t))
	mapped := map[string]bool{}
	for _, part := range readMessage(t, LoginFile) {
		if part.XMLName.Local == "login" {
			for _, e := range part.Nodes {
				mapped[e.attr("ip")] = true
			}
		}
	}
	sources := map[bool]bool{}
	reached := map[string]bool{}
	for _, f := range flows {
		if f.Check != "policy" {
			continue
		}
		r, ok := byDst[f.Destination]
		if !ok || r.name == "uid-lab-catch" {
			t.Errorf("%s: no lab rule has the destination %s", f.Case, f.Destination)
		}
		reached[r.name] = true
		sources[mapped[f.Source]] = true
	}
	if !sources[true] || !sources[false] {
		t.Errorf("the policy flows come from a mapped source %v and from an unmapped source %v", sources[true], sources[false])
	}

	// A rule with a user and a group, which a flow reaches (M9).
	groups := map[string]bool{}
	for g := range xmlapiMembers(t) {
		groups[g] = true
	}
	for _, e := range readSetFile(t) {
		if e.kind == "dynamic-user-group" {
			groups[e.name] = true
		}
	}
	both := false
	for _, r := range byDst {
		su := r.elem.child("source-user").members()
		user := slices.ContainsFunc(su, func(m string) bool { return strings.HasPrefix(m, "${USER_") })
		group := slices.ContainsFunc(su, func(m string) bool { return groups[m] || strings.HasPrefix(m, "${GROUP_") })
		both = both || user && group && reached[r.name]
	}
	if !both {
		t.Error("no flow reaches a rule that names a user and a group")
	}
}

// An XML API group message rewrites the U8 block of each member until the
// next group-mapping refresh, as observed on fw01, PAN-OS 11.2.5 (spec
// 2026-10-17 U18): no user check, UPN or alternate name names a member.
func TestTheLabXMLAPIGroupMeetsNoUserCheck(t *testing.T) {
	t.Parallel()
	members := map[string]bool{}
	for _, ms := range xmlapiMembers(t) {
		for _, m := range ms {
			members[strings.ToLower(m)] = true
		}
	}
	if len(members) == 0 {
		t.Fatal("the login file holds no XML API group member")
	}
	for _, f := range labFlows(t) {
		var names []string
		switch {
		case f.Check == "user":
			names = []string{f.User, f.Subject}
		case f.Expect == "resolved":
			names = []string{f.User, f.Subject}
		}
		for _, n := range names {
			if members[strings.ToLower(n)] {
				t.Errorf("%s names %s, a member of the lab XML API group", f.Case, n)
			}
		}
	}
}

// login is one login entry of a User-ID message.
type login struct{ name, ip, timeout string }

func logins(part node) []login {
	var out []login
	for _, e := range part.Nodes {
		out = append(out, login{e.attr("name"), e.attr("ip"), e.attr("timeout")})
	}
	return out
}

// A logout can fail, as observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17
// U19): the logout file ends with a login of timeout 1 for every mapping, so
// each expires.
func TestTheLogoutEndsWithShortLogins(t *testing.T) {
	t.Parallel()
	in := readMessage(t, LoginFile)
	var mapped []login
	var tags, groups []node
	for _, part := range in {
		switch part.XMLName.Local {
		case "login":
			mapped = append(mapped, logins(part)...)
		case "register-user":
			tags = append(tags, part.Nodes...)
		case "groups":
			groups = append(groups, part.Nodes...)
		default:
			t.Errorf("the login file holds %s", part.XMLName.Local)
		}
	}
	if len(mapped) == 0 {
		t.Fatal("the login file maps no address")
	}
	for _, m := range mapped {
		// The XML API login timeout is in minutes (U13).
		if m.timeout != "240" {
			t.Errorf("login %s: timeout %q, want 240 minutes", m.ip, m.timeout)
		}
	}

	out := readMessage(t, LogoutFile)
	var names []string
	for _, part := range out {
		names = append(names, part.XMLName.Local)
	}
	if want := []string{"logout", "unregister-user", "groups", "login"}; !slices.Equal(names, want) {
		t.Fatalf("the logout file holds %v, want %v", names, want)
	}
	strip := func(ls []login) []login {
		out := slices.Clone(ls)
		for i := range out {
			out[i].timeout = ""
		}
		return out
	}
	if got := logins(out[0]); !slices.Equal(got, strip(mapped)) {
		t.Errorf("logout %v, want every mapping %v", got, strip(mapped))
	}
	if len(out[1].Nodes) != len(tags) {
		t.Errorf("unregister-user holds %d users, want %d", len(out[1].Nodes), len(tags))
	}
	for i, u := range out[1].Nodes {
		if i < len(tags) && (u.attr("user") != tags[i].attr("user") ||
			!slices.Equal(u.child("tag").members(), tags[i].child("tag").members())) {
			t.Errorf("unregister-user %d is %s %v, want %s %v", i+1, u.attr("user"), u.child("tag").members(),
				tags[i].attr("user"), tags[i].child("tag").members())
		}
	}
	// The XML API group stays with empty members (O4).
	for i, g := range out[2].Nodes {
		if i >= len(groups) || g.attr("name") != groups[i].attr("name") || g.child("members") == nil || len(g.child("members").Nodes) > 0 {
			t.Errorf("groups entry %d: want %v with empty members", i+1, groups)
		}
	}
	short := logins(out[3])
	for i := range short {
		if short[i].timeout != "1" {
			t.Errorf("the last login %s: timeout %q, want 1", short[i].ip, short[i].timeout)
		}
	}
	if !slices.Equal(strip(short), strip(mapped)) {
		t.Errorf("the last login %v, want every mapping %v", short, mapped)
	}
}

// labDataFiles are the tracked User-ID lab files.
var labDataFiles = []string{FlowsFile, SetFile, DeleteFile, LoginFile, LogoutFile}

// The documentation ranges of RFC 5737 and RFC 3849. The benchmark range that
// applab allows is not among them.
var exampleNets = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"),
}

// The lab files hold placeholders and dummy names, never a lab address,
// serial or domain (spec 2026-10-17 §10.3, §10.5), and no file with real lab
// data is tracked (D12).
func TestLabFilesHoldNoLabData(t *testing.T) {
	t.Parallel()
	for _, name := range labDataFiles {
		text := labFile(t, name)
		for _, bad := range slices.Concat(labkit.LabDataIn(text, exampleNets), labkit.LabDomainsIn(text, []string{"example.com"})) {
			t.Errorf("%s holds %s", name, bad)
		}
	}
	gi, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(strings.Split(string(gi), "\n"), "/"+VarsFile) {
		t.Errorf(".gitignore does not name /%s", VarsFile)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git, so the tracked-file check cannot run")
	}
	untracked := []string{VarsFile, "docs/lab/user-id-poc*", "docs/lab/user-id-r3*", "docs/lab/user-id-config-switch*"}
	out, err := exec.CommandContext(context.Background(), git, append([]string{"-C", root, "ls-files", "--"}, untracked...)...).Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(out)) > 0 {
		t.Errorf("git tracks lab files with real data:\n%s", out)
	}
}

// U18: with the values filled, no user check and no resolved flow names a
// member of the lab XML API group, in any case.
func TestRefuseXMLAPIMembers(t *testing.T) {
	t.Parallel()
	login := []byte(`<uid-message><payload><groups><entry name="uid-lab-xmlapi"><members>` +
		`<entry name="${USER_X}"/><entry name="other\ghost"/></members></entry></groups></payload></uid-message>`)
	vars := map[string]string{"USER_X": `example.com\xavier`}
	ok := []Flow{
		{Case: "u", Check: "user", User: `example.com\alice`, Subject: "alice@example.com"},
		{Case: "p", Check: "policy", User: `example.com\xavier`}, // a policy flow may name a member (M7)
	}
	if err := refuseXMLAPIMembers(ok, login, vars); err != nil {
		t.Errorf("no member named: %v", err)
	}
	for name, f := range map[string]Flow{
		"user check":      {Case: "u", Check: "user", User: `EXAMPLE.COM\xavier`, Subject: "x@example.com"},
		"user check UPN":  {Case: "u", Check: "user", User: `example.com\bob`, Subject: `other\ghost`},
		"resolved flow":   {Case: "r", Check: "policy", User: "x@example.com", Subject: `example.com\xavier`, Expect: "resolved"},
		"resolved by UPN": {Case: "r", Check: "policy", User: `other\ghost`, Subject: `example.com\bob`, Expect: "resolved"},
	} {
		if err := refuseXMLAPIMembers([]Flow{f}, login, vars); err == nil || !strings.Contains(err.Error(), "member of the lab XML API group") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := refuseXMLAPIMembers(ok, []byte("not xml"), vars); err == nil {
		t.Error("a broken login file gave no error")
	}
	if err := refuseXMLAPIMembers(ok, login, nil); err == nil {
		t.Error("an unfilled login file gave no error")
	}
}

// M18: another try helps only where Compare reads the device answer.
func TestDeviceDecides(t *testing.T) {
	t.Parallel()
	rule := Answer{Rule: "r", Action: "allow"}
	for _, c := range []struct {
		f    Flow
		p    Answer
		perr error
		want bool
	}{
		{Flow{Check: "policy"}, rule, nil, true},
		{Flow{Check: "policy", Expect: "resolved"}, rule, nil, true},
		{Flow{Check: "policy", Expect: "unknown-inferred"}, rule, nil, false},
		{Flow{Check: "policy", Expect: "doubt"}, rule, nil, false},
		{Flow{Check: "policy"}, Answer{}, nil, false}, // proteus undecided
		{Flow{Check: "policy"}, rule, fmt.Errorf("boom"), false},
		{Flow{Check: "user"}, rule, nil, false},
	} {
		if got := deviceDecides(c.f, c.p, c.perr); got != c.want {
			t.Errorf("%+v %+v %v: %v, want %v", c.f, c.p, c.perr, got, c.want)
		}
	}
}
