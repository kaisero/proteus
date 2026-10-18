package securitypolicy

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/simulate"
)

// portObjects are the services and custom applications of the port tests,
// with dummy values: erp-custom (tcp/8443, P7), erp-nodefault (no default
// block, P6), and the services svc-8443 and svc-179.
const portObjects = `<application>` +
	`<entry name="erp-custom"><category>business-systems</category><subcategory>erp-crm</subcategory>` +
	`<technology>client-server</technology><risk>2</risk><default><port><member>tcp/8443</member></port></default></entry>` +
	`<entry name="erp-nodefault"><category>business-systems</category><subcategory>erp-crm</subcategory>` +
	`<technology>client-server</technology><risk>2</risk></entry>` +
	`</application>` +
	`<service>` +
	`<entry name="svc-8443"><protocol><tcp><port>8443</port></tcp></protocol></entry>` +
	`<entry name="svc-179"><protocol><tcp><port>179</port></tcp></protocol></entry>` +
	`</service>`

// svcRule is an allow rule from inside to outside with the given
// applications and service.
func svcRule(name string, apps []string, service string) string {
	return strings.Replace(appRule(name, "allow", apps, ""),
		"<service><member>any</member></service>", "<service><member>"+service+"</member></service>", 1)
}

// runAsGiven runs a flow and keeps its protocol as given, also when it is
// empty; run sets tcp then.
func runAsGiven(t *testing.T, e *simulate.Env, f simulate.Flow) (simulate.Run, Verdict) {
	t.Helper()
	r, err := Simulation{}.Run(context.Background(), e, simulate.Input{Flow: f, Device: "fw01", Vsys: "vsys1"})
	if err != nil {
		t.Fatal(err)
	}
	return r, r.Output.(Verdict)
}

// portFlow is a flow of the application from inside to outside on the
// protocol and port given.
func portFlow(app, proto string, port uint16) simulate.Flow {
	f := appFlow(app)
	f.Protocol, f.DestPort = proto, port
	return f
}

// portCase runs flows against rule r1 and checks whether r1 decides each.
type portCase struct {
	app, proto string
	port       uint16
	hit        bool
}

// checkPorts runs each case with the fixture data and the port objects. A
// hit decides by r1 with no undecided reason and no service doubt; a miss
// leaves r1 out of the candidates.
func checkPorts(t *testing.T, rules string, cases ...portCase) map[portCase]simulate.Run {
	t.Helper()
	e := appEnv(t, appConfig(t, portObjects, rules), content(t))
	runs := map[portCase]simulate.Run{}
	for _, c := range cases {
		r, v := runAsGiven(t, e, portFlow(c.app, c.proto, c.port))
		runs[c] = r
		switch {
		case c.hit && (first(v) != "r1" || len(v.Undecided) > 0):
			t.Errorf("%s %s/%d: first match %s, undecided %v, doubts %s", c.app, c.proto, c.port, first(v), v.Undecided, doubtList(v))
		case c.hit && slices.ContainsFunc(doubtCodesOf(v, "r1"), func(c reason.Code) bool { return strings.HasPrefix(string(c), "doubt.service") }):
			t.Errorf("%s %s/%d: service doubt %s", c.app, c.proto, c.port, doubtList(v))
		case !c.hit && slices.Contains(candidateNames(v), "r1"):
			t.Errorf("%s %s/%d: r1 is a candidate: %s", c.app, c.proto, c.port, doubtList(v))
		}
	}
	return runs
}

// P1: application-default allows the default ports of the application.
func TestApplicationDefaultMatchesDefaultPorts(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("ssl"), "application-default"),
		portCase{"ssl", "tcp", 443, true}, portCase{"ssl", "tcp", 22, false})
}

// P2: a /secure extended port matches as a default port, with a note.
func TestApplicationDefaultSecurePort(t *testing.T) {
	t.Parallel()
	c := portCase{"web-browsing", "tcp", 443, true}
	runs := checkPorts(t, svcRule("r1", apps("web-browsing"), "application-default"), c, portCase{"web-browsing", "tcp", 80, true})
	if !slices.Contains(noteCodes(runs[c].Notes), "note.app-secure-port") {
		t.Errorf("notes %v", runs[c].Notes)
	}
	if plain := runs[portCase{"web-browsing", "tcp", 80, true}]; slices.Contains(noteCodes(plain.Notes), "note.app-secure-port") {
		t.Errorf("a plain port has the note: %v", plain.Notes)
	}
}

// P3: tcp/dynamic is any TCP port, not UDP.
func TestApplicationDefaultDynamic(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("app-dyn-tcp"), "application-default"),
		portCase{"app-dyn-tcp", "tcp", 60000, true}, portCase{"app-dyn-tcp", "udp", 60000, false})
}

// P11: tcp/any is any TCP port, not UDP.
func TestApplicationDefaultAnyTCP(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("app-tcp-any"), "application-default"),
		portCase{"app-tcp-any", "tcp", 60000, true}, portCase{"app-tcp-any", "udp", 60000, false})
}

// P4: ident-by-ip-protocol is that protocol with any port.
func TestApplicationDefaultIPProtocol(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("ospf"), "application-default"),
		portCase{"ospf", "89", 0, true}, portCase{"ospf", "47", 0, false})
}

// P5: ident-by-icmp-type is protocol 1 with any type, with a note.
func TestApplicationDefaultICMP(t *testing.T) {
	t.Parallel()
	c := portCase{"ping", "icmp", 0, true}
	runs := checkPorts(t, svcRule("r1", apps("ping"), "application-default"), c, portCase{"ping", "icmp6", 0, false})
	if !slices.Contains(noteCodes(runs[c].Notes), "note.app-icmp-type") {
		t.Errorf("notes %v", runs[c].Notes)
	}
}

// P6: a custom application without a default block matches every protocol
// and port.
func TestCustomWithoutDefaultMatchesAll(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("erp-nodefault"), "application-default"), portCase{"erp-nodefault", "udp", 9, true})
}

// P6: a predefined application without a default block matches every
// protocol and port.
func TestPredefinedWithoutDefaultMatchesAll(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("app-nodefault"), "application-default"),
		portCase{"app-nodefault", "udp", 9, true}, portCase{"app-nodefault", "", 0, true})
}

// P7: a custom application takes its default from the configuration.
func TestCustomDefaultFromConfig(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("erp-custom"), "application-default"),
		portCase{"erp-custom", "tcp", 8443, true}, portCase{"erp-custom", "tcp", 443, false})
}

// P8: a custom service restricts the port; a port outside the default gets a
// note.
func TestCustomServiceRestricts(t *testing.T) {
	t.Parallel()
	c := portCase{"ssl", "tcp", 8443, true}
	runs := checkPorts(t, svcRule("r1", apps("ssl"), "svc-8443"), c, portCase{"ssl", "tcp", 443, false})
	if !slices.Contains(noteCodes(runs[c].Notes), "note.app-non-default-port") {
		t.Errorf("notes %v", runs[c].Notes)
	}
	// On a default port, the note does not apply.
	runs = checkPorts(t, svcRule("r1", apps("erp-custom"), "svc-8443"), portCase{"erp-custom", "tcp", 8443, true})
	for _, r := range runs {
		if slices.Contains(noteCodes(r.Notes), "note.app-non-default-port") {
			t.Errorf("default port: notes %v", r.Notes)
		}
	}
}

// P12: ident-by-dport does not change application-default.
func TestIdentDoesNotChangeTheMatch(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("ssl"), "application-default"),
		portCase{"ssl", "tcp", 443, true}, portCase{"ssl", "tcp", 8443, false})
}

// I7: an implicit match uses the default ports of the rule's application.
func TestImplicitUsesTheRuleApplicationPorts(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("app-remote"), "application-default"),
		portCase{"ssl", "tcp", 8090, true}, portCase{"ssl", "tcp", 22, false})
}

// I8: the ports of an implicit match are the union over the rule's
// applications that imply the flow's application.
func TestImplicitTakesTheUnionOfImpliers(t *testing.T) {
	t.Parallel()
	checkPorts(t, svcRule("r1", apps("app-remote", "app-remote-b"), "application-default"), portCase{"ssl", "tcp", 9000, true})
	checkPorts(t, svcRule("r1", apps("app-remote", "app-other"), "application-default"),
		portCase{"web-browsing", "tcp", 9977, false}, portCase{"ssl", "tcp", 9977, true})
}

// §4.5: without a port, an application-default rule stays in doubt.
func TestNoPortIsOpen(t *testing.T) {
	t.Parallel()
	e := appEnv(t, appConfig(t, portObjects, svcRule("r1", apps("ssl"), "application-default")), content(t))
	_, v := runAsGiven(t, e, portFlow("ssl", "tcp", 0))
	codes := doubtCodesOf(v, "r1")
	if !slices.Contains(codes, "doubt.app-port-open") || slices.Contains(codes, "doubt.service-application-default") {
		t.Errorf("doubts %s", doubtList(v))
	}
	if o, _ := v.Decision(); o != Undecided {
		t.Errorf("decision %s", o)
	}
	// A custom service without a port keeps today's doubt on the port.
	e = appEnv(t, appConfig(t, portObjects, svcRule("r1", apps("ssl"), "svc-8443")), content(t))
	r, v := runAsGiven(t, e, portFlow("ssl", "tcp", 0))
	if !slices.Contains(doubtCodesOf(v, "r1"), "doubt.service-no-port") {
		t.Errorf("custom service: doubts %s", doubtList(v))
	}
	if st := stage(r, "match-service"); !strings.Contains(st.Fidelity.String(), "not evaluated: service") {
		t.Errorf("custom service: stage %s", st.Fidelity)
	}
}

// With an evaluated application, a service the configuration does not
// define stays in doubt. An application-default that does not match leaves
// only that doubt.
func TestAnUndefinedServiceStaysWithAnApplication(t *testing.T) {
	t.Parallel()
	both := strings.Replace(svcRule("r2", apps("ssl"), "application-default"),
		"<member>application-default</member>", "<member>application-default</member><member>service-https</member>", 1)
	e := appEnv(t, appConfig(t, portObjects, svcRule("r1", apps("ssl"), "service-https")+both), content(t))
	_, v := runAsGiven(t, e, portFlow("ssl", "tcp", 22))
	for _, rule := range []string{"r1", "r2"} {
		if codes := doubtCodesOf(v, rule); !slices.Equal(codes, []reason.Code{"doubt.service-predefined"}) {
			t.Errorf("%s: doubts %s", rule, doubtList(v))
		}
	}
}

// I7, P8: an implicit match on a custom service's port outside the default
// of the rule's application gets the note, naming that application.
func TestAnImplicitMatchOnANonDefaultPort(t *testing.T) {
	t.Parallel()
	runs := checkPorts(t, svcRule("r1", apps("app-remote"), "svc-8443"), portCase{"ssl", "tcp", 8443, true})
	for _, r := range runs {
		i := slices.IndexFunc(r.Notes, func(n reason.Reason) bool { return n.Code == "note.app-non-default-port" })
		if i < 0 || !strings.Contains(r.Notes[i].Text, "app-remote (tcp/80,443,8090)") {
			t.Errorf("notes %v", r.Notes)
		}
	}
}

// P13, D19: a protocol without ports never matches a custom service, with
// and without a flow application.
func TestPortlessProtocolNeverMatchesACustomService(t *testing.T) {
	t.Parallel()
	e := appEnv(t, appConfig(t, portObjects, svcRule("r1", apps("ospf"), "svc-179")), content(t))
	r, v := runAsGiven(t, e, portFlow("ospf", "89", 0))
	if slices.Contains(candidateNames(v), "r1") {
		t.Errorf("ospf: candidates %v", candidateNames(v))
	}
	if st := stage(r, "match-service"); st.Fidelity.Level() != "exact" {
		t.Errorf("ospf: stage %s %q", st.Fidelity, st.Detail)
	}
	for _, data := range []*appid.Data{nil, content(t)} {
		e := appEnv(t, appConfig(t, `<service><entry name="svc-22"><protocol><tcp><port>22</port></tcp></protocol></entry></service>`,
			svcRule("r1", apps("any"), "svc-22")+svcRule("r2", apps("any"), "any")), data)
		r, v := runAsGiven(t, e, portFlow("", "icmp", 0))
		if slices.Contains(candidateNames(v), "r1") || first(v) != "r2" || len(v.Undecided) > 0 {
			t.Errorf("icmp, data %v: first match %s, candidates %v, undecided %v", data != nil, first(v), candidateNames(v), v.Undecided)
		}
		if st := stage(r, "match-service"); st.Fidelity.Level() != "exact" {
			t.Errorf("icmp, data %v: stage %s %q", data != nil, st.Fidelity, st.Detail)
		}
	}
}

// P13: on a protocol without ports, a rule that names an undefined service
// or application-default stays, with its doubt; one with any matches.
func TestPortlessProtocolKeepsWhatItCannotJudge(t *testing.T) {
	t.Parallel()
	e := appEnv(t, appConfig(t, portObjects,
		svcRule("r1", apps("any"), "service-https")+svcRule("r2", apps("any"), "application-default")+svcRule("r3", apps("any"), "any")), nil)
	r, v := runAsGiven(t, e, portFlow("", "icmp", 0))
	if got := candidateNames(v); !slices.Equal(got, []string{"r1", "r2", "r3"}) {
		t.Errorf("candidates %v", got)
	}
	if !slices.Contains(doubtCodesOf(v, "r1"), "doubt.service-predefined") || !slices.Contains(doubtCodesOf(v, "r2"), "doubt.service-application-default") {
		t.Errorf("doubts %s", doubtList(v))
	}
	if st := stage(r, "match-service"); st.Fidelity.Level() != "overmatch" || !strings.Contains(st.Fidelity.String(), "r1, r2") {
		t.Errorf("stage %s", st.Fidelity)
	}
}

// §4.1: with an application and no protocol, the run takes the one protocol
// of the default.
func TestProtocolFromTheDefault(t *testing.T) {
	t.Parallel()
	e := appEnv(t, appConfig(t, portObjects, svcRule("r1", apps("ssl"), "application-default")), content(t))
	r, v := runAsGiven(t, e, portFlow("ssl", "", 443))
	if first(v) != "r1" || len(v.Undecided) > 0 || v.Protocol != "tcp" {
		t.Errorf("first match %s, undecided %v, protocol %q", first(v), v.Undecided, v.Protocol)
	}
	if d := stage(r, "match-service").Detail; !strings.Contains(d, "tcp") || !strings.Contains(d, "default of ssl") {
		t.Errorf("detail %q", d)
	}
	// A given protocol stays as given.
	_, v = runAsGiven(t, e, portFlow("ssl", "udp", 443))
	if v.Protocol != "udp" || first(v) == "r1" {
		t.Errorf("udp: protocol %q, first match %s", v.Protocol, first(v))
	}
}

// §4.1: a default with several protocols, or none, leaves the protocol open.
func TestSeveralProtocolsStayOpen(t *testing.T) {
	t.Parallel()
	e := appEnv(t, appConfig(t, portObjects, svcRule("r1", apps("app-range"), "application-default")+
		svcRule("r2", apps("app-nodefault"), "application-default")), content(t))
	r, v := runAsGiven(t, e, portFlow("app-range", "", 1025))
	if !slices.Contains(doubtCodesOf(v, "r1"), "doubt.app-port-open") || v.Protocol != "" {
		t.Errorf("doubts %s, protocol %q", doubtList(v), v.Protocol)
	}
	if d := stage(r, "match-service").Detail; !strings.Contains(d, "open") || !strings.Contains(d, "app-range") {
		t.Errorf("detail %q", d)
	}
	// No default block: every protocol (P6), so the protocol stays open and
	// the rule matches.
	_, v = runAsGiven(t, e, portFlow("app-nodefault", "", 0))
	if first(v) != "r2" || len(v.Undecided) > 0 || v.Protocol != "" {
		t.Errorf("no default: first match %s, undecided %v, protocol %q", first(v), v.Undecided, v.Protocol)
	}
}

// A custom flow application whose default cannot be read leaves its
// application-default rules in doubt: they are not decided either way.
func TestAnUnreadableDefaultKeepsTheRule(t *testing.T) {
	t.Parallel()
	objects := `<application><entry name="erp-bad"><category>business-systems</category><subcategory>erp-crm</subcategory>` +
		`<technology>client-server</technology><risk>2</risk><default><port><member>tcp/abc</member></port></default></entry></application>`
	e := appEnv(t, appConfig(t, objects, svcRule("r2", apps("erp-bad"), "application-default")), content(t))
	_, v := runAsGiven(t, e, portFlow("erp-bad", "tcp", 22))
	if !slices.Contains(doubtCodesOf(v, "r2"), "doubt.service-application-default") {
		t.Errorf("doubts %s", doubtList(v))
	}
	if o, _ := v.Decision(); o != Undecided {
		t.Errorf("decision %s, rule %s", o, first(v))
	}
}

// The port notes are the winner's only.
func TestOnlyTheWinnerGivesPortNotes(t *testing.T) {
	t.Parallel()
	e := appEnv(t, appConfig(t, portObjects, appRule("r1", "allow", apps("web-browsing"), "")+
		svcRule("r2", apps("web-browsing"), "application-default")), content(t))
	r, v := runAsGiven(t, e, portFlow("web-browsing", "tcp", 443))
	if first(v) != "r1" || slices.Contains(noteCodes(r.Notes), "note.app-secure-port") {
		t.Errorf("first match %s, notes %v", first(v), r.Notes)
	}
}
