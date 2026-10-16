package query

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
	"github.com/okaiser/proteus/internal/store"
	"github.com/okaiser/proteus/internal/testconfig"
)

// appFile copies firewall-appid.xml into a new directory and returns its
// path; with apps, the content file of version 8000-1000 lies beside it.
func appFile(t *testing.T, apps bool) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, pathlab.Read(t, fixture("firewall-appid.xml")), 0o600); err != nil {
		t.Fatal(err)
	}
	if apps {
		testconfig.Content(t, filepath.Join(dir, estate.AppsFile))
	}
	return path
}

// askFile asks simulate policy on a file from inside to outside.
func askFile(t *testing.T, path string, f FlowInput) SecurityResult {
	t.Helper()
	e, err := askFileEnvelope(path, f)
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	return e.Results[0]
}

func askFileEnvelope(path string, f FlowInput) (Envelope[PolicyFileInput, SecurityResult], error) {
	f.Source, f.Destination = "10.1.0.5", "10.2.0.5"
	return PolicyFile(context.Background(), Env{}, PolicyFileInput{Flow: f, Selection: Selection{File: path}})
}

// noteWith is an envelope's first note of a code.
func noteWith(ns []Note, code string) (Note, bool) {
	i := slices.IndexFunc(ns, func(n Note) bool { return string(n.Code) == code })
	if i < 0 {
		return Note{}, false
	}
	return ns[i], true
}

// With apps.xml.gz beside the file, flow ssl decides by the application:
// allow-outer holds ssl through its nested groups, on its default port. The
// run takes tcp from the default, and a note names the file (spec 2026-10-16
// §4.1, §6).
func TestPolicyFileEvaluatesTheApplication(t *testing.T) {
	t.Parallel()
	path := appFile(t, true)
	e, err := askFileEnvelope(path, FlowInput{Application: "ssl", Port: "443"})
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	r := e.Results[0]
	if r.Verdict != "pass" || r.Rule != "allow-outer" || r.Check.Protocol != "tcp" || e.Input.Simulated.Protocol != "" {
		t.Errorf("%s: %s, protocol %q", r.Verdict, r.Answer, r.Check.Protocol)
	}
	n, ok := noteWith(e.Notes, "note.app-data-file")
	if !ok || !strings.Contains(n.Note, filepath.Join(filepath.Dir(path), "apps.xml.gz")) || !strings.Contains(n.Note, "8000-1000") {
		t.Errorf("notes %+v", e.Notes)
	}
	if _, ok := noteWith(e.Notes, "note.app-shift"); !ok {
		t.Errorf("the run's own notes are missing: %+v", e.Notes)
	}
	// An implicit match carries its implicit use in the answer: allow-remote
	// names app-remote, whose implicit use holds web-browsing (I1, I7).
	r = askFile(t, path, FlowInput{Application: "web-browsing", Port: "80"})
	if r.Verdict != "pass" || r.Rule != "allow-remote" || r.Implicit == nil || r.Implicit.App != "web-browsing" ||
		!slices.Equal(r.Implicit.Via, []string{"app-remote"}) {
		t.Errorf("%s: %s, implicit %+v", r.Verdict, r.Answer, r.Implicit)
	}
}

// Without the file, the answer is today's, with note.app-data-missing.
func TestPolicyFileWithoutAppsNotes(t *testing.T) {
	t.Parallel()
	path := appFile(t, false)
	e, err := askFileEnvelope(path, FlowInput{Application: "ssl", Port: "443"})
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	today, err := askFileEnvelope(path, FlowInput{Protocol: "tcp", Port: "443"})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.Results[0]; r.Verdict != today.Results[0].Verdict || r.Answer != today.Results[0].Answer || r.Verdict != "undecided" {
		t.Errorf("%s: %s; today %s", r.Verdict, r.Answer, today.Results[0].Answer)
	}
	n, ok := noteWith(e.Notes, "note.app-data-missing")
	if !ok || !strings.Contains(n.Note, "apps.xml.gz does not exist") {
		t.Errorf("notes %+v", e.Notes)
	}
	if _, ok := noteWith(today.Notes, "note.app-data-missing"); ok {
		t.Errorf("a flow without an application loads no data, so it has no note: %+v", today.Notes)
	}
}

// A truncated content file is as no data, with the cause in the note (Review
// focus 3).
func TestADamagedContentFileIsMissingData(t *testing.T) {
	t.Parallel()
	path := appFile(t, true)
	apps := filepath.Join(filepath.Dir(path), estate.AppsFile)
	b := pathlab.Read(t, apps)
	if err := os.WriteFile(apps, b[:len(b)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := askFileEnvelope(path, FlowInput{Application: "ssl", Port: "443"})
	if err != nil || len(e.Results) != 1 || e.Results[0].Verdict != "undecided" {
		t.Fatalf("%+v %v", e, err)
	}
	n, ok := noteWith(e.Notes, "note.app-data-missing")
	if !ok || !strings.Contains(n.Note, apps+": ") || !strings.Contains(n.Note, "EOF") {
		t.Errorf("notes %+v", e.Notes)
	}
}

// A container is no flow application: exit 2 with its functions (P10, D13).
// So is an unknown name, with the nearest names.
func TestAContainerApplicationIsUsage(t *testing.T) {
	t.Parallel()
	path := appFile(t, true)
	_, err := askFileEnvelope(path, FlowInput{Application: "office-suite", Port: "443"})
	usageOK(t, err, "office-docs, office-mail")
	_, err = askFileEnvelope(path, FlowInput{Application: "app-medai", Port: "443"})
	usageOK(t, err, "nearest: app-media")
}

// contentOf is the content file of a version, gzipped: the fixture's
// applications without the named ones.
func contentOf(t *testing.T, version string, without ...string) []byte {
	t.Helper()
	raw := pathlab.Read(t, filepath.Join("..", "..", "testdata", "appid", "content.xml"))
	raw = bytes.Replace(raw, []byte(`version="8000-1000"`), []byte(`version="`+version+`"`), 1)
	for _, name := range without {
		entry := regexp.MustCompile(`(?s)<entry name="` + regexp.QuoteMeta(name) + `">.*?</entry>\n`)
		raw = entry.ReplaceAll(raw, nil)
	}
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// allowApp is a device's base configuration with one rule that allows an
// application on its default ports, between any zones.
func allowApp(t *testing.T, device, app string) []byte {
	t.Helper()
	rule := `</zone><rulebase><security><rules><entry name="allow-` + app + `">` +
		`<from><member>any</member></from><to><member>any</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<application><member>` + app + `</member></application>` +
		`<service><member>application-default</member></service><action>allow</action></entry></rules></security></rulebase>`
	return bytes.Replace(pathlab.Read(t, pathlab.ConfigFile(device)), []byte("</zone>"), []byte(rule), 1)
}

// appLab is the path lab whose devices allow app, each snapshot with its
// content version: "" names none. Each version's file is stored.
func appLab(t *testing.T, app string, versions map[string]string, files map[string][]byte) *lab {
	t.Helper()
	l := newLab(t)
	for v, b := range files {
		if err := l.st.WriteContent(v, b); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range pathlab.Devices {
		l.write(store.Meta{Device: d, Host: d + ".example.test", AppVersion: versions[d]}, allowApp(t, d, app))
	}
	return l
}

// askPath asks simulate policy along the lab path for an application on a
// port, with no protocol.
func askPath(t *testing.T, env Env, app, port string) Envelope[PolicyInput, PathResult] {
	t.Helper()
	e, err := Policy(context.Background(), env, PolicyInput{Flow: FlowInput{
		Source: pathlab.Source, Destination: pathlab.Destination, Port: port, Application: app, NoDNS: true,
	}})
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	return e
}

// Path mode decides by the application: both hops allow ssl on its default
// port, with each snapshot's content.
func TestPolicyPathEvaluatesTheApplication(t *testing.T) {
	t.Parallel()
	both := map[string]string{pathlab.FW01: "8000-1000", pathlab.FW02: "8000-1000"}
	l := appLab(t, "ssl", both, map[string][]byte{"8000-1000": contentOf(t, "8000-1000")})
	e := askPath(t, l.env(), "ssl", "443")
	r := e.Results[0]
	if r.Verdict != "allowed" || len(r.Hops) != 2 {
		t.Fatalf("%s: %s", r.Verdict, r.Answer)
	}
	for _, h := range r.Hops {
		if s := h.Checks[0].Security; s.Rule != "allow-ssl" || s.Verdict != "pass" {
			t.Errorf("hop %d: %s %s", h.Index, s.Verdict, s.Rule)
		}
	}
	if _, ok := noteWith(e.Notes, "note.app-data-missing"); ok {
		t.Errorf("notes %+v", e.Notes)
	}
	// Without data on fw02, its hop keeps the rule in doubt and says why.
	l = appLab(t, "ssl", map[string]string{pathlab.FW01: "8000-1000"}, map[string][]byte{"8000-1000": contentOf(t, "8000-1000")})
	e = askPath(t, l.env(), "ssl", "443")
	n, ok := noteWith(e.Notes, "note.app-data-missing")
	if r := e.Results[0]; r.Verdict != "undecided" || !ok || n.Device != pathlab.FW02 || !strings.Contains(n.Note, "names no content version") {
		t.Errorf("%s: %s; notes %+v", r.Verdict, r.Answer, e.Notes)
	}
}

// fw01 holds 8000-1000 and fw02 an older 8000-0999 without app-media: the
// fw02 hop is undecided, its reason names fw02 and its content version, and
// the answer is undecided (exit 3), not a usage error (Review focus 2).
func TestPolicyPathApplicationUnknownOnOneHop(t *testing.T) {
	t.Parallel()
	l := appLab(t, "app-media", map[string]string{pathlab.FW01: "8000-1000", pathlab.FW02: "8000-0999"}, map[string][]byte{
		"8000-1000": contentOf(t, "8000-1000"), "8000-0999": contentOf(t, "8000-0999", "app-media"),
	})
	e := askPath(t, l.env(), "app-media", "8554")
	r := e.Results[0]
	if r.Verdict != string(pathpolicy.VerdictUndecided) || len(r.Hops) != 2 {
		t.Fatalf("%s: %s", r.Verdict, r.Answer)
	}
	hop := func(device string) Security {
		i := slices.IndexFunc(r.Hops, func(h PathHop) bool { return h.Device == device })
		if i < 0 {
			t.Fatalf("no hop on %s", device)
		}
		return r.Hops[i].Checks[0].Security
	}
	if s := hop(pathlab.FW01); s.Verdict != "pass" || s.Rule != "allow-app-media" {
		t.Errorf("fw01: %s %s", s.Verdict, s.Rule)
	}
	s := hop(pathlab.FW02)
	if s.Verdict != "undecided" || len(s.Reasons) != 1 || s.Reasons[0].Code != "doubt.application-unknown" ||
		!strings.Contains(s.Reasons[0].Text, "fw02") || !strings.Contains(s.Reasons[0].Text, "8000-0999") {
		t.Errorf("fw02: %s %+v", s.Verdict, s.Reasons)
	}
	if len(e.Unresolved) == 0 || e.Unresolved[0].Device != pathlab.FW02 {
		t.Errorf("unresolved %+v", e.Unresolved)
	}
}

// A snapshot whose app_version names a file a prune removed has no data: the
// answer is as without, with the note (spec 2026-10-16 §3.4).
func TestAMissingContentFileIsMissingData(t *testing.T) {
	t.Parallel()
	both := map[string]string{pathlab.FW01: "8000-1000", pathlab.FW02: "8000-1000"}
	l := appLab(t, "ssl", both, nil)
	e := askPath(t, l.env(), "ssl", "443")
	n, ok := noteWith(e.Notes, "note.app-data-missing")
	if r := e.Results[0]; r.Verdict != "undecided" || !ok || !strings.Contains(n.Note, l.st.ContentPath("8000-1000")+" does not exist") {
		t.Errorf("%s: %s; notes %+v", r.Verdict, r.Answer, e.Notes)
	}
}

// countingApps loads from disk and counts the loads of each path.
type countingApps struct {
	mu    sync.Mutex
	loads map[string]int
}

func (c *countingApps) Apps(path string) (*appid.Data, error) {
	c.mu.Lock()
	c.loads[path]++
	c.mu.Unlock()
	return estate.DiskApps{}.Apps(path)
}

// The two hops share one content version: the question loads its file once
// (D11). A second question loads it again: the memo is the question's.
func TestLoadOncePerQuestion(t *testing.T) {
	t.Parallel()
	both := map[string]string{pathlab.FW01: "8000-1000", pathlab.FW02: "8000-1000"}
	l := appLab(t, "ssl", both, map[string][]byte{"8000-1000": contentOf(t, "8000-1000")})
	src := &countingApps{loads: map[string]int{}}
	env := l.env()
	env.Apps = src
	askPath(t, env, "ssl", "443")
	path := l.st.ContentPath("8000-1000")
	if src.loads[path] != 1 || len(src.loads) != 1 {
		t.Errorf("loads %v", src.loads)
	}
	askPath(t, env, "ssl", "443")
	if src.loads[path] != 2 {
		t.Errorf("loads %v", src.loads)
	}
	// A failed load is kept for the question too.
	m := env.appSource()
	for range 2 {
		if _, err := m.Apps(filepath.Join(t.TempDir(), "absent")); err == nil {
			t.Error("an absent file loads")
		}
	}
}

// appsOf names a target without a content version.
func TestAppsOfWithoutAVersion(t *testing.T) {
	t.Parallel()
	d, notes := appsOf(estate.Target{})
	if d != nil || len(notes) != 1 || notes[0].Code != "note.app-data-missing" || !strings.Contains(notes[0].Text, "the snapshot names no content version") {
		t.Errorf("%v %+v", d, notes)
	}
	if hasAppFile(estate.Target{}) {
		t.Error("a target without a path has a file")
	}
}

// A rule in doubt.application, with application data beside the file and no
// application asked: the application decides it, so the needs ask for it
// (C8).
func TestNeedsAskForTheApplication(t *testing.T) {
	t.Parallel()
	r := askFile(t, appFile(t, true), FlowInput{Protocol: "tcp", Port: "443"})
	i := slices.IndexFunc(r.Needs, func(n Need) bool { return n.Code == "input.application" })
	if r.Verdict != "undecided" || i < 0 || r.Needs[i].Input != "application" ||
		!strings.HasPrefix(r.Needs[i].Text, "give the application; it decides the application of rules allow-media, allow-tagged") {
		t.Errorf("%s: %s, needs %+v", r.Verdict, r.Answer, r.Needs)
	}
}

// The same without data: no application decides the rule, so none is asked.
func TestNeedsDoNotAskForTheApplicationWithoutData(t *testing.T) {
	t.Parallel()
	r := askFile(t, appFile(t, false), FlowInput{Protocol: "tcp", Port: "443"})
	if r.Verdict != "undecided" || slices.ContainsFunc(r.Needs, func(n Need) bool { return n.Code == "input.application" }) {
		t.Errorf("%s: %s, needs %+v", r.Verdict, r.Answer, r.Needs)
	}
}

// doubt.app-port-open without a port asks for the port (spec 2026-10-16 §4.5).
func TestNeedsAskForThePort(t *testing.T) {
	t.Parallel()
	r := askFile(t, appFile(t, true), FlowInput{Application: "ssl", Protocol: "tcp"})
	if r.Verdict != "undecided" || !slices.Equal(needCodes(r.Needs), []string{"input.port port"}) ||
		!slices.Contains(codes(t, r), "doubt.app-port-open") {
		t.Errorf("%s: %s, needs %+v, codes %v", r.Verdict, r.Answer, r.Needs, codes(t, r))
	}
}

// doubt.app-port-open with an open run protocol asks for the protocol: the
// application's default has none or several (spec 2026-10-16 §4.1).
func TestNeedsAskForTheProtocol(t *testing.T) {
	t.Parallel()
	open := simulate.Reasons{reason.New("doubt.app-port-open", "the protocol is open")}
	v := &securitypolicy.Verdict{AppData: true, Doubts: []securitypolicy.Doubt{{Position: 1, Rule: "r", Reasons: open}}}
	flow := simulate.Flow{Application: "app-range", DestPort: 1024}
	if ns := securityNeeds(flow, "undecided", v, simulate.Exact); !slices.Equal(needCodes(ns), []string{"input.protocol protocol"}) {
		t.Errorf("needs %+v", ns)
	}
	// A check that did not run has no doubt to judge.
	if ns := securityNeeds(flow, "undecided", nil, simulate.Exact); len(ns) != 0 {
		t.Errorf("no verdict: %+v", ns)
	}
}

// The flow gives no protocol and the run takes tcp from the application:
// the needs ask for the port and not for the protocol (spec 2026-10-16 §4.1).
func TestNeedsUseTheRunProtocol(t *testing.T) {
	t.Parallel()
	r := askFile(t, appFile(t, true), FlowInput{Application: "ssl"})
	if r.Verdict != "undecided" || r.Check.Protocol != "tcp" || !slices.Equal(needCodes(r.Needs), []string{"input.port port"}) {
		t.Errorf("%s: %s, protocol %q, needs %+v", r.Verdict, r.Answer, r.Check.Protocol, r.Needs)
	}
}
