package securitypolicy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/testconfig"
)

// appConfig writes a small configuration and returns its path: vsys1 with the
// zones inside (10.1.0.0/24) and outside (10.2.0.0/24), the objects given (custom
// applications, filters, groups) and the security rules given (spec 2026-10-16
// D16). Every value is a dummy.
func appConfig(t *testing.T, objects, rules string) string {
	t.Helper()
	cfg := `<config version="11.2.0" urldb="paloaltonetworks"><devices><entry name="localhost.localdomain">` +
		`<network><interface><ethernet>` +
		`<entry name="ethernet1/1"><layer3><ip><entry name="10.1.0.1/24"/></ip></layer3></entry>` +
		`<entry name="ethernet1/2"><layer3><ip><entry name="10.2.0.1/24"/></ip></layer3></entry>` +
		`</ethernet></interface></network>` +
		`<vsys><entry name="vsys1">` +
		`<import><network><interface><member>ethernet1/1</member><member>ethernet1/2</member></interface></network></import>` +
		`<zone><entry name="inside"><network><layer3><member>ethernet1/1</member></layer3></network></entry>` +
		`<entry name="outside"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone>` +
		objects +
		`<rulebase><security><rules>` + rules + `</rules></security></rulebase>` +
		`</entry></vsys></entry></devices></config>`
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// appRule is a security rule from inside to outside with service any. Without
// applications, the rule has no application element. extra is placed in the
// entry as given.
func appRule(name, action string, apps []string, extra string) string {
	var b strings.Builder
	b.WriteString(`<entry name="` + name + `"><from><member>inside</member></from><to><member>outside</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>`)
	if len(apps) > 0 {
		b.WriteString("<application>")
		for _, a := range apps {
			b.WriteString("<member>" + a + "</member>")
		}
		b.WriteString("</application>")
	}
	b.WriteString(`<service><member>any</member></service>` + extra + `<action>` + action + `</action></entry>`)
	return b.String()
}

func apps(names ...string) []string { return names }

var (
	contentOnce sync.Once
	contentData *appid.Data
	contentErr  error
)

// content is the App-ID data of testdata/appid/content.xml, version 8000-1000.
func content(t *testing.T) *appid.Data {
	t.Helper()
	contentOnce.Do(func() {
		dir, err := os.MkdirTemp("", "appid")
		if err != nil {
			contentErr = err
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()
		path := filepath.Join(dir, "apps.xml.gz")
		testconfig.Content(t, path)
		contentData, contentErr = appid.Load(path)
	})
	if contentErr != nil {
		t.Fatal(contentErr)
	}
	return contentData
}

// contentWithoutContainers is the fixture data as a device answer without its
// containers gives it (spec 2026-10-16 §2.2).
func contentWithoutContainers(t *testing.T) *appid.Data {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/appid/content.xml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	s = strings.Replace(s, `trim="1">`, `trim="1" containers="missing">`, 1)
	s = regexp.MustCompile(`(?s)<application-container>\s*<entry.*</application-container>`).ReplaceAllString(s, "")
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	d, err := appid.Parse(&b)
	if err != nil {
		t.Fatal(err)
	}
	if d.HasContainers() {
		t.Fatal("the data still has its containers")
	}
	return d
}

// appEnv loads a configuration's vsys1 with the given application data.
func appEnv(t *testing.T, path string, data *appid.Data) *simulate.Env {
	t.Helper()
	return &simulate.Env{Load: func(_, vsys string) (simulate.Target, error) {
		cfg, _, err := config.Load(path)
		if err != nil {
			return simulate.Target{}, err
		}
		set := index.NewSet(cfg)
		sc := config.Scope{Sort: config.ScopeVsys, Name: vsys}
		if _, err := set.Index(sc, resolve.Security); err != nil {
			return simulate.Target{}, err
		}
		return simulate.Target{Config: cfg, Indexes: set.Provider(sc), Providers: index.Providers{Apps: data}}, nil
	}}
}

// appFlow is a flow from inside to outside on tcp/443 with an application.
func appFlow(app string) simulate.Flow {
	return simulate.Flow{
		Source: ep("10.1.0.5"), Destination: ep("10.2.0.5"), Protocol: "tcp", DestPort: 443,
		FromZone: "inside", ToZone: "outside", Application: app,
	}
}

// appRun runs a flow of the application against a configuration, with the
// fixture data.
func appRun(t *testing.T, objects, rules, app string) (simulate.Run, Verdict) {
	t.Helper()
	return run(t, appEnv(t, appConfig(t, objects, rules), content(t)), appFlow(app))
}

func noteCodes(rs simulate.Reasons) []reason.Code {
	var out []reason.Code
	for _, r := range rs {
		out = append(out, r.Code)
	}
	return out
}

// doubtCodesOf is the codes of the doubts of one rule.
func doubtCodesOf(v Verdict, rule string) []reason.Code {
	var out []reason.Code
	for _, d := range v.Doubts {
		if d.Rule == rule {
			out = append(out, noteCodes(d.Reasons)...)
		}
	}
	return out
}

func candidateNames(v Verdict) []string {
	var out []string
	for _, r := range v.Candidates {
		out = append(out, r.Name)
	}
	return out
}

// I1: an allow rule also matches the implicit-use-applications of its
// applications.
func TestAnAllowRuleMatchesImplicitUse(t *testing.T) {
	t.Parallel()
	r, v := appRun(t, "", appRule("r1", "allow", apps("app-remote"), ""), "ssl")
	if first(v) != "r1" || len(v.Undecided) > 0 {
		t.Fatalf("first match %s, undecided %v", first(v), v.Undecided)
	}
	if v.Implicit == nil || v.Implicit.App != "ssl" || !slices.Equal(v.Implicit.Via, []string{"app-remote"}) {
		t.Errorf("implicit = %+v", v.Implicit)
	}
	if !slices.Contains(noteCodes(r.Notes), "note.app-implicit") {
		t.Errorf("notes = %v", r.Notes)
	}
}

// I2: an explicit match wins over an implicit match, also when it comes later.
func TestExplicitWinsOverAnEarlierImplicit(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "allow", apps("app-remote"), "")+appRule("r2", "deny", apps("ssl"), ""), "ssl")
	if first(v) != "r2" || len(v.Undecided) > 0 || v.Implicit != nil {
		t.Errorf("first match %s, undecided %v, implicit %+v", first(v), v.Undecided, v.Implicit)
	}
}

// I3: an application does not match a rule only because the rule allows its
// use-applications, nor because the rule allows an application it implies.
func TestTheReverseDoesNotMatch(t *testing.T) {
	t.Parallel()
	for _, rule := range []string{"dns", "ssl"} {
		_, v := appRun(t, "", appRule("r1", "allow", apps(rule), ""), "app-remote")
		if first(v) != "none" || slices.Contains(candidateNames(v), "r1") {
			t.Errorf("rule %s: first match %s, candidates %v", rule, first(v), candidateNames(v))
		}
	}
}

// I4: a rule with application any is an explicit match.
func TestAnyIsExplicit(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "allow", apps("app-remote"), "")+appRule("r2", "deny", apps("any"), ""), "ssl")
	if first(v) != "r2" || len(v.Undecided) > 0 {
		t.Errorf("first match %s, undecided %v", first(v), v.Undecided)
	}
}

// I5: a deny rule never matches implicitly.
func TestADenyRuleNeverMatchesImplicitly(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "deny", apps("app-remote"), ""), "ssl")
	if first(v) != "none" || len(v.Candidates) != 0 {
		t.Errorf("first match %s, candidates %v", first(v), candidateNames(v))
	}
}

// I6: with only an implicit candidate, the implicit rule decides, not a default
// rule.
func TestImplicitBeforeTheDefaultRule(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "allow", apps("app-remote"), ""), "ssl")
	if o, why := v.Decision(); first(v) != "r1" || v.Default != "" || o != Pass {
		t.Errorf("first match %s, default %q, %s %s", first(v), v.Default, o, why.Text())
	}
}

// §4.3 item 3: an explicit rule in doubt holds back the implicit winner, unless
// both have the same action.
func TestAnExplicitDoubtHoldsBackTheImplicitWinner(t *testing.T) {
	t.Parallel()
	user := `<source-user><member>corp\alice</member></source-user>`
	_, v := appRun(t, "", appRule("r1", "deny", apps("ssl"), user)+appRule("r2", "allow", apps("app-remote"), ""), "ssl")
	if o, _ := v.Decision(); o != Undecided {
		t.Errorf("deny in doubt: %s, rule %s", o, first(v))
	}
	r, v := appRun(t, "", appRule("r1", "allow", apps("ssl"), user)+appRule("r2", "allow", apps("app-remote"), ""), "ssl")
	o, _ := v.Decision()
	if o != Pass || first(v) != "r2" || !slices.Contains(noteCodes(stage(r, "first-match").Fidelity.Reasons()), "doubt.same-action") {
		t.Errorf("allow in doubt: %s, rule %s, %s", o, first(v), stage(r, "first-match").Fidelity)
	}
}

// S9: a container in a rule matches each of its functions.
func TestAContainerMatchesItsFunctions(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "allow", apps("office-suite"), ""), "office-docs")
	if first(v) != "r1" || len(v.Undecided) > 0 {
		t.Errorf("first match %s, undecided %v", first(v), v.Undecided)
	}
}

// §4.2: a name neither the data nor the configuration holds keeps the rule in
// doubt; it never decides.
func TestAnUnknownNameStaysInDoubt(t *testing.T) {
	t.Parallel()
	r, v := appRun(t, "", appRule("r1", "deny", apps("gone-app"), "")+appRule("r2", "allow", apps("ssl"), ""), "ssl")
	if o, _ := v.Decision(); o != Undecided {
		t.Errorf("decision %s, rule %s", o, first(v))
	}
	if !slices.Contains(doubtCodesOf(v, "r1"), "doubt.application-unknown") {
		t.Errorf("doubts %s", doubtList(v))
	}
	if f := stage(r, "match-application").Fidelity; f.Level() != "overmatch" || !slices.Contains(noteCodes(f.Reasons()), "doubt.application-unknown") {
		t.Errorf("match-application = %s", f)
	}
}

// §4.2, D8: the unknown-name check covers the rule's set after the group
// closure.
func TestAnUnknownGroupMemberStaysInDoubt(t *testing.T) {
	t.Parallel()
	groups := `<application-group>` +
		`<entry name="inner"><members><member>gone-app</member></members></entry>` +
		`<entry name="outer"><members><member>inner</member></members></entry>` +
		`</application-group>`
	_, v := appRun(t, groups, appRule("r1", "deny", apps("outer"), "")+appRule("r2", "allow", apps("ssl"), ""), "ssl")
	if o, _ := v.Decision(); o != Undecided {
		t.Errorf("decision %s, rule %s", o, first(v))
	}
	if !slices.Contains(doubtCodesOf(v, "r1"), "doubt.application-unknown") {
		t.Errorf("doubts %s", doubtList(v))
	}
}

// Review focus 4: a filter whose exclude names a name the data lacks keeps the
// rule in doubt.
func TestAnUnknownExcludeKeepsTheRule(t *testing.T) {
	t.Parallel()
	filter := `<application-filter><entry name="fx"><category><member>media</member></category>` +
		`<exclude><member>gone-app</member></exclude></entry></application-filter>`
	_, v := appRun(t, filter, appRule("r1", "deny", apps("fx"), ""), "ssl")
	if !slices.Contains(candidateNames(v), "r1") || !slices.Contains(doubtCodesOf(v, "r1"), "doubt.application-unknown") {
		t.Errorf("candidates %v, doubts %s", candidateNames(v), doubtList(v))
	}
	if first(v) == "r1" {
		t.Error("the rule in doubt decides")
	}
}

// Review focus 5, I9: a content-preview name the data and the custom
// applications lack, and a container while the containers are missing, keep
// their rules in doubt.
func TestANameTheDataLacksStaysInDoubt(t *testing.T) {
	t.Parallel()
	rules := appRule("r1", "deny", apps("preview-app"), "") + appRule("r2", "deny", apps("office-suite"), "")
	e := appEnv(t, appConfig(t, "", rules), contentWithoutContainers(t))
	for _, app := range []string{"ssl", "office-docs"} {
		_, v := run(t, e, appFlow(app))
		for _, rule := range []string{"r1", "r2"} {
			if !slices.Contains(doubtCodesOf(v, rule), "doubt.application-unknown") {
				t.Errorf("%s: %s has no doubt: %s", app, rule, doubtList(v))
			}
		}
		if first(v) != "none" {
			t.Errorf("%s: a rule in doubt decides: %s", app, first(v))
		}
	}
}

// D8: a rule kept for an unknown name is an explicit candidate only, never also
// an implicit one.
func TestAKeptRuleIsNoImplicitCandidate(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "allow", apps("app-remote", "gone-app"), ""), "ssl")
	if got := candidateNames(v); !slices.Equal(got, []string{"r1"}) {
		t.Errorf("candidates %v", got)
	}
	if !slices.Equal(doubtCodesOf(v, "r1"), []reason.Code{"doubt.application-unknown"}) {
		t.Errorf("doubts %s", doubtList(v))
	}
	if v.Implicit != nil || first(v) == "r1" {
		t.Errorf("implicit %+v, first match %s", v.Implicit, first(v))
	}
}

// A rule that names an application explicitly matches it, whatever unknown
// names it also holds: those can only add applications.
func TestAnExplicitMatchNeedsNoDoubt(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "deny", apps("ssl", "gone-app"), ""), "ssl")
	if first(v) != "r1" || len(v.Undecided) > 0 || len(v.Doubts) > 0 {
		t.Errorf("first match %s, undecided %v, doubts %s", first(v), v.Undecided, doubtList(v))
	}
}

// Review focus 1: a rule exported without an application element takes the
// digest default, any.
func TestARuleWithoutApplicationTakesTheDefault(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "deny", nil, ""), "ssl")
	if first(v) != "r1" || len(v.Undecided) > 0 {
		t.Errorf("first match %s, undecided %v", first(v), v.Undecided)
	}
}

// R1: the default comes from the digest. A schema without a default for the
// field would keep such a rule in doubt; a field the digest lacks has none.
func TestARuleWithoutApplicationAndNoDefaultIsKept(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load(appConfig(t, "", appRule("r1", "deny", nil, "")))
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleDefault(cfg, "application"); got != "any" {
		t.Errorf("default %q", got)
	}
	if got := ruleDefault(cfg, "no-such-field"); got != "" {
		t.Errorf("no field: %q", got)
	}
	s := &state{rules: []resolve.Rule{{Name: "r1"}}, appDoubts: map[uint32][]reason.Reason{}}
	explicit, kept := roaring.New(), roaring.New()
	s.absentApplication("", explicit, kept)
	if !explicit.IsEmpty() || !kept.Contains(0) || len(s.appDoubts[0]) != 1 || s.appDoubts[0][0].Code != "doubt.application" {
		t.Errorf("explicit %v, kept %v, doubts %v", explicit, kept, s.appDoubts)
	}
}

// P14, D17: the flow's application matches without regard to case; the stages
// use the content name or the custom application's name as configured.
func TestTheFlowApplicationIsCanonical(t *testing.T) {
	t.Parallel()
	custom := `<application><entry name="Erp-Mixed"><category>business-systems</category>` +
		`<subcategory>erp-crm</subcategory><technology>client-server</technology><risk>2</risk>` +
		`<default><port><member>tcp/8444</member></port></default></entry></application>`
	e := appEnv(t, appConfig(t, custom, appRule("r1", "deny", apps("ssl"), "")+appRule("r2", "deny", apps("Erp-Mixed"), "")), content(t))
	for _, tc := range []struct{ app, rule, canonical string }{{"SSL", "r1", "ssl"}, {"erp-mixed", "r2", "Erp-Mixed"}} {
		r, v := run(t, e, appFlow(tc.app))
		if first(v) != tc.rule || len(v.Undecided) > 0 {
			t.Errorf("%s: first match %s, undecided %v", tc.app, first(v), v.Undecided)
		}
		if d := stage(r, "match-application").Detail; !strings.HasPrefix(d, tc.canonical+":") {
			t.Errorf("%s: detail %q", tc.app, d)
		}
		if r.Input.Flow.Application != tc.canonical {
			t.Errorf("%s: input %q", tc.app, r.Input.Flow.Application)
		}
	}
}

// P15: the flow's application can be obsolete.
func TestAnObsoleteFlowApplicationIsValid(t *testing.T) {
	t.Parallel()
	_, v := appRun(t, "", appRule("r1", "deny", apps("app-old"), ""), "app-old")
	if first(v) != "r1" {
		t.Errorf("first match %s", first(v))
	}
}

// choice runs a flow application that is no application and returns the error.
func choice(t *testing.T, app string) *simulate.ChoiceError {
	t.Helper()
	e := appEnv(t, appConfig(t, "", appRule("r1", "allow", apps("any"), "")), content(t))
	_, err := Simulation{}.Run(context.Background(), e, simulate.Input{Flow: appFlow(app), Device: "fw01", Vsys: "vsys1"})
	c, ok := errors.AsType[*simulate.ChoiceError](err)
	if !ok {
		t.Fatalf("%s: %v, want a choice", app, err)
	}
	if c.Kind != simulate.ChoiceApplication || len(c.Options) != 0 || c.Error() != c.Question {
		t.Errorf("%s: %+v", app, c)
	}
	return c
}

// suggested is the names after "nearest: " or "functions: ".
func suggested(text string) []string {
	for _, lead := range []string{"nearest: ", "functions: "} {
		if _, rest, ok := strings.Cut(text, lead); ok {
			return strings.Split(rest, ", ")
		}
	}
	return nil
}

// P10, D13: a container is no flow application; the question names its
// functions and the content version.
func TestAContainerFlowIsAChoice(t *testing.T) {
	t.Parallel()
	c := choice(t, "office-suite")
	for _, text := range []string{c.Question, c.ToolText} {
		if !strings.Contains(text, "8000-1000") || !strings.HasSuffix(text, "office-docs, office-mail") {
			t.Errorf("text %q", text)
		}
	}
}

// P10: an unknown name is no flow application; the question suggests up to five
// names, the nearest first.
func TestAnUnknownFlowIsAChoice(t *testing.T) {
	t.Parallel()
	c := choice(t, "sssl")
	for _, text := range []string{c.Question, c.ToolText} {
		got := suggested(text)
		if !strings.Contains(text, "8000-1000") || len(got) == 0 || len(got) > 5 || got[0] != "ssl" {
			t.Errorf("text %q", text)
		}
	}
	if c := choice(t, "zzzzzzzzzzzz"); suggested(c.Question) != nil {
		t.Errorf("no near name: %q", c.Question)
	}
}

// §4.1: without a flow application, the doubts and the fidelity are as without
// data.
func TestNoApplicationKeepsTodaysDoubt(t *testing.T) {
	t.Parallel()
	path := appConfig(t, "", appRule("r1", "deny", apps("ssl"), "")+appRule("r2", "allow", apps("any"), ""))
	without, vw := run(t, appEnv(t, path, nil), appFlow(""))
	with, v := run(t, appEnv(t, path, content(t)), appFlow(""))
	if doubtList(v) != doubtList(vw) || with.Fidelity.String() != without.Fidelity.String() {
		t.Errorf("with data: %s; %s\nwithout: %s; %s", doubtList(v), with.Fidelity, doubtList(vw), without.Fidelity)
	}
	if !slices.Contains(doubtCodesOf(v, "r1"), "doubt.application") || !strings.Contains(with.Fidelity.String(), "application") {
		t.Errorf("doubts %s, fidelity %s", doubtList(v), with.Fidelity)
	}
	if !v.AppData || vw.AppData {
		t.Errorf("app data %v, %v", v.AppData, vw.AppData)
	}
	if st := stage(with, "match-application"); st.Fidelity.Level() != "exact" || st.Detail != "no application given" {
		t.Errorf("stage %s %q", st.Fidelity, st.Detail)
	}
}

// §4.1: a flow application without data gives the answer without one.
func TestNoDataKeepsTodaysDoubt(t *testing.T) {
	t.Parallel()
	e := appEnv(t, appConfig(t, "", appRule("r1", "deny", apps("ssl"), "")+appRule("r2", "allow", apps("any"), "")), nil)
	without, vw := run(t, e, appFlow(""))
	with, v := run(t, e, appFlow("ssl"))
	if doubtList(v) != doubtList(vw) || with.Fidelity.String() != without.Fidelity.String() || first(v) != first(vw) {
		t.Errorf("with app: %s; %s\nwithout: %s; %s", doubtList(v), with.Fidelity, doubtList(vw), without.Fidelity)
	}
	if v.AppData || len(with.Notes) > 0 {
		t.Errorf("app data %v, notes %v", v.AppData, with.Notes)
	}
	if st := stage(with, "match-application"); st.Detail != "no application data" {
		t.Errorf("detail %q", st.Detail)
	}
}

// §4.6: an answer that evaluates the application notes the App-ID shift.
func TestEveryAppAnswerNotesTheShift(t *testing.T) {
	t.Parallel()
	r, _ := appRun(t, "", appRule("r1", "deny", apps("ssl"), ""), "ssl")
	if !slices.Contains(noteCodes(r.Notes), "note.app-shift") {
		t.Errorf("notes %v", r.Notes)
	}
}

// The target's notes stay the target's: a run appends its own notes to a copy.
func TestTheRunCopiesTheTargetNotes(t *testing.T) {
	t.Parallel()
	path := appConfig(t, "", appRule("r1", "deny", apps("ssl"), ""))
	base := appEnv(t, path, content(t))
	notes := make(simulate.Reasons, 1, 4)
	notes[0] = reason.New("note.snapshot-stale", "stale")
	e := &simulate.Env{Load: func(d, vsys string) (simulate.Target, error) {
		tg, err := base.Load(d, vsys)
		tg.Notes = notes
		return tg, err
	}}
	r, _ := run(t, e, appFlow("ssl"))
	if len(r.Notes) < 2 || notes[:cap(notes)][1].Code != "" {
		t.Errorf("run notes %v; the target's array changed", r.Notes)
	}
}

// A custom flow application whose risk cannot be read leaves the rules that
// name a filter in doubt: the filter may select it or not.
func TestAnUnreadableCustomApplicationKeepsFilterRules(t *testing.T) {
	t.Parallel()
	objects := `<application><entry name="erp-bad"><category>business-systems</category>` +
		`<subcategory>erp-crm</subcategory><technology>client-server</technology><risk>high</risk></entry></application>` +
		`<application-filter><entry name="f-low"><risk><member>1</member></risk></entry></application-filter>`
	_, v := appRun(t, objects, appRule("r1", "deny", apps("f-low"), "")+appRule("r2", "allow", apps("any"), ""), "erp-bad")
	if !slices.Contains(doubtCodesOf(v, "r1"), "doubt.application") {
		t.Errorf("doubts %s", doubtList(v))
	}
	if o, _ := v.Decision(); o != Undecided {
		t.Errorf("decision %s, rule %s", o, first(v))
	}
}
