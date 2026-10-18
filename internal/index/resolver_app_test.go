package index

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/testconfig"
)

func appsIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-apps.xml", "vsys1")
}

// A custom application is in the file, and the group holding it resolves through the
// ordinary group closure, so naming the application reaches the rule naming the group.
func TestAppResolverFindsACustomApplicationThroughItsGroup(t *testing.T) {
	t.Parallel()
	idx := appsIndex(t)

	rules, rep := idx.Candidates(Application, "custom-erp")
	if !ruleNames(idx, rules)["erp-allow"] {
		t.Error("a custom application did not reach the rule naming its group")
	}
	var found bool
	for _, h := range rep.Hits {
		if h.Name == "custom-erp" && h.Kind == kindApplication {
			found = true
		}
	}
	if !found {
		t.Errorf("the custom application was not reported as a hit: %+v", rep.Hits)
	}
}

// A predefined application is not in the file, but its name is still a name: a rule
// naming it is found through the ordinary name path.
func TestAppResolverFindsAPredefinedApplicationByName(t *testing.T) {
	t.Parallel()
	idx := appsIndex(t)

	rules, _ := idx.Candidates(Application, "ssl")
	if !ruleNames(idx, rules)["erp-allow"] {
		t.Error("a predefined application named in a group did not reach the rule")
	}
}

// An application filter selects predefined applications by metadata that lives in the
// content database, so its membership is reported rather than guessed. The rule using it
// is therefore never reported as a match for a specific application.
func TestAppResolverReportsAnApplicationFilter(t *testing.T) {
	t.Parallel()
	idx := appsIndex(t)

	rules, rep := idx.Candidates(Application, "custom-erp")

	var told bool
	for _, u := range rep.Unresolved {
		if u.Value == "high-risk-filter" {
			told = true
			if !strings.Contains(u.Reason, "content database") {
				t.Errorf("reason does not explain why: %q", u.Reason)
			}
		}
	}
	if !told {
		t.Errorf("the application filter was not reported: %v", rep.Unresolved)
	}
	// It is reported, not matched.
	if ruleNames(idx, rules)["risk-deny"] {
		t.Error("a rule using an application filter was reported as a match")
	}
}

// An application container groups predefined applications, and its members are in the
// content database too.
func TestAppResolverReportsAnApplicationContainer(t *testing.T) {
	t.Parallel()
	idx := appsIndex(t)

	_, rep := idx.Candidates(Application, "custom-erp")
	var told bool
	for _, u := range rep.Unresolved {
		if u.Value == "ms-office-bundle" && u.Kind == "application-container" {
			told = true
		}
	}
	if !told {
		t.Errorf("the application container was not reported: %v", rep.Unresolved)
	}
}

// Searching finds a custom application by a fragment of its name.
func TestAppResolverSearch(t *testing.T) {
	t.Parallel()
	idx := appsIndex(t)

	var found bool
	for _, h := range idx.SearchValues("erp") {
		if h.Kind == kindApplication {
			found = true
		}
	}
	if !found {
		t.Errorf("searching did not find the custom application")
	}
}

// A value that plainly belongs to another value space is not treated as an application.
func TestAppResolverIgnoresOtherShapes(t *testing.T) {
	t.Parallel()
	idx := appsIndex(t)

	for _, q := range []string{"10.0.0.0/8", "example.com/x", "a b"} {
		_, rep := idx.Candidates(Application, q)
		for _, h := range rep.Hits {
			if h.Kind == kindApplication {
				t.Errorf("%s was reported as an application: %+v", q, h)
			}
		}
	}
}

// appData loads testdata/appid/content.xml, content version 8000-1000.
func appData(t *testing.T) *appid.Data {
	t.Helper()
	path := filepath.Join(t.TempDir(), "apps.xml.gz")
	testconfig.Content(t, path)
	d, err := appid.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// appDataWithoutContainers is the fixture data as a file that records that
// the device did not answer the containers (spec 2026-10-16 §2.2).
func appDataWithoutContainers(t *testing.T) *appid.Data {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/appid/content.xml")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(raw), `trim="1"`, `trim="1" containers="missing"`, 1)
	// The container list is the last child; an application entry names its
	// container too.
	doc = doc[:strings.LastIndex(doc, "<application-container>")] + "</content>\n"
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(doc)); err != nil {
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
		t.Fatal("the data holds the containers")
	}
	return d
}

func appidIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-appid.xml", "vsys1")
}

// hitOf returns the hit of a kind and name, and whether there is one.
func hitOf(rep Report, kind, name string) (Hit, bool) {
	for _, h := range rep.Hits {
		if h.Kind == kind && h.Name == name {
			return h, true
		}
	}
	return Hit{}, false
}

func codesOf(rep Report) map[string]bool {
	out := map[string]bool{}
	for _, u := range rep.Unresolved {
		out[string(u.Code)] = true
	}
	return out
}

// With the content data, a filter answers for an application: a rule that
// names a filter selecting it is a candidate, and the hit says why (S1, §5.1).
func TestAppResolverWithDataFindsFilters(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	view := idx.With(Providers{Apps: appData(t)})
	rules, rep := view.Candidates(Application, "app-media")

	if !ruleNames(idx, rules)["allow-media"] {
		t.Errorf("app-media did not reach allow-media: %v", ruleNames(idx, rules))
	}
	h, ok := hitOf(rep, "application-filter", "f-media")
	if !ok || h.Via != "category=media" || h.Scope != vsys1 {
		t.Errorf("f-media hit = %+v (%v), want Via category=media in vsys1", h, ok)
	}
	p, ok := hitOf(rep, kindApplication, "app-media")
	if !ok || p.Via != "predefined" || p.Scope.Sort != config.ScopePredefined {
		t.Errorf("app-media hit = %+v (%v), want a predefined application", p, ok)
	}
	// With data the resolver answers filters and containers: no gap.
	if codes := codesOf(rep); codes["gap.application-filter"] || codes["gap.application-container"] {
		t.Errorf("gaps with data: %v", rep.Unresolved)
	}
	// f-risky needs evasive, risk 4 and the tag [Streaming]: app-media has them.
	if !ruleNames(idx, rules)["deny-risky"] {
		t.Error("app-media did not reach deny-risky")
	}
	// The flow's application matches in any case (P14); the hit names the
	// content name.
	if _, rep := view.Candidates(Application, "APP-MEDIA"); func() bool { _, ok := hitOf(rep, kindApplication, "app-media"); return !ok }() {
		t.Errorf("APP-MEDIA hits = %+v, want app-media", rep.Hits)
	}
}

// exclude removes an application from a filter (S4); a filter selects an
// obsolete application as any other (S15).
func TestAppResolverExclude(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	_, rep := idx.With(Providers{Apps: appData(t)}).Candidates(Application, "app-old")
	if _, ok := hitOf(rep, "application-filter", "f-risky"); ok {
		t.Error("f-risky excludes app-old, but selected it")
	}
	if _, ok := hitOf(rep, "application-filter", "f-media"); !ok {
		t.Error("f-media does not select the obsolete app-old")
	}
}

// An application-tag entry adds its tags (S12): a filter that needs a
// predefined and a configured tag selects the application. An empty entry
// keeps the predefined tags.
func TestApplicationTagsAdd(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	view := idx.With(Providers{Apps: appData(t)})

	rules, _ := view.Candidates(Application, "app-media")
	if !ruleNames(idx, rules)["allow-tagged"] {
		t.Error("app-media with the configured tag t-sanctioned did not reach allow-tagged")
	}
	rules, _ = view.Candidates(Application, "app-collab")
	names := ruleNames(idx, rules)
	if !names["allow-webapp"] {
		t.Error("the empty application-tag entry of app-collab removed its tag [Web App]")
	}
	if names["allow-tagged"] {
		t.Error("app-collab has no tag t-sanctioned, but reached allow-tagged")
	}
}

// A group can hold a filter and other groups, and resolves to the union (S8).
func TestAppResolverGroupHoldsAFilter(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	rules, rep := idx.With(Providers{Apps: appData(t)}).Candidates(Application, "app-media")
	if !ruleNames(idx, rules)["allow-outer"] {
		t.Errorf("app-media did not reach allow-outer through outer > inner > f-media: %v", ruleNames(idx, rules))
	}
	if !slices.Contains(rep.Groups, "outer") || !slices.Contains(rep.Groups, "inner") {
		t.Errorf("groups = %v, want inner and outer", rep.Groups)
	}
}

// A container in a rule matches each of its functions (S9).
func TestAppResolverContainers(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	rules, rep := idx.With(Providers{Apps: appData(t)}).Candidates(Application, "office-docs")
	if !ruleNames(idx, rules)["allow-office"] {
		t.Errorf("office-docs did not reach allow-office: %v", ruleNames(idx, rules))
	}
	h, ok := hitOf(rep, "application-container", "office-suite")
	if !ok || h.Via != "holds office-docs" || h.Scope.Sort != config.ScopePredefined {
		t.Errorf("office-suite hit = %+v (%v)", h, ok)
	}
}

// A filter includes the custom applications that meet its criteria (S5).
func TestAppResolverCustomInFilter(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	view := idx.With(Providers{Apps: appData(t)})
	rules, rep := view.Candidates(Application, "shared-media")
	if !ruleNames(idx, rules)["allow-media"] {
		t.Errorf("the custom shared-media did not reach allow-media: %v", ruleNames(idx, rules))
	}
	if _, ok := hitOf(rep, "application-filter", "f-media"); !ok {
		t.Errorf("hits = %+v, want f-media", rep.Hits)
	}
	// erp-custom meets no filter and is in no container.
	if _, rep := view.Candidates(Application, "erp-custom"); len(rep.Hits) != 1 {
		t.Errorf("erp-custom hits = %+v, want the application only", rep.Hits)
	}
}

// Hits keep the scope that defines the object (R5).
func TestAppResolverHitsKeepTheScope(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	_, rep := idx.With(Providers{Apps: appData(t)}).Candidates(Application, "shared-media")
	a, ok := hitOf(rep, kindApplication, "shared-media")
	if !ok || a.Scope.Sort != config.ScopeShared || a.Via != "shared-media" {
		t.Errorf("shared-media hit = %+v (%v), want scope shared", a, ok)
	}
	f, ok := hitOf(rep, "application-filter", "f-media")
	if !ok || f.Scope != vsys1 {
		t.Errorf("f-media hit = %+v (%v), want scope vsys1", f, ok)
	}
}

// Without the data, the resolver reports filters and containers as before
// (spec 2026-10-16 §4.8).
func TestAppResolverWithoutDataKeepsGaps(t *testing.T) {
	t.Parallel()
	idx := appsIndex(t)
	_, rep := idx.Candidates(Application, "ssl")
	codes := codesOf(rep)
	if !codes["gap.application-filter"] || !codes["gap.application-container"] {
		t.Errorf("unresolved = %v, want both gaps", rep.Unresolved)
	}
	if _, ok := hitOf(rep, kindApplication, "ssl"); ok {
		t.Error("without data, ssl is no hit")
	}
	// With data the same configuration has neither gap.
	_, rep = idx.With(Providers{Apps: appData(t)}).Candidates(Application, "ssl")
	if codes := codesOf(rep); codes["gap.application-filter"] || codes["gap.application-container"] {
		t.Errorf("unresolved with data = %v", rep.Unresolved)
	}
}

// Data without the containers keeps gap.application-container (spec
// 2026-10-16 §2.2), and still answers the filters.
func TestAppResolverNoContainerDataKeepsTheGap(t *testing.T) {
	t.Parallel()
	idx := appsIndex(t)
	_, rep := idx.With(Providers{Apps: appDataWithoutContainers(t)}).Candidates(Application, "ssl")
	codes := codesOf(rep)
	if !codes["gap.application-container"] || codes["gap.application-filter"] {
		t.Errorf("unresolved = %v, want the container gap only", rep.Unresolved)
	}
	idx = appidIndex(t)
	_, rep = idx.With(Providers{Apps: appDataWithoutContainers(t)}).Candidates(Application, "office-docs")
	if _, ok := hitOf(rep, "application-container", "office-suite"); ok {
		t.Error("a container hit without container data")
	}
}

// A name that is neither in the data nor in the configuration has no hit,
// and no filter selects it.
func TestAppResolverUnknownName(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	rules, rep := idx.With(Providers{Apps: appData(t)}).Candidates(Application, "no-such-app")
	if len(rep.Hits) != 0 || ruleNames(idx, rules)["allow-media"] {
		t.Errorf("hits = %+v, rules = %v", rep.Hits, ruleNames(idx, rules))
	}
}

// Two vsys with one filter name and different criteria answer differently
// (R5, R10).
func TestScopedFilters(t *testing.T) {
	t.Parallel()
	entry := func(vsys, category string) string {
		return `<entry name="` + vsys + `"><application-filter><entry name="f-x"><category><member>` + category +
			`</member></category></entry></application-filter><rulebase><security><rules>` +
			`<entry name="r-` + vsys + `"><source><member>any</member></source><destination><member>any</member></destination>` +
			`<application><member>f-x</member></application><action>allow</action></entry>` +
			`</rules></security></rulebase></entry>`
	}
	doc := `<config version="11.2.0" detail-version="11.2.5"><shared/><devices><entry name="localhost.localdomain"><vsys>` +
		entry("vsys1", "media") + entry("vsys2", "collaboration") + `</vsys></entry></devices></config>`
	path := filepath.Join(t.TempDir(), "scoped.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	data := appData(t)
	for _, tc := range []struct {
		vsys, rule string
		media      bool
	}{{"vsys1", "r-vsys1", true}, {"vsys2", "r-vsys2", false}} {
		idx := indexOf(t, path, tc.vsys)
		rules, rep := idx.With(Providers{Apps: data}).Candidates(Application, "app-media")
		if got := ruleNames(idx, rules)[tc.rule]; got != tc.media {
			t.Errorf("%s: app-media reaches %s = %v, want %v", tc.vsys, tc.rule, got, tc.media)
		}
		h, ok := hitOf(rep, "application-filter", "f-x")
		if ok != tc.media || ok && h.Scope.Name != tc.vsys {
			t.Errorf("%s: f-x hit = %+v (%v)", tc.vsys, h, ok)
		}
	}
}

// GroupPath gives the shortest chain from a group to a member (§5.1).
func TestGroupPath(t *testing.T) {
	t.Parallel()
	idx := appidIndex(t)
	for _, tc := range []struct {
		kind, group, name string
		want              []string
	}{
		{"application-group", "outer", "ssl", []string{"outer", "inner", "ssl"}},
		{"application-group", "inner", "f-media", []string{"inner", "f-media"}},
		{"application-group", "inner", "outer", nil},
		{"application-group", "outer", "no-such-app", nil},
		{"application-group", "outer", "outer", nil},
		{"no-such-kind", "outer", "ssl", nil},
	} {
		if got := idx.GroupPath(tc.kind, tc.group, tc.name); !slices.Equal(got, tc.want) {
			t.Errorf("GroupPath(%s, %s, %s) = %v, want %v", tc.kind, tc.group, tc.name, got, tc.want)
		}
	}

	// Two chains reach ssl, and g2 holds it on both: the walk meets g2 twice
	// and keeps the first, shortest chain.
	doc := `<config version="11.2.0" detail-version="11.2.5"><shared/><devices><entry name="localhost.localdomain">` +
		`<vsys><entry name="vsys1"><application-group>` +
		`<entry name="g1"><members><member>ssl</member></members></entry>` +
		`<entry name="g2"><members><member>ssl</member><member>g1</member></members></entry>` +
		`<entry name="g3"><members><member>g1</member><member>g2</member></members></entry>` +
		`</application-group></entry></vsys></entry></devices></config>`
	path := filepath.Join(t.TempDir(), "diamond.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := indexOf(t, path, "vsys1").GroupPath("application-group", "g3", "ssl"); !slices.Equal(got, []string{"g3", "g1", "ssl"}) {
		t.Errorf("GroupPath(g3, ssl) = %v, want [g3 g1 ssl]", got)
	}
}
