package resolve

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/kaisero/proteus/internal/config"
)

var vsys1Scope = config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

func appidLab(t *testing.T) *config.Config {
	t.Helper()
	return loadT(t, "../../testdata/config/firewall-appid.xml")
}

// appsConfig writes a configuration with the given shared and vsys1 objects.
func appsConfig(t *testing.T, shared, vsys1 string) *config.Config {
	t.Helper()
	doc := `<config version="11.2.0" detail-version="11.2.5"><shared>` + shared + `</shared>` +
		`<devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">` + vsys1 +
		`</entry></vsys></entry></devices></config>`
	path := filepath.Join(t.TempDir(), "apps.xml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadT(t, path)
}

func appsByName(apps []Application) map[string]Application {
	out := map[string]Application{}
	for _, a := range apps {
		out[a.Name] = a
	}
	return out
}

func filtersByName(fs []ApplicationFilter) map[string]ApplicationFilter {
	out := map[string]ApplicationFilter{}
	for _, f := range fs {
		out[f.Name] = f
	}
	return out
}

// A custom application takes its default ports from its own default block
// (P7); without one it allows every protocol and port (P6). The object keeps
// its scope (R5).
func TestApplicationsReadsCustomDefaults(t *testing.T) {
	t.Parallel()
	apps := appsByName(Applications(appidLab(t), vsys1Scope))

	erp, ok := apps["erp-custom"]
	if !ok {
		t.Fatalf("erp-custom is missing: %v", apps)
	}
	if got := erp.App.Default.String(); got != "tcp/8443" {
		t.Errorf("erp-custom default = %q, want tcp/8443", got)
	}
	if !erp.App.Custom || erp.App.Name != "erp-custom" || erp.Kind != "application" {
		t.Errorf("erp-custom = %+v, want a custom application", erp)
	}
	if erp.App.Category != "business-systems" || erp.App.Subcategory != "erp-crm" ||
		erp.App.Technology != "client-server" || erp.App.Risk != 2 {
		t.Errorf("erp-custom metadata = %+v", erp.App)
	}
	if !erp.App.Flags["able-to-transfer-file"] {
		t.Errorf("erp-custom flags = %v, want able-to-transfer-file", erp.App.Flags)
	}
	if erp.Scope != vsys1Scope {
		t.Errorf("erp-custom scope = %v, want vsys1", erp.Scope)
	}
	if erp.Err != nil {
		t.Errorf("erp-custom error = %v", erp.Err)
	}
	if nd := apps["erp-nodefault"]; !nd.App.Default.None {
		t.Errorf("erp-nodefault default = %+v, want none", nd.App.Default)
	}
	shared, ok := apps["shared-media"]
	if !ok || shared.Scope.Sort != config.ScopeShared {
		t.Errorf("shared-media = %+v, want the shared application", shared)
	}
}

// A custom application refuses implicit-use-applications, as observed on
// fw02, PAN-OS 12.2.3 (spec 2026-10-16 I9): Applications never reads it.
func TestApplicationsReadNoImplicitUse(t *testing.T) {
	t.Parallel()
	cfg := appsConfig(t, "", `<application><entry name="c1"><category>media</category><risk>1</risk>`+
		`<implicit-use-applications><member>ssl</member></implicit-use-applications></entry></application>`)
	apps := appsByName(Applications(cfg, vsys1Scope))
	if got := apps["c1"].App.ImplicitUse; got != nil {
		t.Errorf("implicit use = %v, want none", got)
	}
}

// The default block of a custom application in each form the schema allows.
func TestApplicationsReadEveryDefaultForm(t *testing.T) {
	t.Parallel()
	cfg := appsConfig(t, "", `<application>`+
		`<entry name="c-ip"><risk>1</risk><description>Dummy.</description><parent-app>ssl</parent-app><evasive-behavior>no</evasive-behavior>`+
		`<default><ident-by-ip-protocol>89</ident-by-ip-protocol></default></entry>`+
		`<entry name="c-icmp"><risk>1</risk><default><ident-by-icmp-type><type>8</type></ident-by-icmp-type></default></entry>`+
		`<entry name="c-icmp6"><risk>1</risk><default><ident-by-icmp6-type><type>128</type></ident-by-icmp6-type></default></entry>`+
		`<entry name="c-bad-port"><risk>1</risk><default><port><member>tcp/x</member></port></default></entry>`+
		`<entry name="c-bad-risk"><risk>high</risk></entry>`+
		`</application>`)
	apps := appsByName(Applications(cfg, vsys1Scope))
	for name, want := range map[string]string{"c-ip": "ip-protocol/89", "c-icmp": "icmp-type", "c-icmp6": "icmp6-type"} {
		if got := apps[name].App.Default.String(); got != want || apps[name].Err != nil {
			t.Errorf("%s default = %q (%v), want %q", name, got, apps[name].Err, want)
		}
	}
	ip := apps["c-ip"].App
	if ip.Description != "Dummy." || ip.Parent != "ssl" || ip.Flags["evasive-behavior"] {
		t.Errorf("c-ip = %+v", ip)
	}
	if _, ok := ip.Flags["evasive-behavior"]; !ok {
		t.Error("a flag that holds no is present and false")
	}
	// A value the device would refuse at commit is an error, never a guess.
	for _, name := range []string{"c-bad-port", "c-bad-risk"} {
		if apps[name].Err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// The configuration matches names exactly (P14): a custom application keeps
// its configured case.
func TestApplicationsKeepTheConfiguredCase(t *testing.T) {
	t.Parallel()
	apps := appsByName(Applications(appidLab(t), vsys1Scope))
	a, ok := apps["Erp-Mixed"]
	if !ok || a.App.Name != "Erp-Mixed" {
		t.Errorf("Erp-Mixed = %+v, want its configured name", a)
	}
	if _, lower := apps["erp-mixed"]; lower {
		t.Error("the name was lowered")
	}
}

// Each field of a filter lands in Criteria by its configuration name, and the
// tags below tagging land under tag (S1-S4).
func TestApplicationFiltersReadsCriteria(t *testing.T) {
	t.Parallel()
	fs := filtersByName(ApplicationFilters(appidLab(t), vsys1Scope))
	f, ok := fs["f-risky"]
	if !ok {
		t.Fatalf("f-risky is missing: %v", fs)
	}
	want := map[string][]string{
		"category": {"media", "collaboration"},
		"risk":     {"4"},
		"evasive":  {"yes"},
		"tag":      {"[Streaming]"},
	}
	if len(f.Filter.Criteria) != len(want) {
		t.Errorf("criteria = %v, want %v", f.Filter.Criteria, want)
	}
	for k, v := range want {
		if !slices.Equal(f.Filter.Criteria[k], v) {
			t.Errorf("criteria[%s] = %v, want %v", k, f.Filter.Criteria[k], v)
		}
	}
	if !slices.Equal(f.Filter.Exclude, []string{"app-old", "office-suite"}) {
		t.Errorf("exclude = %v", f.Filter.Exclude)
	}
	if f.Filter.Name != "f-risky" || f.Kind != "application-filter" || f.Scope != vsys1Scope {
		t.Errorf("filter = %+v", f)
	}
}

// tagging no-tag yes adds no restriction (S14), so it adds nothing to the
// criteria.
func TestApplicationFiltersIgnoreNoTag(t *testing.T) {
	t.Parallel()
	f := filtersByName(ApplicationFilters(appidLab(t), vsys1Scope))["f-notag"]
	if len(f.Filter.Criteria) != 1 || !slices.Equal(f.Filter.Criteria["category"], []string{"collaboration"}) {
		t.Errorf("criteria = %v, want category only", f.Filter.Criteria)
	}
}

// A vsys filter hides a shared filter of the same name (R5), as every other
// object of a scope does.
func TestApplicationFiltersShadow(t *testing.T) {
	t.Parallel()
	cfg := appsConfig(t,
		`<application-filter><entry name="f"><category><member>media</member></category></entry>`+
			`<entry name="f-shared"><risk><member>5</member></risk></entry></application-filter>`,
		`<application-filter><entry name="f"><category><member>collaboration</member></category></entry></application-filter>`)
	fs := filtersByName(ApplicationFilters(cfg, vsys1Scope))
	f := fs["f"]
	if f.Scope != vsys1Scope || !slices.Equal(f.Filter.Criteria["category"], []string{"collaboration"}) {
		t.Errorf("f = %+v, want the vsys1 filter", f)
	}
	if f.ShadowedFrom == nil || f.ShadowedFrom.Sort != config.ScopeShared {
		t.Errorf("f.ShadowedFrom = %v, want shared", f.ShadowedFrom)
	}
	if s := fs["f-shared"]; s.Scope.Sort != config.ScopeShared {
		t.Errorf("f-shared = %+v, want the shared filter", s)
	}
	// Shared sees its own filter only.
	if got := filtersByName(ApplicationFilters(cfg, config.Scope{Sort: config.ScopeShared}))["f"]; !slices.Equal(got.Filter.Criteria["category"], []string{"media"}) {
		t.Errorf("shared f = %+v", got)
	}
}

// An application-tag entry adds its tags to the application (S12); an empty
// entry adds none. A vsys entry hides a shared one.
func TestApplicationTagsAdd(t *testing.T) {
	t.Parallel()
	tags := ApplicationTags(appidLab(t), vsys1Scope)
	if !slices.Equal(tags["app-media"], []string{"t-sanctioned"}) {
		t.Errorf("app-media tags = %v, want [t-sanctioned]", tags["app-media"])
	}
	if got, ok := tags["app-collab"]; !ok || len(got) != 0 {
		t.Errorf("app-collab tags = %v (%v), want an empty entry", got, ok)
	}

	cfg := appsConfig(t,
		`<tag><entry name="a"/><entry name="b"/></tag><application-tag><entry name="ssl"><tag><member>a</member></tag></entry></application-tag>`,
		`<application-tag><entry name="ssl"><tag><member>b</member></tag></entry></application-tag>`)
	if got := ApplicationTags(cfg, vsys1Scope)["ssl"]; !slices.Equal(got, []string{"b"}) {
		t.Errorf("ssl tags = %v, want the vsys entry [b]", got)
	}
}
