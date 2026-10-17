package appid_test

import (
	"slices"
	"testing"

	"github.com/okaiser/proteus/internal/appid"
)

// selected returns the names of the fixture applications that f selects, by
// name.
func selected(d *appid.Data, f appid.Filter) []string {
	var out []string
	for _, a := range d.Apps() {
		if f.Selects(a).Selected {
			out = append(out, a.Name)
		}
	}
	return out
}

// filter is a filter of the given criteria, field then members.
func filter(criteria map[string][]string, exclude ...string) appid.Filter {
	return appid.Filter{Name: "f", Criteria: criteria, Exclude: exclude}
}

// expectSelected fails when f does not select exactly want in the fixture.
func expectSelected(t *testing.T, d *appid.Data, f appid.Filter, want ...string) {
	t.Helper()
	if got := selected(d, f); !slices.Equal(got, want) {
		t.Errorf("%v exclude %v selects %v, want %v", f.Criteria, f.Exclude, got, want)
	}
}

// S1: values in one field combine with OR for category, subcategory,
// technology and risk.
func TestFilterValuesInOneFieldCombineWithOr(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"category": {"collaboration", "media"}}),
		"app-collab", "app-media", "app-old", "office-docs", "office-mail")
	expectSelected(t, d, filter(map[string][]string{"subcategory": {"sub-b", "sub-a"}}),
		"app-collab", "app-media", "app-old")
	expectSelected(t, d, filter(map[string][]string{"technology": {"tech-a", "tech-b"}}),
		"app-collab", "app-media", "app-old")
	for _, a := range []string{"app-media", "app-collab"} {
		app, _ := d.App(a)
		if !filter(map[string][]string{"risk": {"2", "4"}}).Selects(app).Selected {
			t.Errorf("risk [2 4] does not select %s", a)
		}
	}
	ospf, _ := d.App("ospf") // risk 2
	if !filter(map[string][]string{"risk": {"4", "2"}}).Selects(ospf).Selected {
		t.Error("risk [4 2] does not select ospf")
	}
	if filter(map[string][]string{"risk": {"3", "5"}}).Selects(ospf).Selected {
		t.Error("risk [3 5] selects ospf")
	}
}

// S2: different fields combine with AND.
func TestFilterFieldsCombineWithAnd(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"category": {"general-internet"}, "risk": {"5"}}))
	expectSelected(t, d, filter(map[string][]string{"category": {"media"}, "risk": {"4"}}), "app-media")
}

// S3, F9: tags combine with AND and match verbatim, brackets included.
func TestFilterTagsCombineWithAnd(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"tag": {"[Web App]", "[Streaming]"}}), "app-media")
	expectSelected(t, d, filter(map[string][]string{"tag": {"[Web App]", "[Other]"}}))
	expectSelected(t, d, filter(map[string][]string{"tag": {"Web App"}}))
	expectSelected(t, d, filter(map[string][]string{"tag": {"[Web App]"}}), "app-collab", "app-media")
	// S10 names the field tagging, as the command line shows it; FilterField
	// maps both names to the application's tags.
	expectSelected(t, d, filter(map[string][]string{"tagging": {"[Streaming]"}}), "app-media")
}

// S14: no-tag adds no restriction.
func TestFilterNoTagAddsNoRestriction(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	with := filter(map[string][]string{"category": {"media"}, "no-tag": {"yes"}})
	expectSelected(t, d, with, selected(d, filter(map[string][]string{"category": {"media"}}))...)
}

// S12: the tags that application-tag adds count, with AND. The caller adds
// them to the application's tags.
func TestFilterConfiguredTagsCount(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	collab, _ := d.App("app-collab")
	f := filter(map[string][]string{"tag": {"[Web App]", "t-sanctioned"}})
	if f.Selects(collab).Selected {
		t.Error("the filter selects app-collab without the added tag")
	}
	tagged := collab
	tagged.Tags = append(slices.Clone(collab.Tags), "t-sanctioned")
	if !f.Selects(tagged).Selected {
		t.Error("the filter does not select app-collab with the added tag")
	}
}

// S4: exclude removes the named applications.
func TestFilterExcludeRemovesApps(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"category": {"media"}}, "app-media"), "app-old")
	media, _ := d.App("app-media")
	if s := filter(map[string][]string{"category": {"media"}}, "app-media").Selects(media); s.Selected || s.Via != "" {
		t.Errorf("an excluded application gives %+v", s)
	}
}

// S13, F15: exclude can name a container and then removes every function.
func TestFilterExcludeExpandsAContainer(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"category": {"collaboration"}}, "office-suite"), "app-collab")
	expectSelected(t, d, filter(map[string][]string{"category": {"collaboration"}}),
		"app-collab", "office-docs", "office-mail")
}

// S5: a filter selects the custom applications that meet its criteria.
func TestFilterSelectsCustomApps(t *testing.T) {
	t.Parallel()
	custom := appid.App{Name: "erp-custom", Custom: true, Category: "media", Risk: 4}
	f := filter(map[string][]string{"category": {"media"}, "risk": {"4"}})
	if s := f.Selects(custom); !s.Selected || s.Via != "category=media, risk=4" {
		t.Errorf("custom application: %+v", s)
	}
	if filter(map[string][]string{"evasive": {"yes"}}).Selects(custom).Selected {
		t.Error("a custom application without flags is evasive")
	}
}

// S6, S11: saas-risk reads the yes children of the saas block, with AND.
func TestFilterSaaSRiskCombinesWithAnd(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"saas-risk": {"is-data-breaches"}}), "app-saas-a")
	expectSelected(t, d, filter(map[string][]string{"saas-risk": {"is-data-breaches", "is-poor-terms-of-service"}}),
		"app-saas-a")
	expectSelected(t, d, filter(map[string][]string{"saas-risk": {"is-data-breaches", "is-ip-based-restrictions"}}))
}

// S6, S11, F17: saas-certifications reads the yes children of
// saas/certifications, with AND; no-certifications selects the SaaS
// applications with a saas block and no certification. An application with
// is-saas yes and no saas block is not selected: as observed on fw02,
// PAN-OS 12.2.3, content 9160-10295 (docs/lab/app-id-lab.md, F17 cases).
func TestFilterSaaSCertificationsCombineWithAnd(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"saas-certifications": {"is-soc2"}}), "app-saas-a")
	expectSelected(t, d, filter(map[string][]string{"saas-certifications": {"is-soc1", "is-soc2"}}))
	expectSelected(t, d, filter(map[string][]string{"saas-certifications": {"no-certifications"}}),
		"app-saas-b")
	f := filter(map[string][]string{"saas-certifications": {"no-certifications"}})
	if f.Selects(appid.App{Name: "c", Custom: true}).Selected {
		t.Error("no-certifications selects an application that is no SaaS")
	}
}

// S7: new-appid yes selects the applications with new-appid.
func TestFilterNewAppID(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"new-appid": {"yes"}}), "app-new")
}

// S15: a filter selects obsolete applications as any other.
func TestFilterSelectsObsoleteApps(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"category": {"media"}}), "app-media", "app-old")
}

// S10: a filter field reads its application field.
func TestFilterFieldNames(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for field, want := range map[string][]string{
		"evasive":                   {"app-media"},
		"excessive-bandwidth-use":   {"app-media"},
		"transfers-files":           {"app-media", "ssl", "web-browsing"},
		"has-known-vulnerabilities": {"app-collab", "ssl", "web-browsing"},
		"tunnels-other-apps":        {"app-collab", "ssl"},
		"pervasive":                 {"app-collab", "ssl", "web-browsing"},
		"used-by-malware":           {"app-collab", "ssl", "web-browsing"},
		"prone-to-misuse":           {"app-collab"},
		"is-saas":                   {"app-saas-a", "app-saas-b", "app-saas-c"},
	} {
		expectSelected(t, d, filter(map[string][]string{field: {"yes"}}), want...)
	}
	// The application field is no filter field: it selects nothing.
	expectSelected(t, d, filter(map[string][]string{"evasive-behavior": {"yes"}}))
	expectSelected(t, d, filter(map[string][]string{"tagging": {"[Streaming]"}}), "app-media")
}

// Spec 2026-10-16 §5.1: Via names the matching fields in schema field order.
func TestFilterVia(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	media, _ := d.App("app-media")
	f := filter(map[string][]string{"risk": {"2", "4"}, "category": {"collaboration", "media"}})
	if s := f.Selects(media); !s.Selected || s.Via != "category=media, risk=4" {
		t.Errorf("app-media: %+v", s)
	}
	f = filter(map[string][]string{
		"tag": {"[Web App]", "[Streaming]"}, "evasive": {"yes"}, "no-tag": {"yes"}, "technology": {"tech-a"},
	})
	if s := f.Selects(media); !s.Selected || s.Via != "technology=tech-a, evasive=yes, tag=[Web App],[Streaming]" {
		t.Errorf("app-media: %+v", s)
	}
	saas, _ := d.App("app-saas-a")
	f = filter(map[string][]string{"saas-risk": {"is-data-breaches"}, "saas-certifications": {"is-soc2"}})
	if s := f.Selects(saas); !s.Selected || s.Via != "saas-certifications=is-soc2, saas-risk=is-data-breaches" {
		t.Errorf("app-saas-a: %+v", s)
	}
	if s := filter(map[string][]string{"category": {"collaboration"}}).Selects(media); s.Selected || s.Via != "" {
		t.Errorf("a filter that does not select gives %+v", s)
	}
}

// A field the package cannot read selects nothing; an empty member list in a
// known field selects nothing either.
func TestFilterUnreadableCriteria(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	expectSelected(t, d, filter(map[string][]string{"no-such-field": {"x"}}))
	expectSelected(t, d, filter(map[string][]string{"category": nil}))
	expectSelected(t, d, filter(map[string][]string{"evasive": {"no"}}))
}
