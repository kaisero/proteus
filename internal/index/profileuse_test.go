package index

import "testing"

// The fixture mirrors how a real lab firewall is configured: every rule has
// "category any" and all URL policy runs through profile settings, four rules by
// profile group and one naming the profile directly. A category-field-only answer
// reports nothing about any of them.
func TestProfileUsesFindsBothPathsByCategoryName(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlprofile.xml", "vsys1")

	uses := idx.ProfileUses("demo-category")
	if len(uses) != 2 {
		t.Fatalf("got %d profile paths, want 2: %+v", len(uses), uses)
	}
	byRule := map[string]ProfileUse{}
	for _, u := range uses {
		byRule[u.Rule] = u
	}

	viaGroup, ok := byRule["via-group"]
	if !ok {
		t.Fatal("the rule reaching the profile through a profile group was not found")
	}
	if viaGroup.Group != "default" || viaGroup.Profile != "default-url-filter" {
		t.Errorf("group path = %+v", viaGroup)
	}
	if viaGroup.List != "alert" {
		t.Errorf("list = %q, want alert", viaGroup.List)
	}

	direct, ok := byRule["via-named-profile"]
	if !ok {
		t.Fatal("the rule naming the profile directly was not found")
	}
	if direct.Group != "" {
		t.Errorf("a directly named profile should report no group, got %q", direct.Group)
	}

	if _, unwanted := byRule["no-profile"]; unwanted {
		t.Error("a rule with no profile setting reached the category")
	}
}

// A URL reaches the profile path through the category covering it, and the path
// reports which member matched.
func TestProfileUsesFindsPathsByURL(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlprofile.xml", "vsys1")

	for url, wantVia := range map[string]string{
		"example.com/this/is/a/very/long/url/i/need/to/match": "example.com/this/is/a/very/long/url/i/need/to/match",
		"x.flagged.example.com":                               "*.flagged.example.com",
	} {
		uses := idx.ProfileUses(url)
		if len(uses) != 2 {
			t.Errorf("%s gave %d paths, want 2", url, len(uses))
			continue
		}
		for _, u := range uses {
			if u.Via != wantVia {
				t.Errorf("%s Via = %q, want %q", url, u.Via, wantVia)
			}
			if u.Category != "demo-category" {
				t.Errorf("%s category = %q", url, u.Category)
			}
		}
	}
}

// A URL no category covers reaches no profile.
func TestProfileUsesIgnoresAnUnrelatedURL(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlprofile.xml", "vsys1")

	if uses := idx.ProfileUses("unrelated.example.org"); len(uses) != 0 {
		t.Errorf("got %d paths, want none: %+v", len(uses), uses)
	}
}

// A profile path is not a match. The rules above have "category any", so they match
// every URL anyway; what the profile then does is not modelled, and the rule bitmaps
// must not gain entries from a profile.
func TestProfileUsesDoNotChangeMatching(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlprofile.xml", "vsys1")

	// no-profile has category any, so it matches; it has no profile path.
	rules, _ := idx.Candidates(Category, "x.flagged.example.com")
	if !ruleNames(idx, rules)["no-profile"] {
		t.Error("a rule whose category is any should match every URL")
	}
}

// A keyword in an action list is not a category.
func TestProfileUsesSkipsKeywords(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlprofile.xml", "vsys1")

	if uses := idx.ProfileUses("any"); len(uses) != 0 {
		t.Errorf("the allow list holds \"any\", which is not a category: %+v", uses)
	}
}
