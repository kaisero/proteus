package resolve

import (
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

// A url-filtering profile carries several action lists, and which list a category
// sits in is the whole point, so it cannot be flattened to one value the way Object
// does.
func TestURLFilteringProfilesInScope(t *testing.T) {
	cfg := loadT(t, "../../testdata/config/firewall-urlprofile.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	profs := URLFilteringProfilesInScope(cfg, sc)
	if len(profs) != 1 {
		t.Fatalf("got %d profiles, want 1", len(profs))
	}
	p := profs[0]
	if p.Name != "default-url-filter" {
		t.Errorf("name = %q", p.Name)
	}
	if got := p.Lists["alert"]; len(got) != 1 || got[0] != "demo-category" {
		t.Errorf("alert list = %v, want [demo-category]", got)
	}
	if got := p.Lists["block"]; len(got) != 1 || got[0] != "malware" {
		t.Errorf("block list = %v, want [malware]", got)
	}
	if p.Scope != sc {
		t.Errorf("scope = %s, want %s", p.Scope, sc)
	}
}

// A profile group names profiles by kind, and that is the other way a rule reaches a
// url-filtering profile.
func TestProfileGroupsInScope(t *testing.T) {
	cfg := loadT(t, "../../testdata/config/firewall-urlprofile.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	groups := ProfileGroupsInScope(cfg, sc)
	if len(groups) != 1 || groups[0].Name != "default" {
		t.Fatalf("got %+v, want one group named default", groups)
	}
	if got := groups[0].Kinds["url-filtering"]; len(got) != 1 || got[0] != "default-url-filter" {
		t.Errorf("url-filtering = %v, want [default-url-filter]", got)
	}
	if got := groups[0].Kinds["virus"]; len(got) != 1 {
		t.Errorf("other kinds are read too, got %v", got)
	}
}

// A scope with none of a kind yields none, not an error.
func TestProfileReadersOnAConfigurationWithNoProfiles(t *testing.T) {
	cfg := loadT(t, "../../testdata/config/firewall-urlcat.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	profs := URLFilteringProfilesInScope(cfg, sc)
	if len(profs) != 0 {
		t.Errorf("got %d profiles, want none", len(profs))
	}
	groups := ProfileGroupsInScope(cfg, sc)
	if len(groups) != 0 {
		t.Errorf("got %d groups, want none", len(groups))
	}
}

// A rule's profile setting is read both ways PAN-OS writes it, and it is not a
// matching field.
func TestRulesReadProfileSettings(t *testing.T) {
	cfg := loadT(t, "../../testdata/config/firewall-urlprofile.xml")
	tgs := Targets(cfg)
	rules := tgs[0].Rules(Security)
	byName := map[string]Rule{}
	for _, r := range rules {
		byName[r.Name] = r
	}
	if got := byName["via-group"].ProfileGroups; len(got) != 1 || got[0] != "default" {
		t.Errorf("via-group profile groups = %v, want [default]", got)
	}
	if got := byName["via-named-profile"].Profiles["url-filtering"]; len(got) != 1 {
		t.Errorf("via-named-profile url-filtering = %v, want one profile", got)
	}
	if got := byName["no-profile"].ProfileGroups; len(got) != 0 {
		t.Errorf("no-profile should have no profile group, got %v", got)
	}
}

// Shared profiles are visible in a vsys, and a vsys's own definition replaces a
// shared one of the same name.
func TestURLFilteringProfilesShadowShared(t *testing.T) {
	cfg := loadT(t, "../../testdata/config/firewall-urlprofile-shadow.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}

	profs := URLFilteringProfilesInScope(cfg, sc)
	got := map[string]URLFilteringProfile{}
	for _, p := range profs {
		got[p.Name] = p
	}
	shared, ok := got["shared-filter"]
	if !ok {
		t.Fatal("a shared profile is not visible in the vsys")
	}
	if shared.Scope.Sort != config.ScopeShared {
		t.Errorf("shared-filter scope = %s, want shared", shared.Scope)
	}
	overridden, ok := got["both-filter"]
	if !ok {
		t.Fatal("the overridden profile is missing")
	}
	if overridden.Scope.Sort != config.ScopeVsys {
		t.Errorf("both-filter scope = %s, want the vsys to win", overridden.Scope)
	}
	if list := overridden.Lists["block"]; len(list) != 1 || list[0] != "vsys-category" {
		t.Errorf("both-filter block list = %v, want the vsys definition", list)
	}
}
