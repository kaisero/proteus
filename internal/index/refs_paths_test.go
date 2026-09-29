package index

import (
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

func refpathsIndex(t *testing.T) (*config.Config, *Index) {
	t.Helper()
	cfg, _, err := config.Load("../../testdata/config/firewall-refpaths.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, idx
}

// The question this started from: which rules reach a profile group, a named
// security profile and a log-forwarding profile. Every one of these answered
// "nothing references it" before the walk saw more than one reference shape.
func TestRefsReachesProfileAndScalarEdges(t *testing.T) {
	_, idx := refpathsIndex(t)
	for _, tc := range []struct {
		name, field string
		want        []string
	}{
		{"baseline", "profile-setting/group", []string{"by-group"}},
		{"strict-url", "profile-setting/profiles/url-filtering", []string{"by-profiles"}},
		{"no-exe", "profile-setting/profiles/file-blocking", []string{"by-profiles"}},
		{"to-siem", "log-setting", []string{"by-group", "by-profiles"}},
		{"off-hours", "schedule", []string{"by-profiles"}},
		{"edge", "group-tag", []string{"by-profiles"}},
	} {
		var got []string
		for _, r := range idx.Refs(tc.name) {
			if r.Field == tc.field && strings.Contains(r.From, "/security/rules/") {
				got = append(got, path.Base(r.From))
			}
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("Refs(%q) at %s = %v, want %v", tc.name, tc.field, got, tc.want)
		}
	}
}

// A field's candidates are now the ones the schema declares for that leaf, not
// the union of everything below the top-level field. profile-setting used to
// merge a profile group with all ten profile kinds.
func TestRefsCandidatesArePerLeaf(t *testing.T) {
	_, idx := refpathsIndex(t)
	for _, r := range idx.Refs("baseline") {
		if r.Field != "profile-setting/group" {
			continue
		}
		if len(r.Candidates) != 1 || r.Candidates[0] != "profile-group" {
			t.Errorf("candidates for profile-setting/group = %v, want [profile-group]", r.Candidates)
		}
		return
	}
	t.Error("no edge at profile-setting/group")
}

// resolve reads a rule's profile setting by hand; the walk derives it from the
// schema. They must agree, because they are two readers of the same XML and it
// was their silent disagreement that hid the missing edges for so long.
func TestRefsAgreeWithResolveOnProfileEdges(t *testing.T) {
	_, idx := refpathsIndex(t)
	rules := idx.Rules()

	type link struct{ rule, field, target string }
	want := map[link]bool{}
	for _, r := range rules {
		for _, g := range r.ProfileGroups {
			want[link{r.Name, "profile-setting/group", g}] = true
		}
		for kind, names := range r.Profiles {
			for _, n := range names {
				want[link{r.Name, "profile-setting/profiles/" + kind, n}] = true
			}
		}
	}
	if len(want) == 0 {
		t.Fatal("the fixture must hold profile edges for this to mean anything")
	}

	got := map[link]bool{}
	for _, r := range rules {
		for _, g := range append(append([]string{}, r.ProfileGroups...), flatten(r.Profiles)...) {
			for _, ref := range idx.Refs(g) {
				if !strings.HasSuffix(ref.From, "/"+r.Name) ||
					!strings.HasPrefix(ref.Field, "profile-setting/") {
					continue
				}
				got[link{r.Name, ref.Field, ref.Target}] = true
			}
		}
	}
	for l := range want {
		if !got[l] {
			t.Errorf("resolve has %+v, Refs does not", l)
		}
	}
	for l := range got {
		if !want[l] {
			t.Errorf("Refs has %+v, resolve does not", l)
		}
	}
}

func flatten(m map[string][]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v...)
	}
	return out
}
