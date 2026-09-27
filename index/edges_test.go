package index

import (
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/config"
)

func siblingIndex(t *testing.T, vsys string) *Index {
	t.Helper()
	return indexOf(t, "../testdata/config/firewall-siblings.xml", vsys)
}

// R10. The edge list spans the file, so this is the test that the indexes built
// from it do not: an index shows its own scope and shared, never a sibling's.
//
// The name means different things on each side — both-sides is 10.1.0.0/24 in
// vsys1 and 10.2.0.0/24 in vsys2 — so a merged answer is wrong, not incomplete.
func TestNoGlobalIndex(t *testing.T) {
	for _, tc := range []struct{ vsys, wantRule, notRule string }{
		{"vsys1", "left-rule", "right-rule"},
		{"vsys2", "right-rule", "left-rule"},
	} {
		refs := siblingIndex(t, tc.vsys).Refs("both-sides")
		if len(refs) != 1 {
			t.Errorf("%s: Refs(both-sides) returned %d edges, want 1: %+v", tc.vsys, len(refs), refs)
			continue
		}
		if !strings.HasSuffix(refs[0].From, "/"+tc.wantRule) {
			t.Errorf("%s: edge came from %s, want %s", tc.vsys, refs[0].From, tc.wantRule)
		}
		if strings.Contains(refs[0].From, tc.notRule) {
			t.Errorf("%s: edge leaked from the sibling vsys: %s", tc.vsys, refs[0].From)
		}
	}
}

// A scope still inherits shared, which is why the filter cannot simply be equality.
func TestAnIndexSeesSharedEdges(t *testing.T) {
	for _, vsys := range []string{"vsys1", "vsys2"} {
		refs := siblingIndex(t, vsys).Refs("everywhere")
		if len(refs) != 1 {
			t.Errorf("%s: Refs(everywhere) returned %d edges, want 1", vsys, len(refs))
			continue
		}
		if refs[0].Field != "destination" {
			t.Errorf("%s: shared edge at %s, want destination", vsys, refs[0].Field)
		}
	}
}

// The file is read once however many scopes ask for it.
func TestTheEdgeListIsReadOnce(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/firewall-siblings.xml")
	if err != nil {
		t.Fatal(err)
	}
	first, err := edgesOf(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := edgesOf(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 {
		t.Fatal("the fixture must yield edges for this to mean anything")
	}
	if &first[0] != &second[0] {
		t.Error("edgesOf read the configuration twice; it must return the cached list")
	}
}
