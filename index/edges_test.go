package index

import (
	"strings"
	"testing"

	"github.com/okaiser/go-panos-schema/config"
)

func siblingIndex(t *testing.T, dg string) *Index {
	t.Helper()
	cfg, _, err := config.Load("../testdata/config/panorama-siblings.xml")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := For(cfg, config.Scope{Sort: config.ScopeDeviceGroup, Name: dg})
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// R10. The edge list spans the file, so this is the test that the indexes built
// from it do not: an index shows its own scope and shared, never a sibling's.
//
// The name means different things on each side — both-sides is 10.1.0.0/24 in
// left and 10.2.0.0/24 in right — so a merged answer is wrong, not incomplete.
func TestNoGlobalIndex(t *testing.T) {
	for _, tc := range []struct{ dg, wantRule, notRule string }{
		{"left", "left-rule", "right-rule"},
		{"right", "right-rule", "left-rule"},
	} {
		refs := siblingIndex(t, tc.dg).Refs("both-sides")
		if len(refs) != 1 {
			t.Errorf("%s: Refs(both-sides) returned %d edges, want 1: %+v", tc.dg, len(refs), refs)
			continue
		}
		if !strings.HasSuffix(refs[0].From, "/"+tc.wantRule) {
			t.Errorf("%s: edge came from %s, want %s", tc.dg, refs[0].From, tc.wantRule)
		}
		if strings.Contains(refs[0].From, tc.notRule) {
			t.Errorf("%s: edge leaked from the sibling device group: %s", tc.dg, refs[0].From)
		}
	}
}

// A scope still inherits shared, which is why the filter cannot simply be equality.
func TestAnIndexSeesSharedEdges(t *testing.T) {
	for _, dg := range []string{"left", "right"} {
		refs := siblingIndex(t, dg).Refs("everywhere")
		if len(refs) != 1 {
			t.Errorf("%s: Refs(everywhere) returned %d edges, want 1", dg, len(refs))
			continue
		}
		if refs[0].Field != "destination" {
			t.Errorf("%s: shared edge at %s, want destination", dg, refs[0].Field)
		}
	}
}

// The file is read once however many scopes ask for it.
func TestTheEdgeListIsReadOnce(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/panorama-siblings.xml")
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
