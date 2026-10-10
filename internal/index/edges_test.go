package index

import (
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

func siblingIndex(t *testing.T, vsys string) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-siblings.xml", vsys)
}

// R10. The edge list spans the file, so this is the test that the indexes built
// from it do not: an index shows its own scope and shared, never a sibling's.
//
// The name means different things on each side — both-sides is 10.1.0.0/24 in
// vsys1 and 10.2.0.0/24 in vsys2 — so a merged answer is wrong, not incomplete.
func TestNoGlobalIndex(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// The device's own configuration, outside any vsys, names objects too: a static
// route's destination and an IKE gateway's peer address. Those edges carry the
// scope config, and every scope's index keeps them.
func TestAnIndexSeesDeviceLevelEdges(t *testing.T) {
	t.Parallel()
	for _, sc := range []config.Scope{{Sort: config.ScopeVsys, Name: "vsys1"}, {Sort: config.ScopeShared}} {
		cfg, _, err := config.Load("../../testdata/config/firewall-device-refs.xml")
		if err != nil {
			t.Fatal(err)
		}
		idx, err := New(cfg, sc, resolve.Security)
		if err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]string{
			"net-remote": "/network/virtual-router/default/routing-table/ip/static-route/to-remote destination",
			"peer-1":     "/network/ike/gateway/gw-1 peer-address/ip",
		} {
			var got []string
			for _, r := range idx.Refs(name) {
				if r.Scope.Sort == config.ScopeConfig && r.Scope.String() == "config" {
					got = append(got, r.From+" "+r.Field)
				}
			}
			if len(got) != 1 || !strings.HasSuffix(got[0], want) {
				t.Errorf("%s: device-level Refs(%s) = %v, want one ending %q", sc, name, got, want)
			}
		}
	}
}

// The file is read once however many indexes of a set ask for it.
func TestTheEdgeListIsReadOnce(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-siblings.xml")
	if err != nil {
		t.Fatal(err)
	}
	s := NewSet(cfg)
	first, err := s.readEdges()
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.readEdges()
	if err != nil {
		t.Fatal(err)
	}
	if len(first.list) == 0 {
		t.Fatal("the fixture must yield edges for this to mean anything")
	}
	if first != second {
		t.Error("the set read the configuration twice; it must keep the list it read")
	}
}
