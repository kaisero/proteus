package resolve

import (
	"testing"

	"github.com/okaiser/go-panos-schema/config"
)

func lab(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

// parent-dg lives only under /config/readonly, which the schema describes as
// empty. It is the only hand-modelled node in the library. See AGENTS.md R8.
func TestHierarchyFromReadonly(t *testing.T) {
	h, err := NewHierarchy(lab(t))
	if err != nil {
		t.Fatalf("NewHierarchy: %v", err)
	}
	roots := h.Roots()
	if len(roots) != 2 {
		t.Fatalf("roots = %v, want two (corp and vsys01)", roots)
	}
	for dg, want := range map[string]string{
		"at-ktn":           "vsys01",
		"at-ooe":           "vsys01",
		"host_1_directory": "corp",
		"corp-graz":        "corp",
	} {
		got, ok := h.ParentOf(dg)
		if !ok || got != want {
			t.Errorf("ParentOf(%q) = %q,%v want %q,true", dg, got, ok, want)
		}
	}
	if _, ok := h.ParentOf("corp"); ok {
		t.Error("corp is a root and has no parent")
	}
	if got := h.Children("corp"); len(got) != 2 {
		t.Errorf("Children(corp) = %v, want two", got)
	}
}

// The chain runs shared first, then root to leaf, which is the order pre-rules
// are evaluated in.
func TestHierarchyChain(t *testing.T) {
	h, _ := NewHierarchy(lab(t))
	got := h.Chain("host_1_directory")
	want := []string{"shared", "dg:corp", "dg:host_1_directory"}
	if len(got) != len(want) {
		t.Fatalf("chain = %v, want %v", scopeStrings(got), want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("chain[%d] = %q, want %q", i, got[i].String(), want[i])
		}
	}
}

func TestHierarchyRejectsACycle(t *testing.T) {
	cfg, _, err := config.Load("../testdata/config/panorama-cycle.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := NewHierarchy(cfg); err == nil {
		t.Fatal("a cyclic parent-dg must be an error")
	}
}

// A template's nested config also has a readonly device-group section in some
// exports. Only the top-level readonly counts.
func TestHierarchyIgnoresNothingItNeeds(t *testing.T) {
	h, _ := NewHierarchy(lab(t))
	if len(h.Roots()) == 0 {
		t.Fatal("no roots found")
	}
}

func scopeStrings(ss []config.Scope) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.String()
	}
	return out
}
