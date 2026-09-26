package schema

import (
	"strings"
	"testing"
)

func TestHandModelledIsDeclared(t *testing.T) {
	got := HandModelled()
	if len(got) == 0 {
		t.Fatal("no hand-modelled nodes registered; parent-dg must be one")
	}
	var found bool
	for _, h := range got {
		if h.Reason == "" {
			t.Errorf("%s has no reason", h.Path)
		}
		if h.Owner == "" {
			t.Errorf("%s has no owner", h.Path)
		}
		if strings.Contains(h.Path, "parent-dg") {
			found = true
		}
	}
	if !found {
		t.Error("parent-dg is not registered")
	}
}

func TestHandModelledIsACopy(t *testing.T) {
	first := HandModelled()
	first[0].Reason = "mutated"
	if HandModelled()[0].Reason == "mutated" {
		t.Error("HandModelled returned the backing slice; it must return a copy")
	}
}
