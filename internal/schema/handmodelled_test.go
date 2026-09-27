package schema

import "testing"

// R8. Every registered node carries its reason and its owner.
func TestHandModelledIsDeclared(t *testing.T) {
	for _, h := range HandModelled() {
		if h.Path == "" {
			t.Error("a hand-modelled node has no path")
		}
		if h.Reason == "" {
			t.Errorf("%s has no reason", h.Path)
		}
		if h.Owner == "" {
			t.Errorf("%s has no owner", h.Path)
		}
	}
}

func TestHandModelledIsACopy(t *testing.T) {
	saved := handModelled
	defer func() { handModelled = saved }()
	handModelled = []HandModel{{Path: "/config/x", Reason: "r", Owner: "o"}}

	first := HandModelled()
	first[0].Reason = "mutated"
	if HandModelled()[0].Reason == "mutated" {
		t.Error("HandModelled returned the backing slice; it must return a copy")
	}
}
