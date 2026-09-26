package schema

import "testing"

func TestEntryTypesFound(t *testing.T) {
	root := load(t)
	got := EntryTypes(root)
	if len(got) < 10 {
		t.Fatalf("found %d entry types, want at least 10", len(got))
	}
	paths := map[string]bool{}
	for _, n := range got {
		paths[n.Path()] = true
	}
	for _, want := range []string{
		"/config/shared/address",
		"/config/devices/entry/device-group",
		"/config/devices/entry/device-group/entry/devices",
		"/config/devices/entry/device-group/entry/devices/entry/vsys",
	} {
		if !paths[want] {
			t.Errorf("entry type %s not found", want)
		}
	}
}

// headers and params hold the same shape. They must share one fingerprint so
// code generation emits one type plus an alias.
func TestIdenticalShapesShareAFingerprint(t *testing.T) {
	root := load(t)
	headers := root.Child("shared").Child("headers")
	params := root.Child("devices").Child("entry").Child("device-group").
		EntrySequence().Child("params")
	if got, want := Fingerprint(params.EntrySequence()), Fingerprint(headers.EntrySequence()); got != want {
		t.Errorf("params and headers must share a fingerprint\n got %s\nwant %s", got, want)
	}
}

func TestDifferentShapesDoNotShareAFingerprint(t *testing.T) {
	root := load(t)
	addr := root.Child("shared").Child("address").EntrySequence()
	tag := root.Child("shared").Child("tag").EntrySequence()
	if Fingerprint(addr) == Fingerprint(tag) {
		t.Error("address and tag must not share a fingerprint")
	}
}

func TestGroupByShapeCollapsesDuplicates(t *testing.T) {
	root := load(t)
	entries := EntryTypes(root)
	groups := GroupByShape(entries)
	if len(groups) >= len(entries) {
		t.Fatalf("grouping produced %d shapes from %d types; it must collapse some",
			len(groups), len(entries))
	}
	multi := 0
	for _, g := range groups {
		if len(g) > 1 {
			multi++
		}
	}
	if multi < 2 {
		t.Errorf("only %d shapes are shared; the fixture has at least 2", multi)
	}
}
