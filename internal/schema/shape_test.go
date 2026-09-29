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
