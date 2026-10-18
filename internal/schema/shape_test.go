package schema

import "testing"

func TestEntryTypesFound(t *testing.T) {
	t.Parallel()
	root := load(t)
	got := EntryTypes(root)
	if len(got) < 6 {
		t.Fatalf("found %d entry types, want at least 6", len(got))
	}
	paths := map[string]bool{}
	for _, n := range got {
		paths[n.Path()] = true
	}
	for _, want := range []string{
		"/config/shared/address",
		"/config/devices",
		"/config/devices/entry/vsys",
		"/config/devices/entry/vsys/entry/rulebase/security/rules",
	} {
		if !paths[want] {
			t.Errorf("entry type %s not found", want)
		}
	}
}
