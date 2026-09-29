package resolve

import (
	"slices"
	"testing"
)

func TestObjectKindsComeFromTheSchema(t *testing.T) {
	t.Parallel()
	got := ObjectKinds(fwLab(t))
	for _, want := range []string{"address", "address-group", "service", "service-group", "custom-url-category", "tag", "zone"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s is missing from %v", want, got)
		}
	}
	for _, not := range []string{"pan-url-categories", "text()", "vsys"} {
		if slices.Contains(got, not) {
			t.Errorf("%s has no container under a scope and must not be listed", not)
		}
	}
	if !slices.IsSorted(got) {
		t.Error("the kinds must be sorted")
	}
}
