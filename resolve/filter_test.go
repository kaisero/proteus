package resolve

import "testing"

func TestTagFilterSingleTag(t *testing.T) {
	f, err := ParseTagFilter("'corp-location'")
	if err != nil {
		t.Fatalf("ParseTagFilter: %v", err)
	}
	if !f.Match([]string{"corp-location"}) {
		t.Error("the tag must match")
	}
	if f.Match([]string{"other"}) {
		t.Error("a different tag must not match")
	}
	if f.Match(nil) {
		t.Error("no tags must not match")
	}
}

func TestTagFilterAnd(t *testing.T) {
	f, err := ParseTagFilter("'a' and 'b'")
	if err != nil {
		t.Fatalf("ParseTagFilter: %v", err)
	}
	if !f.Match([]string{"a", "b", "c"}) {
		t.Error("both tags present must match")
	}
	if f.Match([]string{"a"}) {
		t.Error("only one tag must not match an and")
	}
}

func TestTagFilterOr(t *testing.T) {
	f, err := ParseTagFilter("'a' or 'b'")
	if err != nil {
		t.Fatalf("ParseTagFilter: %v", err)
	}
	if !f.Match([]string{"b"}) {
		t.Error("either tag must match")
	}
	if f.Match([]string{"c"}) {
		t.Error("neither tag must not match")
	}
}

func TestTagFilterNot(t *testing.T) {
	f, err := ParseTagFilter("'a' and not 'b'")
	if err != nil {
		t.Fatalf("ParseTagFilter: %v", err)
	}
	if !f.Match([]string{"a"}) {
		t.Error("a without b must match")
	}
	if f.Match([]string{"a", "b"}) {
		t.Error("a with b must not match")
	}
}

// and binds tighter than or, as in PAN-OS.
func TestTagFilterPrecedence(t *testing.T) {
	f, err := ParseTagFilter("'a' and 'b' or 'c'")
	if err != nil {
		t.Fatalf("ParseTagFilter: %v", err)
	}
	for _, tc := range []struct {
		tags []string
		want bool
	}{
		{[]string{"a", "b"}, true},
		{[]string{"c"}, true},
		{[]string{"a"}, false},
		{[]string{"b"}, false},
		{[]string{"d"}, false},
	} {
		if got := f.Match(tc.tags); got != tc.want {
			t.Errorf("tags %v matched %v, want %v", tc.tags, got, tc.want)
		}
	}
}

func TestTagFilterParentheses(t *testing.T) {
	f, err := ParseTagFilter("('a' or 'b') and 'c'")
	if err != nil {
		t.Fatalf("ParseTagFilter: %v", err)
	}
	if !f.Match([]string{"a", "c"}) {
		t.Error("a and c must match")
	}
	if f.Match([]string{"a", "b"}) {
		t.Error("without c it must not match")
	}
}

func TestTagFilterTags(t *testing.T) {
	f, _ := ParseTagFilter("'a' and not 'b' or 'c'")
	got := f.Tags()
	want := map[string]bool{"a": true, "b": true, "c": true}
	if len(got) != len(want) {
		t.Fatalf("Tags = %v, want a, b and c", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected tag %q", g)
		}
	}
}

func TestTagFilterRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "and", "'a' and", "'a' 'b'", "('a'", "'a')", "$unquoted"} {
		if _, err := ParseTagFilter(bad); err == nil {
			t.Errorf("ParseTagFilter(%q) must fail", bad)
		}
	}
}
