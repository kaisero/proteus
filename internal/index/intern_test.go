package index

import "testing"

func TestInternIsStableAndReversible(t *testing.T) {
	t.Parallel()
	in := NewInterner()
	a := in.ID("net-labor")
	b := in.ID("net-labor")
	if a != b {
		t.Errorf("the same name interned to %d then %d", a, b)
	}
	if got := in.Name(a); got != "net-labor" {
		t.Errorf("Name(%d) = %q, want net-labor", a, got)
	}
	if in.ID("dc01") == a {
		t.Error("different names must intern to different ids")
	}
	if in.Len() != 2 {
		t.Errorf("Len = %d, want 2", in.Len())
	}
}

func TestInternLookupDoesNotInsert(t *testing.T) {
	t.Parallel()
	in := NewInterner()
	if _, ok := in.Lookup("absent"); ok {
		t.Error("Lookup must not report an absent name as present")
	}
	if in.Len() != 0 {
		t.Errorf("Lookup inserted a name; Len = %d, want 0", in.Len())
	}
}

func TestInternNameOfUnknownIDIsEmpty(t *testing.T) {
	t.Parallel()
	in := NewInterner()
	if got := in.Name(42); got != "" {
		t.Errorf("Name(42) = %q, want empty", got)
	}
}
