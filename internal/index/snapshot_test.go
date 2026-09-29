package index

import "testing"

// A snapshot built in code, not read from JSON, still answers case insensitively.
func TestGroupsOfOnASnapshotBuiltInCode(t *testing.T) {
	t.Parallel()
	s := &UserSnapshot{Groups: map[string][]string{"ACME\\Carol": {"engineering"}}}
	if got := s.GroupsOf(" acme\\carol "); len(got) != 1 || got[0] != "engineering" {
		t.Errorf("GroupsOf = %v, want [engineering]", got)
	}
}
