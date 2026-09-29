package index

import (
	"os"
	"strings"
	"testing"
	"time"
)

func usersIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-users.xml", "vsys1")
}

func snapshot(t *testing.T) *UserSnapshot {
	t.Helper()
	f, err := os.Open("../../testdata/users-snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := LoadUserSnapshot(f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Without a directory only the local database is searched, and the answer says that a
// rule naming a directory group is missing. This is the first value space a
// configuration cannot answer on its own, so silence here would be a wrong answer.
func TestUserResolverWithoutADirectorySaysWhatIsMissing(t *testing.T) {
	t.Parallel()
	idx := usersIndex(t)

	rules, rep := idx.Candidates(SourceUser, "alice")

	names := ruleNames(idx, rules)
	if !names["admins-allowed"] {
		t.Error("the rule naming the local group alice belongs to was not found")
	}
	if names["engineering-allowed"] {
		t.Error("a directory group cannot be known without a directory")
	}
	var told bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "no user directory was supplied") {
			told = true
		}
	}
	if !told {
		t.Errorf("the missing directory was not reported: %v", rep.Unresolved)
	}
}

// With a directory the groups it reports are added, and the rules naming them follow.
func TestUserResolverWithADirectory(t *testing.T) {
	t.Parallel()
	idx := usersIndex(t)

	rules, rep := idx.With(Providers{Users: snapshot(t)}).Candidates(SourceUser, "alice")

	names := ruleNames(idx, rules)
	for _, want := range []string{"admins-allowed", "engineering-allowed"} {
		if !names[want] {
			t.Errorf("%s was not reached", want)
		}
	}
	// One membership, reported once, though both the file and the directory know it.
	var localAdmins int
	for _, h := range rep.Hits {
		if h.Name == "local-admins" {
			localAdmins++
		}
	}
	if localAdmins != 1 {
		t.Errorf("local-admins reported %d times, want once", localAdmins)
	}
}

// A dynamic user group is filled in at runtime, so it is always reported rather than
// matched, with or without a directory.
func TestUserResolverAlwaysReportsDynamicUserGroups(t *testing.T) {
	t.Parallel()
	idx := usersIndex(t)

	for label, p := range map[string]Providers{
		"no directory":   {},
		"with directory": {Users: snapshot(t)},
	} {
		_, rep := idx.With(p).Candidates(SourceUser, "alice")
		var found bool
		for _, u := range rep.Unresolved {
			if u.Value == "quarantined-users" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the dynamic user group was not reported: %v", label, rep.Unresolved)
		}
	}
}

// A user named directly by a rule is found without any directory at all.
func TestUserResolverFindsAUserNamedByARule(t *testing.T) {
	t.Parallel()
	idx := usersIndex(t)

	rules, _ := idx.Candidates(SourceUser, "bob")
	if !ruleNames(idx, rules)["bob-direct"] {
		t.Error("a rule naming a local user directly was not found")
	}
}

// A stale snapshot is reported rather than trusted. A mapping read days ago can put a
// user in a group they have since left.
func TestUserSnapshotReportsStaleness(t *testing.T) {
	t.Parallel()
	idx := usersIndex(t)
	snap := snapshot(t)
	snap.TakenAt = time.Now().Add(-72 * time.Hour)

	_, rep := idx.With(Providers{Users: snap}).Candidates(SourceUser, "alice")

	var told bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "more than the") {
			told = true
		}
	}
	if !told {
		t.Errorf("a three day old snapshot was not reported as stale: %v", rep.Unresolved)
	}

	// And a fresh one is not reported.
	snap.TakenAt = time.Now().Add(-time.Hour)
	_, rep = idx.With(Providers{Users: snap}).Candidates(SourceUser, "alice")
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "more than the") {
			t.Errorf("a one hour old snapshot was called stale: %v", u)
		}
	}
}

// A snapshot with no timestamp is refused, because it could never be reported stale.
func TestLoadUserSnapshotRequiresATimestamp(t *testing.T) {
	t.Parallel()
	_, err := LoadUserSnapshot(strings.NewReader(`{"groups":{"alice":["x"]}}`))
	if err == nil {
		t.Fatal("a snapshot with no taken_at was accepted")
	}
	if !strings.Contains(err.Error(), "taken_at") {
		t.Errorf("error does not name the missing field: %v", err)
	}
}

// Malformed JSON is reported, not ignored.
func TestLoadUserSnapshotRejectsBadJSON(t *testing.T) {
	t.Parallel()
	if _, err := LoadUserSnapshot(strings.NewReader(`{`)); err == nil {
		t.Error("malformed JSON was accepted")
	}
}

// A directory and a firewall rule rarely agree on case, so lookups ignore it.
func TestUserSnapshotIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	snap := snapshot(t)
	for _, q := range []string{"alice", "ALICE", "Alice", `acme\carol`, `ACME\CAROL`} {
		if len(snap.GroupsOf(q)) == 0 {
			t.Errorf("GroupsOf(%q) found nothing", q)
		}
	}
	if len(snap.GroupsOf("nobody")) != 0 {
		t.Error("an unknown user returned groups")
	}
}

// A value that plainly belongs to another value space is not reported as a user.
func TestUserResolverIgnoresNonUserShapes(t *testing.T) {
	t.Parallel()
	idx := usersIndex(t)

	for _, q := range []string{"10.0.0.0/8", "example.com/path", "a b"} {
		_, rep := idx.Candidates(SourceUser, q)
		for _, h := range rep.Hits {
			if h.Kind == "user" || h.Kind == "user-group" {
				t.Errorf("%s was reported as a user: %+v", q, h)
			}
		}
	}
}

// Searching looks inside values, and a user group's value is its membership. So a
// fragment of a member finds the group, while a fragment of the group's own name does
// not: a name is found by looking it up, which already works.
func TestUserResolverSearchLooksAtMembership(t *testing.T) {
	t.Parallel()
	idx := usersIndex(t)

	hits := idx.SearchValues("alic")
	kinds := map[string]bool{}
	for _, h := range hits {
		kinds[h.Kind] = true
	}
	if !kinds["user"] {
		t.Errorf("a fragment of a user name did not find the user: %+v", hits)
	}
	if !kinds["user-group"] {
		t.Errorf("a fragment of a member did not find the group holding it: %+v", hits)
	}

	// "admin" is part of the group's name, not of any value, so searching values does
	// not find it. Looking the name up does.
	if got := idx.SearchValues("admin"); len(got) != 0 {
		t.Errorf("searching values found a name-only fragment: %+v", got)
	}
	if rules, _ := idx.Candidates(SourceUser, "local-admins"); rules.IsEmpty() {
		t.Error("the group is still reachable by its name")
	}
}
