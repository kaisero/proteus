package identity_test

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/identity"
)

// diff gives the changes from the fixture after before changes it to the
// fixture after after changes it.
func diff(t *testing.T, before, after func(f *identity.File)) []identity.Change {
	t.Helper()
	return identity.Diff(fixtureWith(t, before), fixtureWith(t, after))
}

// equalChanges compares two change lists, one change at a time.
func equalChanges(t *testing.T, got, want []identity.Change) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes:\n got %+v\nwant %+v", got, want)
	}
}

// dropUser removes the user of a primary name.
func dropUser(f *identity.File, name string) {
	f.Users = slices.DeleteFunc(f.Users, func(u identity.User) bool { return u.Name == name })
}

// §6.3: per user, the groups added and removed, and the users that come and
// go with their groups. Users compare by primary name and groups by name, in
// any case (N1, M11, X2), so a change of case alone is no change. The changes
// come by kind and name, and their groups by name.
func TestDiffGroups(t *testing.T) {
	t.Parallel()
	got := diff(t,
		func(f *identity.File) { dropUser(f, `example.com\dave`) },
		func(f *identity.File) {
			dropUser(f, `example.com\carol`)
			f.Users[0].Groups = []string{"CN=Domain Users,CN=Users,DC=example,DC=com", "team-x"} // alice
			f.Users[1].Name = `EXAMPLE.COM\Bob`
			f.Users[1].Groups = []string{"Team-X", domainUsers, "team-x"}
		})
	equalChanges(t, got, []identity.Change{
		{Op: "changed", Kind: "user", Name: `example.com\alice`, Added: []string{"team-x"}, Removed: []string{payroll}},
		{Op: "removed", Kind: "user", Name: `example.com\carol`, Removed: []string{domainUsers, "dug-a", "dug-ab", "engineering"}},
		{Op: "added", Kind: "user", Name: `example.com\dave`},
	})
}

// §6.3: per source, a source that comes, a source that goes, and a change of
// the group count. A source is LDAP or CIE by its name, as a group source
// names it. A change of the domain or the base alone is no change. The line
// of a source holds the values that the data knows (ruling Q1).
func TestDiffSources(t *testing.T) {
	t.Parallel()
	branch := identity.LDAPSource{Name: "branch", Domain: "example.com", Base: "ou=branch,dc=example,dc=com", Groups: 2}
	got := diff(t,
		func(f *identity.File) { f.Sources.LDAP = append(f.Sources.LDAP, branch) },
		func(f *identity.File) {
			f.Sources.LDAP[0].Groups = 4
			moved := branch
			moved.Domain, moved.Base = "", "OU=Branch,DC=example,DC=com"
			f.Sources.LDAP = append(f.Sources.LDAP, moved,
				identity.LDAPSource{Name: "east", Base: "ou=east,dc=example,dc=com", Groups: 1})
			f.Sources.CIE = nil
		})
	equalChanges(t, got, []identity.Change{
		{Op: "removed", Kind: "source", Name: "cie:cie-a", Old: "domain=example-cie groups=1"},
		{Op: "added", Kind: "source", Name: "ldap:east", New: "base=ou=east,dc=example,dc=com groups=1"},
		{Op: "changed", Kind: "source", Name: "ldap:example.com", Old: "3", New: "4"},
	})
	added := diff(t, func(f *identity.File) { f.Sources.LDAP = nil }, func(*identity.File) {})
	equalChanges(t, added, []identity.Change{
		{Op: "added", Kind: "source", Name: "ldap:example.com", New: "domain=example.com base=dc=example,dc=com groups=3"},
	})
}

// D9, §6.3: mapping changes give no change: the table moves all day. Tags,
// alternate names, emails, group lists and the time of the fetch give none
// either: the diff compares the groups of the users and the sources only.
func TestDiffIgnoresMappings(t *testing.T) {
	t.Parallel()
	got := diff(t,
		func(*identity.File) {},
		func(f *identity.File) {
			f.TakenAt = f.TakenAt.Add(time.Hour)
			f.Mappings = append(f.Mappings[2:], mapping("203.0.113.5", `example.com\alice`, 60))
			f.Mappings[0].User = `example.com\bob`
			f.MappingsPartial = true
			f.Tags = nil
			f.Users[0].Alt, f.Users[0].Email = nil, ""
			f.Groups, f.DUGs = f.Groups[:2], nil
		})
	if len(got) != 0 {
		t.Errorf("changes %+v, want none", got)
	}
	d := loadFixture(t)
	if got := identity.Diff(d, d); len(got) != 0 {
		t.Errorf("one data against itself: %+v", got)
	}
}

// PD19, SG8: a part that is missing in either snapshot is not compared,
// because its entries would show as removed or added. The other parts still
// compare. A side without data gives no change; the caller notes it (SG8).
func TestDiffLeavesOutAMissingPart(t *testing.T) {
	t.Parallel()
	whole := loadFixture(t)
	ldapGrows := fixtureWith(t, func(f *identity.File) { f.Sources.LDAP[0].Groups = 4 })
	ldapChange := identity.Change{Op: "changed", Kind: "source", Name: "ldap:example.com", Old: "3", New: "4"}
	for _, part := range []string{identity.PartUserGroups, identity.PartUserNames, identity.PartCIE} {
		equalChanges(t, identity.Diff(missing(t, part), ldapGrows), []identity.Change{ldapChange})
		equalChanges(t, identity.Diff(ldapGrows, missing(t, part)), []identity.Change{
			{Op: "changed", Kind: "source", Name: "ldap:example.com", Old: "4", New: "3"},
		})
	}
	aliceMoves := fixtureWith(t, func(f *identity.File) { f.Users[0].Groups = []string{domainUsers} })
	aliceChange := identity.Change{Op: "changed", Kind: "user", Name: `example.com\alice`, Removed: []string{payroll}}
	for _, part := range []string{identity.PartLDAP, identity.PartGroups, identity.PartTags, identity.PartMappings} {
		equalChanges(t, identity.Diff(missing(t, part), aliceMoves), []identity.Change{aliceChange})
	}
	cieGoes := fixtureWith(t, func(f *identity.File) { f.Sources.CIE = nil })
	equalChanges(t, identity.Diff(missing(t, identity.PartLDAP), cieGoes), []identity.Change{
		{Op: "removed", Kind: "source", Name: "cie:cie-a", Old: "domain=example-cie groups=1"},
	})
	for name, got := range map[string][]identity.Change{
		"no data before": identity.Diff(nil, whole),
		"no data after":  identity.Diff(whole, nil),
	} {
		if got != nil {
			t.Errorf("%s: %+v, want nil", name, got)
		}
	}
}
