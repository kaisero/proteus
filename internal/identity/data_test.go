package identity_test

import (
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/identity"
)

// fixtureWith builds the data of the fixture file after change.
func fixtureWith(t *testing.T, change func(f *identity.File)) *identity.Data {
	t.Helper()
	f := fixtureFile(t)
	change(&f)
	return identity.New(f)
}

// N7, SG4, PD21: the two email decisions. fw01 could not show N7 in round 3,
// so an email resolves in --user and in a search term, and the answer is
// inferred. No fact shows that a rule resolves an email, so a rule's email
// member does not resolve until the owner says so. A change of either
// constant fails here, so the change is deliberate.
func TestEmailConstantsFollowTheFacts(t *testing.T) {
	t.Parallel()
	got := []bool{identity.InputEmail, identity.RuleEmail}
	if want := []bool{true, false}; !slices.Equal(got, want) {
		t.Errorf("InputEmail, RuleEmail = %v, want %v: N7 is not shown (PD21), and SG4 holds until the owner says otherwise", got, want)
	}
}

// N1, N2, N5, D7, N7: a primary name in any case and an alternate name give
// the primary name. An email gives it too, because InputEmail holds (PD21).
// The NetBIOS form example\alice is no name of the data (N5), and a mapped
// user outside the directory is no user of it (M2, M3).
func TestResolve(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for in, want := range map[string]string{
		`example.com\alice`: `example.com\alice`,
		`EXAMPLE.COM\Alice`: `example.com\alice`,
		"alice@example.com": `example.com\alice`,
		"ALICE@Example.COM": `example.com\alice`,
		"bob@example.com":   `example.com\bob`,
		// The email of bob is no alternate name of his (N7, PD21).
		"robert@example.com": `example.com\bob`,
		"Robert@Example.com": `example.com\bob`,
	} {
		if got, ok := d.Resolve(in); !ok || got != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{`example\alice`, `other\ghost`, "nobody", "", domainUsers, `example.com\domain users`} {
		if got, ok := d.Resolve(in); ok {
			t.Errorf("Resolve(%q) = %q; want nothing", in, got)
		}
	}
}

// A primary name comes before an alternate name, and an alternate name
// before an email: the UPN of one user can be the email of another. Of two
// users with one alternate name or one email, the first in the file counts.
func TestResolveOrder(t *testing.T) {
	t.Parallel()
	d := fixtureWith(t, func(f *identity.File) {
		f.Users[2].Alt = []string{"robert@example.com", `example.com\alice`} // carol
		f.Users[3].Email = "Alice@Example.com"                               // dave
		f.Users[3].Alt = append(f.Users[3].Alt, "bob@example.com")
	})
	for in, want := range map[string]string{
		"robert@example.com": `example.com\carol`, // an alternate name of carol, the email of bob
		`example.com\alice`:  `example.com\alice`, // a primary name of alice, an alternate name of carol
		"alice@example.com":  `example.com\alice`, // an alternate name of alice, the email of dave
		"bob@example.com":    `example.com\bob`,   // bob comes before dave in the file
	} {
		if got, ok := d.Resolve(in); !ok || got != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

// U8, PD18: User finds a user by its primary name, an alternate name and an
// email, through Resolve: one email rule serves lookup and simulate. The
// caller gets a copy.
func TestUser(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	want := identity.User{
		Name: `example.com\bob`, Alt: []string{"bob@example.com"}, Email: "robert@example.com",
		Groups: []string{domainUsers, "team-x"},
	}
	for _, name := range []string{`example.com\bob`, `EXAMPLE.COM\BOB`, "bob@example.com", "robert@example.com"} {
		got, ok := d.User(name)
		if !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("User(%q) = %+v, %v\nwant %+v", name, got, ok, want)
		}
		if primary, _ := d.Resolve(name); primary != got.Name {
			t.Errorf("User(%q) is %q, Resolve gives %q", name, got.Name, primary)
		}
	}
	for _, name := range []string{`example\alice`, `other\ghost`, "nobody"} {
		if got, ok := d.User(name); ok {
			t.Errorf("User(%q) = %+v; want none", name, got)
		}
	}
	alice, _ := d.User("alice@example.com")
	alice.Groups[0], alice.Alt[0] = "changed", "changed"
	if again, _ := d.User(`example.com\alice`); again.Groups[0] != domainUsers || again.Alt[0] != "alice@example.com" {
		t.Errorf("a change of the answer reached the data: %+v", again)
	}
}

// allParts are the parts of a fetch (spec 2026-10-17 §3.2).
var allParts = []string{
	identity.PartLDAP, identity.PartCIE, identity.PartUserGroups, identity.PartUserNames,
	identity.PartGroups, identity.PartTags, identity.PartMappings,
}

// PD19, SG13: the fixture is complete in every part. A part that
// parts_missing names is not complete, and mappings_partial makes mappings
// not complete. A name that is no part is never complete.
func TestComplete(t *testing.T) {
	t.Parallel()
	whole := loadFixture(t)
	for _, p := range allParts {
		if !whole.Complete(p) {
			t.Errorf("the fixture: %s is not complete", p)
		}
	}
	for _, c := range []struct {
		name       string
		change     func(f *identity.File)
		incomplete string
	}{
		{"users.groups missing", func(f *identity.File) { f.PartsMissing = []string{identity.PartUserGroups} }, identity.PartUserGroups},
		{"mappings partial", func(f *identity.File) { f.MappingsPartial = true }, identity.PartMappings},
		{"mappings missing", func(f *identity.File) { f.PartsMissing = []string{identity.PartMappings} }, identity.PartMappings},
	} {
		d := fixtureWith(t, c.change)
		for _, p := range allParts {
			if got, want := d.Complete(p), p != c.incomplete; got != want {
				t.Errorf("%s: Complete(%s) = %v, want %v", c.name, p, got, want)
			}
		}
	}
	for _, p := range []string{"users", "", "Mappings"} {
		if whole.Complete(p) {
			t.Errorf("Complete(%q) holds for no part", p)
		}
	}
}

// M2: GroupsOf takes a primary name, in any case (N1). The NetBIOS form of a
// mapping, an alternate name and an outside user have no group, and dave, a
// user of U8 alone, has none (D13). The DUGs of U3 are among the groups. The
// caller gets a copy.
func TestGroupsOfIsPrimaryOnly(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	if got := d.GroupsOf(`example.com\alice`); !slices.Contains(got, payroll) {
		t.Errorf("GroupsOf(alice) = %q, want payroll among them", got)
	}
	if got, want := d.GroupsOf(`EXAMPLE.COM\Carol`), []string{domainUsers, "engineering", "dug-a", "dug-ab"}; !slices.Equal(got, want) {
		t.Errorf("GroupsOf(carol) = %q, want %q", got, want)
	}
	for _, name := range []string{`example\alice`, "alice@example.com", `other\ghost`, `example.com\dave`} {
		if got := d.GroupsOf(name); got != nil {
			t.Errorf("GroupsOf(%q) = %q, want nil", name, got)
		}
	}
	d.GroupsOf(`example.com\alice`)[0] = "changed"
	if got := d.GroupsOf(`example.com\alice`)[0]; got != domainUsers {
		t.Errorf("a change of the answer reached the data: %q", got)
	}
}

// M11: as observed on fw01, PAN-OS 11.2.5, a rule matches a group DN in
// another case. The user compares in any case (N1, X2), and the group of a
// short name is its DN (M12). A mapped NetBIOS name and an alternate name are
// in no group (M2), and an empty group holds no user (M13).
func TestInGroupFollowsM11(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for _, c := range []struct {
		user, group string
		want        bool
	}{
		{`example.com\alice`, "CN=DOMAIN USERS,CN=USERS,DC=EXAMPLE,DC=COM", true},
		{`example.com\alice`, "CN=Payroll,OU=Groups,DC=example,DC=com", true},
		{`EXAMPLE.COM\ALICE`, domainUsers, true},
		{`example.com\alice`, `EXAMPLE.COM\Domain Users`, true},
		{`Example.Com\Carol`, "Engineering", true},
		{`example\alice`, domainUsers, false},
		{"alice@example.com", domainUsers, false},
		{`example.com\bob`, payroll, false},
		{`example.com\alice`, emptyGroup, false},
		{`example.com\alice`, "cn=no-such,ou=groups,dc=example,dc=com", false},
		{"nobody", domainUsers, false},
	} {
		if got := d.InGroup(c.user, c.group); got != c.want {
			t.Errorf("InGroup(%q, %q) = %v, want %v", c.user, c.group, got, c.want)
		}
	}
	// U3 can print a group in another case than U5, and without U5 no group
	// list gives the stored name: the groups of the user compare in any case.
	upper := fixtureWith(t, func(f *identity.File) { f.Users[1].Groups[0] = "CN=Domain Users,CN=Users,DC=example,DC=com" })
	if !upper.InGroup(`example.com\bob`, domainUsers) {
		t.Error("a group of U3 in another case than U5: InGroup = false")
	}
	if !missing(t, identity.PartGroups).InGroup(`example.com\alice`, "CN=DOMAIN USERS,CN=USERS,DC=EXAMPLE,DC=COM") {
		t.Error("without groups: a DN in another case is not in the groups of the user")
	}
}

// U3, D13: carol is in dug-a and dug-ab, because U3 lists both DUGs among her
// groups, also as EXAMPLE.COM\Carol (X2). dave has registered tags and no U3
// entry, so he is in no DUG: no code evaluates a DUG filter.
func TestInGroupHoldsTheDUGsOfU3(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for _, user := range []string{`example.com\carol`, `EXAMPLE.COM\Carol`} {
		for _, dug := range []string{"dug-a", "dug-ab", "DUG-A"} {
			if !d.InGroup(user, dug) {
				t.Errorf("InGroup(%q, %q) = false, want true", user, dug)
			}
		}
	}
	for _, user := range []string{`example.com\dave`, `example.com\alice`} {
		for _, dug := range []string{"dug-a", "dug-ab"} {
			if d.InGroup(user, dug) {
				t.Errorf("InGroup(%q, %q) = true, want false", user, dug)
			}
		}
	}
}

// M11, M12: a group by its name in any case; a DN in any case; the short
// name <domain>\<cn> of an LDAP group gives the group of its DN, in any case.
// The domain of a short name is the domain of the profile of the group (U4).
func TestGroup(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	domain := identity.Group{Name: domainUsers, Source: "ldap:example.com", Members: 3}
	for name, want := range map[string]identity.Group{
		domainUsers: domain,
		"CN=Domain Users,CN=Users,DC=example,DC=com": domain,
		`example.com\domain users`:                   domain,
		`EXAMPLE.COM\Domain Users`:                   domain,
		`example.com\payroll`:                        {Name: payroll, Source: "ldap:example.com", Members: 1},
		"Engineering":                                {Name: "engineering", Source: "xmlapi", Members: 1},
		"DUG-AB":                                     {Name: "dug-ab", Source: "dug", Members: 1},
		`Example-CIE\Cloud-Team`:                     {Name: `example-cie\cloud-team`, Source: "cie:cie-a", Members: 0},
	} {
		if got, ok := d.Group(name); !ok || got != want {
			t.Errorf("Group(%q) = %+v, %v; want %+v", name, got, ok, want)
		}
	}
	for _, name := range []string{
		"cn=no-such,ou=groups,dc=example,dc=com", `example\domain users`, `example-cie\domain users`,
		`example.com\nobody`, `example.com\`, `\domain users`, "domain users", `example.com\alice`, "nobody",
	} {
		if got, ok := d.Group(name); ok {
			t.Errorf("Group(%q) = %+v; want none", name, got)
		}
	}
}

// U3: the members of a group are the users whose groups hold it, in any
// case, as primary names in name order. The group is a name, a DN in any case
// (M11) or a short name (M12). A DUG holds the users that U3 lists in it
// (D13).
func TestMembers(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	want := []string{`example.com\alice`, `example.com\bob`, `example.com\carol`}
	for _, name := range []string{domainUsers, "CN=DOMAIN USERS,CN=USERS,DC=EXAMPLE,DC=COM", `example.com\domain users`} {
		if got := d.Members(name); !slices.Equal(got, want) {
			t.Errorf("Members(%q) = %q, want %q", name, got, want)
		}
	}
	if got := d.Members("DUG-A"); !slices.Equal(got, []string{`example.com\carol`}) {
		t.Errorf("Members(DUG-A) = %q, want carol", got)
	}
	for _, name := range []string{emptyGroup, "nobody", `example-cie\cloud-team`} {
		if got := d.Members(name); got != nil {
			t.Errorf("Members(%q) = %q, want nil", name, got)
		}
	}
	reversed := fixtureWith(t, func(f *identity.File) { slices.Reverse(f.Users) })
	if got := reversed.Members(domainUsers); !slices.Equal(got, want) {
		t.Errorf("users in another order: Members = %q, want %q", got, want)
	}
}

// §8, U3: MemberCount is the length of Members, which New counts once, so a
// caller reads no list of members. A user that lists a group twice, in two
// cases, counts once (M11). A short name counts the members of its group
// (M12).
func TestMemberCount(t *testing.T) {
	t.Parallel()
	d := fixtureWith(t, func(f *identity.File) {
		f.Users[0].Groups = append(f.Users[0].Groups, strings.ToUpper(domainUsers))
	})
	for _, name := range []string{
		domainUsers, "CN=DOMAIN USERS,CN=USERS,DC=EXAMPLE,DC=COM", `example.com\domain users`,
		"DUG-A", "dug-ab", "engineering", emptyGroup, "nobody", `example-cie\cloud-team`,
	} {
		if got, want := d.MemberCount(name), len(d.Members(name)); got != want {
			t.Errorf("MemberCount(%q) = %d, want %d", name, got, want)
		}
	}
	if got := d.MemberCount(domainUsers); got != 3 {
		t.Errorf("MemberCount(domain users) = %d, want 3", got)
	}
}

// M8, X2: the registered tags of a user, by the name of the registration in
// any case. They feed lookup only (D13). Two registrations of one user in two
// cases give the tags of both, each tag once in its own case (M14). The
// caller gets a copy.
func TestTagsOf(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	if got := d.TagsOf(`EXAMPLE.COM\Carol`); !slices.Equal(got, []string{"tag-a", "tag-b"}) {
		t.Errorf("TagsOf(carol) = %q, want [tag-a tag-b]", got)
	}
	if got := d.TagsOf(`example.com\dave`); !slices.Equal(got, []string{"tag-a"}) {
		t.Errorf("TagsOf(dave) = %q, want [tag-a]", got)
	}
	for _, name := range []string{`example.com\alice`, `example\carol`, "carol"} {
		if got := d.TagsOf(name); got != nil {
			t.Errorf("TagsOf(%q) = %q, want nil", name, got)
		}
	}
	twice := fixtureWith(t, func(f *identity.File) {
		f.Tags = append(f.Tags, identity.Tags{User: `EXAMPLE.COM\CAROL`, Tags: []string{"tag-b", "tag-c", "TAG-A"}})
	})
	if got, want := twice.TagsOf(`example.com\carol`), []string{"tag-a", "tag-b", "tag-c", "TAG-A"}; !slices.Equal(got, want) {
		t.Errorf("two registrations: TagsOf(carol) = %q, want %q", got, want)
	}
	d.TagsOf(`example.com\carol`)[0] = "changed"
	if got := d.TagsOf(`example.com\carol`)[0]; got != "tag-a" {
		t.Errorf("a change of the answer reached the data: %q", got)
	}
}

// U1: a mapping by its address, IPv6 too (Review focus 4). An address without
// a mapping has none. Of two mappings of one address, the later one counts,
// as the fetch keeps the later page (spec 2026-10-17 §3.2).
func TestMapping(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for ip, user := range map[string]string{
		"198.51.100.11": `example.com\alice`,
		"2001:db8::11":  `example.com\bob`,
		"198.51.100.10": `example\alice`,
	} {
		if got, ok := d.Mapping(netip.MustParseAddr(ip)); !ok || got != mapping(ip, user, 14400) {
			t.Errorf("Mapping(%s) = %+v, %v; want %s", ip, got, ok, user)
		}
	}
	for _, ip := range []netip.Addr{netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("2001:db8::12"), {}} {
		if got, ok := d.Mapping(ip); ok {
			t.Errorf("Mapping(%s) = %+v; want none", ip, got)
		}
	}
	later := fixtureWith(t, func(f *identity.File) {
		f.Mappings = append(f.Mappings, mapping("198.51.100.11", `example.com\bob`, 60), mapping("198.51.100.20", `example.com\carol`, 60))
	})
	if got, _ := later.Mapping(netip.MustParseAddr("198.51.100.11")); got.User != `example.com\bob` {
		t.Errorf("two mappings of one address: %+v, want the later one", got)
	}
	if got, ok := later.Mapping(netip.MustParseAddr("198.51.100.20")); !ok || got.User != `example.com\carol` {
		t.Errorf("a mapping after the IPv6 one in the file: %+v, %v", got, ok)
	}
}

// U1, M2: the mappings of a user, by the stored name in any case, in address
// order with IPv4 first. example\alice is another stored name, so its mapping
// is not alice's; an alternate name has no mapping. A mapping that a later
// one of its address replaces is no mapping of its user.
func TestMappingsOf(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	if got, want := d.MappingsOf(`Example.com\alice`), []identity.Mapping{mapping("198.51.100.11", `example.com\alice`, 14400)}; !slices.Equal(got, want) {
		t.Errorf("MappingsOf(alice) = %+v, want %+v", got, want)
	}
	if got, want := d.MappingsOf(`EXAMPLE\ALICE`), []identity.Mapping{mapping("198.51.100.10", `example\alice`, 14400)}; !slices.Equal(got, want) {
		t.Errorf("MappingsOf(example\\alice) = %+v, want %+v", got, want)
	}
	for _, name := range []string{"alice@example.com", "nobody"} {
		if got := d.MappingsOf(name); got != nil {
			t.Errorf("MappingsOf(%q) = %+v, want nil", name, got)
		}
	}
	bob := `example.com\bob`
	unsorted := fixtureWith(t, func(f *identity.File) {
		f.Mappings = []identity.Mapping{
			mapping("2001:db8::12", bob, 60), mapping("198.51.100.20", bob, 60), mapping("198.51.100.3", bob, 60),
			mapping("198.51.100.20", `example.com\carol`, 60),
		}
	})
	want := []identity.Mapping{mapping("198.51.100.3", bob, 60), mapping("2001:db8::12", bob, 60)}
	if got := unsorted.MappingsOf(bob); !slices.Equal(got, want) {
		t.Errorf("MappingsOf(bob) = %+v, want %+v", got, want)
	}
}

// missing gives the fixture data as a fetch gives it when the command of a
// part fails: the part holds nothing, and parts_missing names it (spec
// 2026-10-17 §3.4). Without U3, the users of U8 alone stay, without groups;
// without U8, the users of U3 alone stay, without names. The group sources
// follow D9 and ruling Q2.
func missing(t *testing.T, part string) *identity.Data {
	t.Helper()
	f := fixtureFile(t)
	var users []identity.User
	for _, u := range f.Users {
		switch part {
		case identity.PartUserGroups:
			u.Groups = nil
			if len(u.Alt) == 0 && u.Email == "" {
				continue
			}
		case identity.PartUserNames:
			u.Alt, u.Email = nil, ""
			if len(u.Groups) == 0 {
				continue
			}
		}
		users = append(users, u)
	}
	f.Users = users
	for i, g := range f.Groups {
		switch {
		case part == identity.PartLDAP && strings.HasPrefix(g.Source, "ldap:"):
			f.Groups[i].Source = identity.SourceLDAP
		case part == identity.PartCIE && strings.HasPrefix(g.Source, "cie:"):
			f.Groups[i].Source = identity.SourceCIE
		}
	}
	switch part {
	case identity.PartLDAP:
		f.Sources.LDAP = nil
	case identity.PartCIE:
		f.Sources.CIE = nil
	case identity.PartGroups:
		f.Groups, f.DUGs = nil, nil
	case identity.PartTags:
		f.Tags = nil
	case identity.PartMappings:
		f.Mappings = nil
	}
	f.PartsMissing = []string{part}
	return identity.New(f)
}

// Shorthands for the members of a test.
func userMember(name string) identity.Member {
	return identity.Member{Kind: identity.MemberUser, Name: name}
}

func groupMember(name, source string) identity.Member {
	return identity.Member{Kind: identity.MemberGroup, Name: name, Source: source}
}

func dugMember(name string) identity.Member {
	return identity.Member{Kind: identity.MemberDUG, Name: name, Source: identity.SourceDUG}
}

func cieMember(name, source string) identity.Member {
	return identity.Member{Kind: identity.MemberCIE, Name: name, Source: source}
}

func unknownMember(name string) identity.Member {
	return identity.Member{Kind: identity.MemberUnknown, Name: name}
}

// §5.2, §5.3: Member reads a source-user member of a rule, one row of the
// table of plan Task 5 at a time: a user by its primary or alternate name in
// any case (N1, N2); an email, which a rule does not resolve (SG4); a group of
// groups[] by its name or its DN in any case (U3, M7, M11); a short name
// (M12); a DUG (U5, U10, D13); a CIE group, also when groups[] lacks it (D1,
// U16); anything else (M13, M17).
func TestMember(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for _, c := range []struct {
		name string
		want identity.Member
	}{
		{`example.com\alice`, userMember(`example.com\alice`)},
		{`EXAMPLE.COM\ALICE`, userMember(`example.com\alice`)},
		{"alice@example.com", userMember(`example.com\alice`)},
		{"Bob@Example.com", userMember(`example.com\bob`)},
		{"robert@example.com", unknownMember("robert@example.com")},
		{domainUsers, groupMember(domainUsers, "ldap:example.com")},
		{"CN=Domain Users,CN=Users,DC=example,DC=com", groupMember(domainUsers, "ldap:example.com")},
		{emptyGroup, groupMember(emptyGroup, "ldap:example.com")},
		{"Engineering", groupMember("engineering", "xmlapi")},
		{`example.com\domain users`, groupMember(domainUsers, "ldap:example.com")},
		{`EXAMPLE.COM\Payroll`, groupMember(payroll, "ldap:example.com")},
		{"dug-a", dugMember("dug-a")},
		{"DUG-AB", dugMember("dug-ab")},
		{`example-cie\cloud-team`, cieMember(`example-cie\cloud-team`, "cie:cie-a")},
		{`EXAMPLE-CIE\Sales-Team`, cieMember(`EXAMPLE-CIE\Sales-Team`, "cie:cie-a")},
		{"cn=no-such,ou=groups,dc=example,dc=com", unknownMember("cn=no-such,ou=groups,dc=example,dc=com")},
		{`other\ghost`, unknownMember(`other\ghost`)},
		{`example\alice`, unknownMember(`example\alice`)},
		{`example.com\nobody`, unknownMember(`example.com\nobody`)},
		{"tag-a", unknownMember("tag-a")},
	} {
		if got := d.Member(c.name); got != c.want {
			t.Errorf("Member(%q) = %+v, want %+v", c.name, got, c.want)
		}
	}
}

// SG13, PD19: while a part is missing, Member gives the kind that the data
// still shows, and the caller asks Complete. Without U5, a group or a DUG is
// unknown, but a CIE domain still names a CIE group. Without U6 and U7, a
// group takes the source of an unknown profile (D9, ruling Q2): then every
// <domain>\<group> can be a CIE group.
func TestMemberWhileAPartIsMissing(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		part, name string
		want       identity.Member
	}{
		{identity.PartUserGroups, domainUsers, groupMember(domainUsers, "ldap:example.com")},
		{identity.PartUserGroups, "dug-a", dugMember("dug-a")},
		{identity.PartUserGroups, "alice@example.com", userMember(`example.com\alice`)},
		{identity.PartGroups, domainUsers, unknownMember(domainUsers)},
		{identity.PartGroups, "dug-a", unknownMember("dug-a")},
		{identity.PartGroups, `example.com\domain users`, unknownMember(`example.com\domain users`)},
		{identity.PartGroups, `example-cie\cloud-team`, cieMember(`example-cie\cloud-team`, "cie:cie-a")},
		{identity.PartGroups, `example.com\carol`, userMember(`example.com\carol`)},
		{identity.PartUserNames, "alice@example.com", unknownMember("alice@example.com")},
		{identity.PartUserNames, `example.com\alice`, userMember(`example.com\alice`)},
		{identity.PartLDAP, domainUsers, groupMember(domainUsers, "ldap")},
		{identity.PartLDAP, "cn=no-such,ou=groups,dc=example,dc=com", unknownMember("cn=no-such,ou=groups,dc=example,dc=com")},
		{identity.PartCIE, `example-cie\cloud-team`, cieMember(`example-cie\cloud-team`, "cie")},
		{identity.PartCIE, `other\ghost`, cieMember(`other\ghost`, "cie")},
		{identity.PartTags, "dug-a", dugMember("dug-a")},
	} {
		d := missing(t, c.part)
		if got := d.Member(c.name); got != c.want {
			t.Errorf("without %s: Member(%q) = %+v, want %+v", c.part, c.name, got, c.want)
		}
		if d.Complete(c.part) {
			t.Errorf("without %s: Complete holds", c.part)
		}
	}
}

// Ruling Q1, M12: the device resolves a short name with the domain of the
// group-mapping profile of the group (U4). While that domain is unknown, or
// sources.ldap is missing (D9), or two groups have one short name, the data
// resolves the name to no one group: Member gives MemberInDoubt with source
// ldap, Group gives nothing, and the caller keeps the rule in doubt. The CIE
// domain of a name does not decide it, because the unknown domain can be that
// domain too. A short name whose cn no LDAP group has stays unknown.
func TestMemberKeepsAShortNameInDoubt(t *testing.T) {
	t.Parallel()
	inDoubt := func(name string) identity.Member {
		return identity.Member{Kind: identity.MemberInDoubt, Name: name, Source: identity.SourceLDAP}
	}
	short := `example.com\domain users`
	for name, d := range map[string]*identity.Data{
		"no domain":       fixtureWith(t, func(f *identity.File) { f.Sources.LDAP[0].Domain = "" }),
		"no sources.ldap": missing(t, identity.PartLDAP),
		"no profile":      fixtureWith(t, func(f *identity.File) { f.Sources.LDAP[0].Name = "other" }),
	} {
		for _, n := range []string{short, `Example-CIE\Domain Users`} {
			if got := d.Member(n); got != inDoubt(n) {
				t.Errorf("%s: Member(%q) = %+v, want %+v", name, n, got, inDoubt(n))
			}
		}
		if g, ok := d.Group(short); ok {
			t.Errorf("%s: Group(%q) = %+v, want none", name, short, g)
		}
		if d.InGroup(`example.com\alice`, short) || d.Members(short) != nil {
			t.Errorf("%s: the short name holds a user", name)
		}
		if got := d.Member(`example.com\nobody`); got != unknownMember(`example.com\nobody`) {
			t.Errorf("%s: Member(nobody) = %+v", name, got)
		}
		if got := d.Member(domainUsers); got.Kind != identity.MemberGroup || got.Name != domainUsers {
			t.Errorf("%s: Member(DN) = %+v, want the group: its base classifies it", name, got)
		}
	}
	twice := fixtureWith(t, func(f *identity.File) {
		f.Groups = append(f.Groups, identity.Group{Name: "cn=payroll,ou=branch,dc=example,dc=com", Source: "ldap:example.com"})
	})
	if got := twice.Member(`example.com\payroll`); got != inDoubt(`example.com\payroll`) {
		t.Errorf("two groups with one short name: Member = %+v", got)
	}
	if g, ok := twice.Group(`example.com\payroll`); ok {
		t.Errorf("two groups with one short name: Group = %+v, want none", g)
	}
	if got := twice.Member(short); got != groupMember(domainUsers, "ldap:example.com") {
		t.Errorf("another short name: Member = %+v", got)
	}
	branch := fixtureWith(t, func(f *identity.File) {
		f.Sources.LDAP = append(f.Sources.LDAP, identity.LDAPSource{Name: "branch", Base: "ou=branch,dc=example,dc=com", Groups: 2})
		f.Groups = append(f.Groups,
			identity.Group{Name: branchStaff, Source: "ldap:branch"},
			identity.Group{Name: "cn=domain users,ou=branch,dc=example,dc=com", Source: "ldap:branch"})
	})
	for _, n := range []string{`example.com\branch staff`, short} {
		if got := branch.Member(n); got != inDoubt(n) {
			t.Errorf("a profile without a domain: Member(%q) = %+v, want %+v", n, got, inDoubt(n))
		}
	}
	if got := branch.Member(`example.com\payroll`); got != groupMember(payroll, "ldap:example.com") {
		t.Errorf("a cn of the profile with a domain alone: Member = %+v", got)
	}
	ou := fixtureWith(t, func(f *identity.File) {
		f.Groups = append(f.Groups, identity.Group{Name: "ou=sales,dc=example,dc=com", Source: "ldap:example.com"})
	})
	if got := ou.Member(`example.com\sales`); got != unknownMember(`example.com\sales`) {
		t.Errorf("a DN without a cn has no short name: Member = %+v", got)
	}
}

// Review focus 5: Known holds for a user, a group or a mapped user of the
// data, in any case. A group DN with spaces is a name of the data, though its
// shape is no user shape. A user that resolves (Resolve), a short name (M12),
// a DUG and an outside user of a mapping (M3, M17) are known; a tag and a
// name of nothing are not. While groups is missing, the groups that U3 lists
// for the users stay known.
func TestKnown(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for _, name := range []string{
		`example.com\alice`, `EXAMPLE.COM\Dave`, "ALICE@example.com", "robert@example.com",
		domainUsers, "CN=Domain Users,CN=Users,DC=example,DC=com", `example.com\domain users`,
		"engineering", "DUG-A", `example-cie\cloud-team`, emptyGroup, `other\ghost`, `Example\Alice`,
	} {
		if !d.Known(name) {
			t.Errorf("Known(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"nobody", "", "tag-a", "cn=no-such,ou=groups,dc=example,dc=com", `example.com\nobody`, "198.51.100.11"} {
		if d.Known(name) {
			t.Errorf("Known(%q) = true, want false", name)
		}
	}
	noGroups := missing(t, identity.PartGroups)
	for _, name := range []string{domainUsers, "dug-a", "TEAM-X"} {
		if !noGroups.Known(name) {
			t.Errorf("without groups: Known(%q) = false, want true", name)
		}
	}
	if noGroups.Known(emptyGroup) {
		t.Error("without groups: a group that no user holds is known")
	}
}

// A member count reads "1 member" for one and "<n> members" else, in every
// answer that counts the members of a group.
func TestMembersText(t *testing.T) {
	t.Parallel()
	for n, want := range map[int]string{0: "0 members", 1: "1 member", 2: "2 members", 20: "20 members"} {
		if got := identity.MembersText(n); got != want {
			t.Errorf("MembersText(%d) = %q, want %q", n, got, want)
		}
	}
}
