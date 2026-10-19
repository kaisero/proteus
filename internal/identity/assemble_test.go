package identity_test

import (
	"bytes"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/identity"
)

var takenAt = time.Date(2026, 10, 17, 20, 0, 0, 0, time.UTC)

// fixtureParts are the parts of a fetch that give testdata/identity/identity.json,
// each in the order of its answer, with the domains of the configuration.
func fixtureParts() (identity.Parts, identity.Domains) {
	m := func(ip, user string) identity.Mapping {
		return identity.Mapping{IP: netip.MustParseAddr(ip), User: user, Type: "XMLAPI", Timeout: 14400}
	}
	p := identity.Parts{
		LDAP: []identity.LDAPSource{{Name: "example.com", Base: "dc=example,dc=com", Groups: 3}},
		// Ruling D10: cie-a synced one group. Its last action is synthetic: no
		// device showed a CIE profile that synced (U16).
		CIE: []identity.CIESource{{Name: "cie-a", Groups: 1, Last: "120 secs ago"}},
		UserIDs: map[string][]string{
			`example.com\carol`: {domainUsers, "engineering", "dug-a", "dug-ab"},
			`example.com\alice`: {domainUsers, payroll},
			`example.com\bob`:   {domainUsers, "team-x"},
		},
		Attrs: []identity.Attributes{
			{Primary: `example.com\bob`, Email: "robert@example.com", Alt: []string{"bob@example.com"}},
			{Primary: `example.com\alice`, Email: "alice@example.com", Alt: []string{"alice@example.com"}},
			{Primary: `example.com\dave`, Alt: []string{"dave@example.com"}},
		},
		Groups: []string{domainUsers, payroll, emptyGroup, "engineering", "team-x", "dug-a", "dug-ab", `example-cie\cloud-team`},
		DUGs:   []string{"dug-ab", "dug-a"},
		Tags: []identity.Tags{
			{User: `example.com\dave`, Tags: []string{"tag-a"}},
			{User: `example.com\carol`, Tags: []string{"tag-a", "tag-b"}},
		},
		Mappings: []identity.Mapping{
			m("2001:db8::11", `example.com\bob`),
			m("198.51.100.11", `example.com\alice`),
			m("198.51.100.10", `example\alice`),
			m("198.51.100.14", `example.com\dave`),
			m("198.51.100.12", `other\ghost`),
			m("198.51.100.13", `example.com\carol`),
		},
	}
	domains := identity.Domains{
		LDAP: map[string]string{"example.com": "example.com"},
		CIE:  map[string]string{"cie-a": "example-cie"},
	}
	return p, domains
}

// §3.3, §4.1: the parts of the fixture assemble into the fixture file.
func TestAssembleGivesTheFixture(t *testing.T) {
	t.Parallel()
	p, domains := fixtureParts()
	equalFiles(t, identity.Assemble(p, domains, takenAt), fixtureFile(t))
}

// §3.3: the source of a group follows from its form, in the order of the
// table: an LDAP DN by the base of its profile in any case (U11); a DN while
// sources.ldap is missing (D9); a name of the dynamic list (U10); a CIE
// domain; a <domain>\<group> while a CIE profile has no known domain (SG2) or
// sources.cie is missing (ruling Q2); else XML API.
func TestClassify(t *testing.T) {
	t.Parallel()
	ldap := []identity.LDAPSource{
		{Name: "example.com", Base: "dc=example,dc=com"},
		{Name: "branch", Base: "OU=Branch,DC=example,DC=com"},
	}
	cie := []identity.CIESource{{Name: "cie-a", Domain: "example-cie"}}
	cieUnknown := []identity.CIESource{{Name: "cie-a", Domain: "example-cie"}, {Name: "cie-b"}}
	dugs := []string{"dug-a"}
	for _, c := range []struct {
		group       string
		ldap        []identity.LDAPSource
		ldapMissing bool
		cie         []identity.CIESource
		cieMissing  bool
		want        string
	}{
		{domainUsers, ldap, false, cie, false, "ldap:example.com"},
		// U11, M11: the base in any case.
		{"CN=Domain Users,CN=Users,DC=EXAMPLE,DC=COM", ldap, false, cie, false, "ldap:example.com"},
		// The longest base that the DN ends with names the profile.
		{"cn=staff,ou=branch,dc=example,dc=com", ldap, false, cie, false, "ldap:branch"},
		// An escaped comma belongs to its value.
		{`cn=team\, east,ou=groups,dc=example,dc=com`, ldap, false, cie, false, "ldap:example.com"},
		// A base matches whole parts of the DN only.
		{"cn=x,adc=example,dc=com", ldap, false, cie, false, "xmlapi"},
		// A DN below no base of a profile is no LDAP group of a known profile.
		{"cn=x,dc=exmple,dc=com", ldap, false, cie, false, "xmlapi"},
		// D9: a DN while sources.ldap is missing is an LDAP group of an unknown profile.
		{"cn=x,dc=exmple,dc=com", nil, true, cie, false, "ldap"},
		{domainUsers, nil, true, nil, true, "ldap"},
		// U10: a name of the dynamic list, in any case.
		{"dug-a", ldap, false, cieUnknown, true, "dug"},
		{"DUG-A", ldap, false, cie, false, "dug"},
		// A CIE profile domain, in any case.
		{`example-cie\cloud-team`, ldap, false, cie, false, "cie:cie-a"},
		{`EXAMPLE-CIE\Cloud-Team`, ldap, false, cie, false, "cie:cie-a"},
		{`example-cie\cloud-team`, ldap, false, cieUnknown, false, "cie:cie-a"},
		// SG2: a CIE profile without a known domain can hold any <domain>\<group>.
		{`other\team`, ldap, false, cieUnknown, false, "cie"},
		// Ruling Q2: the same while sources.cie is missing.
		{`other\team`, ldap, false, nil, true, "cie"},
		{`other\team`, ldap, false, cie, false, "xmlapi"},
		{"engineering", ldap, false, cieUnknown, true, "xmlapi"},
		// A short name has no rule here: Task 5 resolves it to its DN first (M12).
		{`example.com\domain users`, ldap, false, cie, false, "xmlapi"},
		// A name with = before its backslash is no <domain>\<group>.
		{`cn=x\y`, ldap, false, nil, true, "xmlapi"},
		// A part without = makes no DN, after an escape too.
		{`team\`, nil, true, nil, true, "xmlapi"},
		{`cn=x,team`, nil, true, cie, false, "xmlapi"},
		// A key is a letter, then letters, digits and hyphens (RFC 4514).
		{"ou-2=x,dc=example,dc=com", ldap, false, cie, false, "ldap:example.com"},
		{"2cn=x,dc=example,dc=com", nil, true, cie, false, "xmlapi"},
		{"c n=x,dc=example,dc=com", nil, true, cie, false, "xmlapi"},
		// A profile without a base holds no DN, and a shorter base after a
		// longer one does not win.
		{"cn=staff,ou=branch,dc=example,dc=com", []identity.LDAPSource{
			{Name: "no-base"}, {Name: "branch", Base: "ou=branch,dc=example,dc=com"}, {Name: "example.com", Base: "dc=example,dc=com"},
		}, false, cie, false, "ldap:branch"},
	} {
		if got := identity.Classify(c.group, c.ldap, c.ldapMissing, dugs, c.cie, c.cieMissing); got != c.want {
			t.Errorf("Classify(%q, ldap missing %v, cie %v, cie missing %v) = %q, want %q",
				c.group, c.ldapMissing, c.cie, c.cieMissing, got, c.want)
		}
	}
}

// §3.3, D13: U3 and U8 merge by primary name in any case, and the U3 name
// stays. A user of U8 alone, as dave, has no group and no DUG. Alternate
// names and emails keep their case. A block that U18 rewrote names another
// primary name, so it stays a user of its own.
func TestAssembleMergesUsers(t *testing.T) {
	t.Parallel()
	p := identity.Parts{
		UserIDs: map[string][]string{
			`example.com\alice`: {domainUsers},
			`example.com\carol`: {domainUsers, "dug-a"},
		},
		Attrs: []identity.Attributes{
			{Primary: `EXAMPLE.COM\Alice`, Email: "Alice@Example.com", Alt: []string{"Alice@Example.com", `example.com\alice`}},
			{Primary: `example\carol`},
			{Primary: `example.com\dave`, Alt: []string{"dave@example.com"}},
			// A second block of alice adds the names that the first lacks.
			{Primary: `example.com\alice`, Email: "alice@example.com", Alt: []string{"alice@example.com", "a.l@example.com"}},
		},
	}
	got := identity.Assemble(p, identity.Domains{}, takenAt).Users
	want := []identity.User{
		{Name: `example.com\alice`, Alt: []string{"Alice@Example.com", `example.com\alice`, "a.l@example.com"}, Email: "Alice@Example.com", Groups: []string{domainUsers}},
		{Name: `example.com\carol`, Groups: []string{domainUsers, "dug-a"}},
		{Name: `example.com\dave`, Alt: []string{"dave@example.com"}},
		{Name: `example\carol`},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("users %+v\nwant %+v", got, want)
	}
	// Two U3 lines of one user in two cases merge too; a group shows once.
	twice := identity.Assemble(identity.Parts{UserIDs: map[string][]string{
		`example.com\bob`: {domainUsers}, `EXAMPLE.COM\BOB`: {"CN=Domain Users,CN=Users,DC=example,DC=com", "team-x"},
	}}, identity.Domains{}, takenAt).Users
	if len(twice) != 1 || twice[0].Name != `EXAMPLE.COM\BOB` || !slices.Equal(twice[0].Groups, []string{"CN=Domain Users,CN=Users,DC=example,DC=com", "team-x"}) {
		t.Errorf("one user in two cases: %+v", twice)
	}
}

// §4.1: members counts the users whose groups hold the group, in any case. A
// DUG counts the users that U3 lists in it (D13). A group that no user holds
// has 0 members.
func TestAssembleCountsMembers(t *testing.T) {
	t.Parallel()
	p := identity.Parts{
		LDAP: []identity.LDAPSource{{Name: "example.com", Base: "dc=example,dc=com"}},
		UserIDs: map[string][]string{
			`example.com\alice`: {domainUsers, "dug-a"},
			`example.com\bob`:   {"CN=Domain Users,CN=Users,DC=example,DC=com", "Team-X"},
			`example.com\carol`: {domainUsers, "dug-a", "dug-ab"},
		},
		Groups: []string{domainUsers, emptyGroup, "team-x", "dug-a", "dug-ab", "dug-a"},
		DUGs:   []string{"dug-a", "dug-ab"},
	}
	got := identity.Assemble(p, identity.Domains{}, takenAt).Groups
	want := []identity.Group{
		{Name: domainUsers, Source: "ldap:example.com", Members: 3},
		{Name: emptyGroup, Source: "ldap:example.com", Members: 0},
		{Name: "dug-a", Source: "dug", Members: 2},
		{Name: "dug-ab", Source: "dug", Members: 1},
		{Name: "team-x", Source: "xmlapi", Members: 1},
	}
	if !slices.Equal(got, want) {
		t.Errorf("groups %+v\nwant %+v", got, want)
	}
}

// §3.4: parts_missing names each missing part once, sorted. A CIE profile
// without a domain adds sources.cie (SG2). A whole fetch gives [].
func TestAssembleNamesMissingParts(t *testing.T) {
	t.Parallel()
	p := identity.Parts{Missing: []string{identity.PartTags, identity.PartMappings, identity.PartLDAP, identity.PartTags}}
	got := identity.Assemble(p, identity.Domains{}, takenAt).PartsMissing
	if want := []string{"mappings", "sources.ldap", "tags"}; !slices.Equal(got, want) {
		t.Errorf("parts_missing %v, want %v", got, want)
	}
	p.CIE = []identity.CIESource{{Name: "cie-a"}, {Name: "cie-b"}}
	got = identity.Assemble(p, identity.Domains{CIE: map[string]string{"cie-a": "example-cie"}}, takenAt).PartsMissing
	if want := []string{"mappings", "sources.cie", "sources.ldap", "tags"}; !slices.Equal(got, want) {
		t.Errorf("parts_missing %v, want %v", got, want)
	}
	if got := identity.Assemble(identity.Parts{}, identity.Domains{}, takenAt).PartsMissing; got == nil || len(got) != 0 {
		t.Errorf("a whole fetch: %#v, want []", got)
	}
}

// D9, ruling Q2: while sources.ldap or sources.cie is missing, Assemble
// gives a DN or a <domain>\<group> the source of an unknown profile.
func TestAssembleClassifiesWhileASourceIsMissing(t *testing.T) {
	t.Parallel()
	p := identity.Parts{
		Groups:  []string{domainUsers, `example-cie\cloud-team`, "team-x"},
		Missing: []string{identity.PartLDAP, identity.PartCIE},
	}
	got := identity.Assemble(p, identity.Domains{}, takenAt).Groups
	want := []identity.Group{
		{Name: domainUsers, Source: "ldap"},
		{Name: `example-cie\cloud-team`, Source: "cie"},
		{Name: "team-x", Source: "xmlapi"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("groups %+v\nwant %+v", got, want)
	}
}

// Ruling Q1: the domain of an LDAP profile comes from the configuration, as
// the domain of a CIE profile does (SG2). Without it the domain is unknown;
// the base still classifies the groups, and only a CIE profile without a
// domain makes its part missing.
func TestAssembleTakesTheDomains(t *testing.T) {
	t.Parallel()
	p := identity.Parts{
		LDAP:   []identity.LDAPSource{{Name: "example.com", Base: "dc=example,dc=com", Groups: 1}},
		CIE:    []identity.CIESource{{Name: "cie-a", Groups: 1, Last: "Never"}},
		Groups: []string{domainUsers, `example-cie\cloud-team`},
	}
	with := identity.Assemble(p, identity.Domains{
		LDAP: map[string]string{"example.com": "example.com"},
		CIE:  map[string]string{"cie-a": "example-cie"},
	}, takenAt)
	if got := with.Sources.LDAP[0].Domain; got != "example.com" {
		t.Errorf("LDAP domain %q, want example.com", got)
	}
	if got := with.Sources.CIE[0].Domain; got != "example-cie" {
		t.Errorf("CIE domain %q, want example-cie", got)
	}
	if len(with.PartsMissing) != 0 || with.Groups[0].Source != "ldap:example.com" || with.Groups[1].Source != "cie:cie-a" {
		t.Errorf("with the domains: missing %v, groups %+v", with.PartsMissing, with.Groups)
	}
	without := identity.Assemble(p, identity.Domains{}, takenAt)
	if without.Sources.LDAP[0].Domain != "" || without.Sources.CIE[0].Domain != "" {
		t.Errorf("without the domains: %+v", without.Sources)
	}
	if !slices.Equal(without.PartsMissing, []string{identity.PartCIE}) ||
		without.Groups[0].Source != "ldap:example.com" || without.Groups[1].Source != "cie" {
		t.Errorf("without the domains: missing %v, groups %+v", without.PartsMissing, without.Groups)
	}
	if p.LDAP[0].Domain != "" || p.CIE[0].Domain != "" {
		t.Errorf("Assemble changed its parts: %+v %+v", p.LDAP, p.CIE)
	}
}

// SG13: Parts.MappingsPartial gives mappings_partial: true; false leaves the
// key out of the file.
func TestAssembleCopiesMappingsPartial(t *testing.T) {
	t.Parallel()
	for _, partial := range []bool{true, false} {
		f := identity.Assemble(identity.Parts{MappingsPartial: partial}, identity.Domains{}, takenAt)
		if f.MappingsPartial != partial {
			t.Errorf("partial %v: the file says %v", partial, f.MappingsPartial)
		}
		var b bytes.Buffer
		if err := identity.Encode(&b, f); err != nil {
			t.Fatal(err)
		}
		doc := gunzip(t, b.Bytes())
		if strings.Contains(doc, `"mappings_partial":true`) != partial || (!partial && strings.Contains(doc, "mappings_partial")) {
			t.Errorf("partial %v: %s", partial, doc)
		}
	}
}

// The file is stable whatever the order of the answers: users and groups by
// name in any case, DUGs, tags by user, mappings by address with IPv4 first.
// Names keep their case, and a user keeps the U3 order of its groups.
func TestAssembleSortsTheFile(t *testing.T) {
	t.Parallel()
	p := identity.Parts{
		LDAP: []identity.LDAPSource{{Name: "example.com", Base: "dc=example,dc=com"}, {Name: "branch", Base: "ou=branch,dc=example,dc=com"}},
		CIE:  []identity.CIESource{{Name: "cie-b"}, {Name: "cie-a"}},
		UserIDs: map[string][]string{
			`example.com\Bob`:   {"team-x", domainUsers},
			`example.com\alice`: {domainUsers},
		},
		Groups: []string{"team-x", "Engineering", domainUsers},
		DUGs:   []string{"dug-b", "dug-a"},
		Tags: []identity.Tags{
			{User: `example.com\dave`, Tags: []string{"tag-b", "tag-a"}},
			{User: `example.com\Carol`, Tags: []string{"tag-a"}},
		},
		Mappings: []identity.Mapping{
			{IP: netip.MustParseAddr("2001:db8::11"), User: `example.com\Bob`},
			{IP: netip.MustParseAddr("198.51.100.20"), User: `example.com\alice`},
			{IP: netip.MustParseAddr("198.51.100.3"), User: `example.com\alice`},
		},
	}
	f := identity.Assemble(p, identity.Domains{}, takenAt)
	var ldap, cie, users, groups, tagUsers, ips []string
	for _, s := range f.Sources.LDAP {
		ldap = append(ldap, s.Name)
	}
	for _, s := range f.Sources.CIE {
		cie = append(cie, s.Name)
	}
	for _, u := range f.Users {
		users = append(users, u.Name)
	}
	for _, g := range f.Groups {
		groups = append(groups, g.Name)
	}
	for _, tg := range f.Tags {
		tagUsers = append(tagUsers, tg.User)
	}
	for _, m := range f.Mappings {
		ips = append(ips, m.IP.String())
	}
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		{"ldap", ldap, []string{"branch", "example.com"}},
		{"cie", cie, []string{"cie-a", "cie-b"}},
		{"users", users, []string{`example.com\alice`, `example.com\Bob`}},
		{"bob's groups", f.Users[1].Groups, []string{"team-x", domainUsers}},
		{"groups", groups, []string{domainUsers, "Engineering", "team-x"}},
		{"dugs", f.DUGs, []string{"dug-a", "dug-b"}},
		{"tags", tagUsers, []string{`example.com\Carol`, `example.com\dave`}},
		{"dave's tags", f.Tags[1].Tags, []string{"tag-b", "tag-a"}},
		{"mappings", ips, []string{"198.51.100.3", "198.51.100.20", "2001:db8::11"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s %q, want %q", c.name, c.got, c.want)
		}
	}
	if !f.TakenAt.Equal(takenAt) || f.Format != identity.Format {
		t.Errorf("taken_at %v, format %d", f.TakenAt, f.Format)
	}
	p.Tags[0].Tags[0] = "changed"
	p.UserIDs[`example.com\Bob`][0] = "changed"
	if f.Tags[1].Tags[0] != "tag-b" || f.Users[1].Groups[0] != "team-x" {
		t.Error("the file shares a list with its parts")
	}
}
