package index

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/reason"
)

func usersIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-users.xml", "vsys1")
}

// identityIndex is vsys1 of the User-ID fixture: one rule per source-user form.
func identityIndex(t *testing.T) *Index {
	t.Helper()
	return indexOf(t, "../../testdata/config/firewall-identity.xml", "vsys1")
}

// idFile is the identity fixture, testdata/identity/identity.json: no part is
// missing.
func idFile(t *testing.T) identity.File {
	t.Helper()
	b, err := os.ReadFile("../../testdata/identity/identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var f identity.File
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func idData(t *testing.T) *identity.Data {
	t.Helper()
	return identity.New(idFile(t))
}

// without is the fixture as a fetch gives it when one part does not arrive
// (spec 2026-10-17 §3.3, §3.4): the answers of the part are empty, and
// parts_missing names it.
func without(t *testing.T, part string) *identity.Data {
	t.Helper()
	f := idFile(t)
	switch part {
	case identity.PartUserGroups: // U3: no user has a group
		for i := range f.Users {
			f.Users[i].Groups = nil
		}
		for i := range f.Groups {
			f.Groups[i].Members = 0
		}
	case identity.PartGroups: // U5: no group list, no DUG list
		f.Groups, f.DUGs = nil, nil
	case identity.PartTags: // U9
		f.Tags = nil
	case identity.PartUserNames: // U8: no alternate name, no email, no user of U8 alone
		var kept []identity.User
		for _, u := range f.Users {
			if len(u.Groups) > 0 {
				u.Alt, u.Email = nil, ""
				kept = append(kept, u)
			}
		}
		f.Users = kept
	case identity.PartCIE: // U7
		f.Sources.CIE = nil
	case identity.PartLDAP: // U6: a DN is an LDAP group of an unknown profile (D9)
		f.Sources.LDAP = nil
		for i, g := range f.Groups {
			if strings.HasPrefix(g.Source, identity.SourceLDAP+":") {
				f.Groups[i].Source = identity.SourceLDAP
			}
		}
	default:
		t.Fatalf("no part %s", part)
	}
	f.PartsMissing = []string{part}
	return identity.New(f)
}

// users are the user values of the fixture: the four directory users, the
// NetBIOS form of a mapping (M2) and an outside user (M3, M17).
var users = []string{`example.com\alice`, `example.com\bob`, `example.com\carol`, `example.com\dave`, `example\alice`, `other\ghost`}

// reached is the rules a user value reaches with the identity data, by name.
func reached(idx *Index, d *identity.Data, value string) (map[string]bool, Report) {
	rules, rep := idx.With(Providers{Users: d}).Candidates(SourceUser, value)
	return ruleNames(idx, rules), rep
}

// wantReached checks that a value reaches exactly the rules named and the
// rules whose source-user is any.
func wantReached(t *testing.T, idx *Index, value string, got map[string]bool, want ...string) {
	t.Helper()
	exp := ruleNames(idx, idx.RulesWithAny(SourceUser))
	for _, w := range want {
		exp[w] = true
	}
	if !maps.Equal(got, exp) {
		t.Errorf("%s reaches %v, want %v", value, slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(exp)))
	}
}

// memberHit is the hit of a member, if the report holds one.
func memberHit(rep Report, member string) (Hit, bool) {
	i := slices.IndexFunc(rep.Hits, func(h Hit) bool { return h.Name == member })
	if i < 0 {
		return Hit{}, false
	}
	return rep.Hits[i], true
}

// codes are the codes of a report's unresolved entries, by value.
func codes(rep Report) map[string][]reason.Code {
	out := map[string][]reason.Code{}
	for _, u := range rep.Unresolved {
		out[u.Value] = append(out[u.Value], u.Code)
	}
	return out
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

// With the identity data, a directory user reaches the rule that names its
// group, and the local database still answers for its own users and groups:
// one membership, reported once.
func TestUserResolverWithADirectory(t *testing.T) {
	t.Parallel()
	idx := usersIndex(t)
	view := idx.With(Providers{Users: idData(t)})

	rules, _ := view.Candidates(SourceUser, `example.com\carol`)
	if !ruleNames(idx, rules)["engineering-allowed"] {
		t.Error("carol's XML API group engineering was not reached")
	}
	rules, rep := view.Candidates(SourceUser, "alice")
	if !ruleNames(idx, rules)["admins-allowed"] {
		t.Error("the local group of the local user alice was not reached")
	}
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

// A user reaches each rule that names it in a form the device reads (spec
// 2026-10-17 §5.2, §5.3): its primary name in any case (N1), its UPN (N2), its
// LDAP group by U3, a rule with a user and a group (M9), the group DN in
// another case (M11) and the short name of the group (M12). Each hit carries
// the scope of the index and says why it matched.
func TestUserResolverMatchesTheRuleForms(t *testing.T) {
	t.Parallel()
	idx, d := identityIndex(t), idData(t)
	vsys1 := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	for _, value := range []string{`example.com\alice`, `EXAMPLE.COM\ALICE`} {
		got, rep := reached(idx, d, value)
		wantReached(t, idx, value, got, "u-user", "u-upn", "u-ldap-group", "u-multi", "u-dn-case", "u-short")
		for member, want := range map[string]Hit{
			`example.com\alice`:                          {Kind: "user", Via: value},
			"alice@example.com":                          {Kind: "user", Via: value},
			"cn=domain users,cn=users,dc=example,dc=com": {Kind: "user-group", Via: "ldap:example.com, 3 members"},
			"CN=Domain Users,CN=Users,DC=example,DC=com": {Kind: "user-group", Via: "ldap:example.com, 3 members"},
			`example.com\domain users`:                   {Kind: "user-group", Via: "ldap:example.com, 3 members"},
			"cn=payroll,ou=groups,dc=example,dc=com":     {Kind: "user-group", Via: "ldap:example.com, 1 member"},
		} {
			want.Name, want.Scope = member, vsys1
			if h, ok := memberHit(rep, member); !ok || h != want {
				t.Errorf("%s: hit of %s = %+v, want %+v", value, member, h, want)
			}
		}
		for v, cs := range codes(rep) {
			if slices.Contains(cs, "gap.no-user-directory") || slices.Contains(cs, "gap.dynamic-user-group") {
				t.Errorf("%s: the data is loaded, yet %s has %v", value, v, cs)
			}
		}
	}
}

// As observed on fw01, PAN-OS 11.2.5, a mapping in the stored form
// example\alice matches no user rule and no group (spec 2026-10-17 M2).
func TestUserResolverNetBIOSFormMatchesNoName(t *testing.T) {
	t.Parallel()
	idx := identityIndex(t)
	got, _ := reached(idx, idData(t), `example\alice`)
	wantReached(t, idx, `example\alice`, got)
}

// An outside user matches a rule that names it literally (M17).
func TestUserResolverLiteralName(t *testing.T) {
	t.Parallel()
	idx := identityIndex(t)
	got, rep := reached(idx, idData(t), `other\ghost`)
	wantReached(t, idx, `other\ghost`, got, "u-ghost")
	if h, ok := memberHit(rep, `other\ghost`); !ok || h.Kind != "user" || h.Via != `other\ghost` {
		t.Errorf("hit %+v", h)
	}
}

// An XML API group matches its members and no other user (M7).
func TestUserResolverXMLAPIGroup(t *testing.T) {
	t.Parallel()
	idx, d := identityIndex(t), idData(t)
	got, rep := reached(idx, d, `example.com\carol`)
	wantReached(t, idx, `example.com\carol`, got, "u-xmlapi", "u-ldap-group", "u-dn-case", "u-short", "u-dug", "u-dug-ab")
	if h, _ := memberHit(rep, "engineering"); h.Kind != "user-group" || h.Via != "xmlapi, 1 member" {
		t.Errorf("hit %+v", h)
	}
	if got, _ := reached(idx, d, `example.com\bob`); got["u-xmlapi"] {
		t.Error("bob is no member of engineering")
	}
}

// DUG membership comes from U3 only (D13): U3 lists both DUGs for carol. dave
// has the tag of dug-a, and U3 does not list him, so he is in no DUG. No code
// evaluates the tag filter (PD20).
func TestUserResolverDUGFromU3(t *testing.T) {
	t.Parallel()
	idx, d := identityIndex(t), idData(t)
	got, rep := reached(idx, d, `example.com\carol`)
	if !got["u-dug"] || !got["u-dug-ab"] {
		t.Errorf("carol reaches %v", got)
	}
	for _, dug := range []string{"dug-a", "dug-ab"} {
		if h, _ := memberHit(rep, dug); h.Kind != "dynamic-user-group" || h.Via != "dug, 1 member" {
			t.Errorf("hit of %s %+v", dug, h)
		}
	}
	got, rep = reached(idx, d, `example.com\dave`)
	if got["u-dug"] || got["u-dug-ab"] {
		t.Errorf("dave reaches %v", got)
	}
	if len(codes(rep)["dug-a"]) > 0 {
		t.Errorf("a DUG is judged by U3, so it is in no doubt: %v", rep.Unresolved)
	}
	// A DUG that the group list lacks takes its member count from U3.
	f := idFile(t)
	f.Groups = slices.DeleteFunc(f.Groups, func(g identity.Group) bool { return g.Name == "dug-a" })
	if _, rep := reached(idx, identity.New(f), `example.com\carol`); !slices.Contains(rep.Hits,
		Hit{Name: "dug-a", Kind: "dynamic-user-group", Scope: idx.Scope(), Via: "dug, 1 member"}) {
		t.Errorf("hits %+v", rep.Hits)
	}
}

// A DUG that the group list lacks takes its member count from the data, which
// counts it once: a resolve reads no list of members, so a DUG of 3000
// members costs it no more allocations than a DUG of 300. The hit keeps its
// Via text.
//
// It does not run in parallel: it counts the allocations of the process. It
// does not run with the race detector, whose count varies.
//
//nolint:paralleltest // it counts allocations
func TestUserResolverCountsNoDUGMembers(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates on its own")
	}
	idx := identityIndex(t)
	allocs := func(members int) float64 {
		f := idFile(t)
		f.Groups = slices.DeleteFunc(f.Groups, func(g identity.Group) bool { return g.Name == "dug-a" })
		for i := range members - 1 { // carol is the first member
			f.Users = append(f.Users, identity.User{Name: fmt.Sprintf(`example.com\member-%04d`, i), Groups: []string{"dug-a"}})
		}
		with := idx.With(Providers{Users: identity.New(f)})
		_, rep := with.Candidates(SourceUser, `example.com\carol`)
		if h, _ := memberHit(rep, "dug-a"); h.Via != fmt.Sprintf("dug, %d members", members) {
			t.Errorf("%d members: hit %+v", members, h)
		}
		return testing.AllocsPerRun(20, func() { with.Candidates(SourceUser, `example.com\carol`) })
	}
	// Both counts are 256 or more: a smaller int goes into the Via text
	// without an allocation.
	if few, many := allocs(300), allocs(3000); few != many {
		t.Errorf("a resolve allocates %.0f times for a DUG of 300 members and %.0f for one of 3000", few, many)
	}
}

// A CIE group never decides: every user gives it as an unresolved entry, and
// no user reaches its rule (spec 2026-10-17 D1, §5.6).
func TestUserResolverCIEGroupIsADoubt(t *testing.T) {
	t.Parallel()
	idx, d := identityIndex(t), idData(t)
	for _, value := range users {
		got, rep := reached(idx, d, value)
		if cs := codes(rep)[`example-cie\cloud-team`]; !slices.Equal(cs, []reason.Code{"doubt.user-cie-group"}) {
			t.Errorf("%s: %v", value, rep.Unresolved)
		}
		if got["u-cie"] {
			t.Errorf("%s reaches u-cie", value)
		}
	}
}

// With sources.cie missing, a <domain>\<name> that names no user and no
// group of the data can be a CIE group, so it reads as one (ruling Q2): the
// member other\ghost is in doubt for every user and no hit. Only its own
// name in the same case reaches its rule, by the name the rule holds, as the
// device matches a literal source-user (M17). The users and LDAP groups still
// read as before.
func TestUserResolverWithoutCIESourcesADomainNameIsCIE(t *testing.T) {
	t.Parallel()
	idx, d := identityIndex(t), without(t, identity.PartCIE)
	for _, value := range users {
		got, rep := reached(idx, d, value)
		if cs := codes(rep)[`other\ghost`]; !slices.Equal(cs, []reason.Code{"doubt.user-cie-group"}) {
			t.Errorf("%s: unresolved %v", value, rep.Unresolved)
		}
		if h, ok := memberHit(rep, `other\ghost`); ok {
			t.Errorf("%s: a member in doubt is a hit: %+v", value, h)
		}
		if got["u-ghost"] != (value == `other\ghost`) {
			t.Errorf("%s reaches %v", value, got)
		}
	}
	got, _ := reached(idx, d, `example.com\alice`)
	wantReached(t, idx, `example.com\alice`, got, "u-user", "u-upn", "u-ldap-group", "u-multi", "u-dn-case", "u-short")
}

// A group without members, and a DN that is no group, match no directory user
// (M13).
func TestUserResolverEmptyGroupsMatchNoUser(t *testing.T) {
	t.Parallel()
	idx, d := identityIndex(t), idData(t)
	for _, value := range users {
		if got, _ := reached(idx, d, value); got["u-empty"] || got["u-no-group"] {
			t.Errorf("%s reaches %v", value, got)
		}
	}
}

// Without identity data the answer says what it could not judge, as before
// the data existed (spec 2026-10-17 §5.5): no directory, and each dynamic user
// group, whose members only User-ID knows.
func TestUserResolverWithoutDataKeepsTheGaps(t *testing.T) {
	t.Parallel()
	idx := identityIndex(t)
	rules, rep := idx.With(Providers{}).Candidates(SourceUser, `example.com\carol`)
	cs := codes(rep)
	if !slices.Equal(cs[`example.com\carol`], []reason.Code{"gap.no-user-directory"}) ||
		!slices.Equal(cs["dug-a"], []reason.Code{"gap.dynamic-user-group"}) ||
		!slices.Equal(cs["dug-ab"], []reason.Code{"gap.dynamic-user-group"}) {
		t.Errorf("unresolved %v", rep.Unresolved)
	}
	wantReached(t, idx, `example.com\carol`, ruleNames(idx, rules))
}

// A missing part never gives an exact answer (spec 2026-10-17 §5.5, PD19):
// each member that the part judges is an unresolved entry
// doubt.user-data-missing that names the part, and no hit, whatever the user.
// Without tags no member is in doubt: tags decide no match (D13). A local
// group is the configuration's, so no part puts it in doubt.
func TestUserResolverMissingParts(t *testing.T) {
	t.Parallel()
	groupRules := []string{"u-ldap-group", "u-xmlapi", "u-multi", "u-dn-case", "u-short", "u-empty", "u-dug", "u-dug-ab"}
	for _, tc := range []struct {
		part  string
		rules []string
	}{
		{identity.PartUserGroups, groupRules},
		{identity.PartGroups, append(slices.Clone(groupRules), "u-no-group", "u-ghost")},
		{identity.PartTags, nil},
		{identity.PartUserNames, []string{"u-upn"}},
	} {
		t.Run(tc.part, func(t *testing.T) {
			t.Parallel()
			idx, d := identityIndex(t), without(t, tc.part)
			for _, value := range users {
				_, rep := reached(idx, d, value)
				doubted := map[string]bool{}
				members := map[string]bool{}
				for _, u := range rep.Unresolved {
					if u.Code != "doubt.user-data-missing" {
						continue
					}
					if !strings.Contains(u.Reason, tc.part) {
						t.Errorf("%s: %s: the entry names no part: %s", value, u.Value, u.Reason)
					}
					members[u.Value] = true
					for name := range ruleNames(idx, idx.RulesReaching(SourceUser, u.Value)) {
						doubted[name] = true
					}
				}
				if got, want := slices.Sorted(maps.Keys(doubted)), slices.Sorted(slices.Values(tc.rules)); !slices.Equal(got, want) {
					t.Errorf("%s: rules in doubt %v, want %v", value, got, want)
				}
				for _, h := range rep.Hits {
					if members[h.Name] {
						t.Errorf("%s: %s is in doubt and a hit: %+v", value, h.Name, h)
					}
				}
			}
		})
	}
}

// A short name that the data resolves to no one group can name a group on the
// device, so its rule stays in doubt (spec 2026-10-17 M12, ruling Q1, PD19):
// while sources.ldap is missing (D9), and when two LDAP groups have the short
// name.
func TestUserResolverShortNameInDoubt(t *testing.T) {
	t.Parallel()
	idx := identityIndex(t)
	f := idFile(t)
	f.Groups = append(f.Groups, identity.Group{Name: "cn=domain users,ou=branch,dc=example,dc=com", Source: "ldap:example.com"})
	for _, tc := range []struct {
		name string
		data *identity.Data
		says string
	}{
		{"without sources.ldap", without(t, identity.PartLDAP), identity.PartLDAP},
		{"two groups of one short name", identity.New(f), "two groups"},
	} {
		got, rep := reached(idx, tc.data, `example.com\alice`)
		i := slices.IndexFunc(rep.Unresolved, func(u Unresolved) bool { return u.Value == `example.com\domain users` })
		if i < 0 || rep.Unresolved[i].Code != "doubt.user-data-missing" || !strings.Contains(rep.Unresolved[i].Reason, tc.says) {
			t.Errorf("%s: unresolved %v", tc.name, rep.Unresolved)
		}
		if got["u-short"] {
			t.Errorf("%s: alice reaches u-short", tc.name)
		}
	}
}

// A group DN holds spaces and commas, so looksLikeUser refuses its shape. The
// identity data knows it, so with the data it is a user term: the members that
// name the group, in any case (M11), are hits, which search reads as findings,
// and their rules are reached (Review focus 5). Without the data the user
// value space gives no hit.
func TestAGroupDNWithSpacesIsAUserTerm(t *testing.T) {
	t.Parallel()
	idx := identityIndex(t)
	const dn = "cn=domain users,cn=users,dc=example,dc=com"
	got, rep := reached(idx, idData(t), dn)
	wantReached(t, idx, dn, got, "u-ldap-group", "u-dn-case")
	for _, member := range []string{dn, "CN=Domain Users,CN=Users,DC=example,DC=com"} {
		if h, ok := memberHit(rep, member); !ok || h.Kind != "user-group" || h.Via != "ldap:example.com, 3 members" {
			t.Errorf("hit of %s: %+v", member, h)
		}
	}
	if _, rep := idx.Candidates(SourceUser, dn); len(rep.Hits) != 0 {
		t.Errorf("without data the DN is no user term: %+v", rep.Hits)
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
