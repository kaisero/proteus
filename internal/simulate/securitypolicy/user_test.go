package securitypolicy

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/identity"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
)

// userRule is a security rule from inside to outside to one destination, with
// source, application and service any. Without users, the rule has no
// source-user element.
func userRule(name, action, dst string, users []string) string {
	var b strings.Builder
	b.WriteString(`<entry name="` + name + `"><from><member>inside</member></from><to><member>outside</member></to>` +
		`<source><member>any</member></source><destination><member>` + dst + `</member></destination>`)
	if len(users) > 0 {
		b.WriteString("<source-user>")
		for _, u := range users {
			b.WriteString("<member>" + u + "</member>")
		}
		b.WriteString("</source-user>")
	}
	b.WriteString(`<application><member>any</member></application><service><member>any</member></service>` +
		`<action>` + action + `</action></entry>`)
	return b.String()
}

func users(names ...string) []string { return names }

// identityFixture is the User-ID fixture configuration: one rule per
// source-user form (spec 2026-10-17, plan Fixtures).
const identityFixture = "../../../testdata/config/firewall-identity.xml"

// userConfig is the User-ID fixture with more rules after its own, written to
// a new file.
func userConfig(t *testing.T, extra ...string) string {
	t.Helper()
	raw, err := os.ReadFile(identityFixture)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(raw), "</rules>", strings.Join(extra, "")+"</rules>", 1)
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// userEnv loads a configuration's vsys1 with the given identity data.
func userEnv(t *testing.T, path string, data *identity.Data) *simulate.Env {
	t.Helper()
	return &simulate.Env{Load: func(_, vsys string) (simulate.Target, error) {
		cfg, _, err := config.Load(path)
		if err != nil {
			return simulate.Target{}, err
		}
		set := index.NewSet(cfg)
		sc := config.Scope{Sort: config.ScopeVsys, Name: vsys}
		if _, err := set.Index(sc, resolve.Security); err != nil {
			return simulate.Target{}, err
		}
		return simulate.Target{Config: cfg, Indexes: set.Provider(sc), Providers: index.Providers{Users: data}}, nil
	}}
}

// userFlow is a flow on tcp/443 from inside to outside, the zones given, with
// a user; "" gives none.
func userFlow(src, dst, user string) simulate.Flow {
	return simulate.Flow{
		Source: ep(src), Destination: ep(dst), Protocol: "tcp", DestPort: 443,
		FromZone: "inside", ToZone: "outside", User: user,
	}
}

// idFile is the identity fixture, testdata/identity/identity.json: no part is
// missing. Each call gives a new copy.
func idFile(t *testing.T) identity.File {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/identity/identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var f identity.File
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

var (
	idOnce sync.Once
	idOnly *identity.Data
)

// idData is the identity fixture, loaded once. The data is read-only.
func idData(t *testing.T) *identity.Data {
	t.Helper()
	f := idFile(t)
	idOnce.Do(func() { idOnly = identity.New(f) })
	return idOnly
}

// without is the fixture as a fetch gives it when one part does not arrive
// (spec 2026-10-17 §3.3, §3.4): the answers of the part are empty, and
// parts_missing names it. "mappings-partial" is the whole table, cut or
// read while it moved (SG13).
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
	case identity.PartMappings: // U1
		f.Mappings = nil
	case "mappings-partial":
		f.MappingsPartial = true
		return identity.New(f)
	default:
		t.Fatalf("no part %s", part)
	}
	f.PartsMissing = []string{part}
	return identity.New(f)
}

// userRun runs a flow on the User-ID fixture with the data.
func userRun(t *testing.T, data *identity.Data, f simulate.Flow) (simulate.Run, Verdict) {
	t.Helper()
	return run(t, userEnv(t, identityFixture, data), f)
}

// noUser is a source without a mapping in the fixture.
const noUser = "203.0.113.5"

// hasCode says whether reasons hold one of a code, and gives its text.
func hasCode(rs simulate.Reasons, code reason.Code) (string, bool) {
	i := slices.IndexFunc(rs, func(r reason.Reason) bool { return r.Code == code })
	if i < 0 {
		return "", false
	}
	return rs[i].Text, true
}

// decides checks the rule or the default rule that decides a flow.
func decides(t *testing.T, v Verdict, what, want string) {
	t.Helper()
	got := first(v)
	if v.Rule == nil && v.Default != "" {
		got = v.Default
	}
	if got != want || len(v.Undecided) > 0 {
		t.Errorf("%s: decided by %s, undecided %v; want %s", what, got, v.Undecided, want)
	}
}

// M1, §5.1: the mapping of the source address gives the user, as stored.
func TestAMappingDecidesTheUser(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow("198.51.100.11", "192.0.2.10", ""))
	decides(t, v, "alice by her mapping", "u-ldap-group")
	want := FlowUser{Name: `example.com\alice`, From: "mapping", IP: "198.51.100.11", Directory: true, Judged: true}
	if v.User == nil || *v.User != want {
		t.Errorf("user %+v, want %+v", v.User, want)
	}
	if text, ok := hasCode(r.Notes, "note.user-from-mapping"); !ok || !strings.Contains(text, "198.51.100.11") {
		t.Errorf("notes %v", r.Notes)
	}
	if st := stage(r, "match-user"); st.Fidelity.Level() != "exact" || !strings.Contains(st.Detail, `example.com\alice`) {
		t.Errorf("stage %s: %s", st.Fidelity, st.Detail)
	}
	b, err := json.Marshal(v.User)
	if err != nil || string(b) != `{"name":"example.com\\alice","from":"mapping","ip":"198.51.100.11","directory":true}` {
		t.Errorf("JSON %s, %v", b, err)
	}
}

// D5, M1: a mapping wins over the user given, and the note names both.
func TestAMappingWinsOverTheGivenUser(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow("198.51.100.11", "192.0.2.11", `example.com\bob`))
	decides(t, v, "alice, not bob", "u-user")
	if v.User == nil || v.User.Name != `example.com\alice` || v.User.Given != `example.com\bob` || v.User.From != "mapping" {
		t.Errorf("user %+v", v.User)
	}
	if text, ok := hasCode(r.Notes, "note.user-from-mapping"); !ok || !strings.Contains(text, `example.com\alice`) || !strings.Contains(text, `example.com\bob`) {
		t.Errorf("notes %v", r.Notes)
	}
}

// §5.1: without a mapping, the user given decides.
func TestTheGivenUserWithoutAMapping(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.11", `example.com\alice`))
	decides(t, v, "the given alice", "u-user")
	want := FlowUser{Name: `example.com\alice`, From: "given", Directory: true, Judged: true}
	if v.User == nil || *v.User != want {
		t.Errorf("user %+v, want %+v", v.User, want)
	}
	if len(r.Notes) != 0 {
		t.Errorf("notes %v", r.Notes)
	}
}

// N2, D7: a UPN as --user resolves to its primary name, with a note. A UPN is
// an alternate name, so the answer stays exact.
func TestAGivenUPNResolves(t *testing.T) {
	t.Parallel()
	for _, dst := range []string{"192.0.2.11", "192.0.2.12"} {
		r, v := userRun(t, idData(t), userFlow(noUser, dst, "alice@example.com"))
		decides(t, v, dst, map[string]string{"192.0.2.11": "u-user", "192.0.2.12": "u-upn"}[dst])
		if v.User == nil || v.User.Name != `example.com\alice` || v.User.Given != "alice@example.com" {
			t.Errorf("user %+v", v.User)
		}
		if _, ok := hasCode(r.Notes, "note.user-resolved"); !ok {
			t.Errorf("notes %v", r.Notes)
		}
		if st := stage(r, "match-user"); st.Fidelity.Level() != "exact" {
			t.Errorf("stage %s", st.Fidelity)
		}
	}
	// The primary name in another case is no resolution.
	r, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.11", `EXAMPLE.COM\ALICE`))
	decides(t, v, "upper case", "u-user")
	if _, ok := hasCode(r.Notes, "note.user-resolved"); ok || v.User.Given != `EXAMPLE.COM\ALICE` {
		t.Errorf("notes %v, user %+v", r.Notes, v.User)
	}
}

// N7, PD21: an email as --user resolves while identity.InputEmail holds, and
// the answer is inferred.
func TestAGivenEmailFollowsN7(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.18", "robert@example.com"))
	decides(t, v, "bob by his email", "u-multi")
	if v.User == nil || v.User.Name != `example.com\bob` {
		t.Errorf("user %+v", v.User)
	}
	if text, ok := hasCode(r.Notes, "note.user-resolved"); !ok || !strings.Contains(text, "email") {
		t.Errorf("notes %v", r.Notes)
	}
	if st := stage(r, "match-user"); st.Fidelity.Level() != "inferred" || r.Fidelity.Level() != "inferred" {
		t.Errorf("stage %s, run %s", st.Fidelity, r.Fidelity)
	}
}

// Review focus 3, SG10: a name outside the directory stays as given. It
// matches known-user and no rule that names a directory user.
func TestAGivenNameOutsideTheDirectory(t *testing.T) {
	t.Parallel()
	const typo = `exmple.com\alice`
	r, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.13", typo))
	decides(t, v, "known-user", "u-known")
	want := FlowUser{Name: typo, From: "given", Judged: true}
	if v.User == nil || *v.User != want {
		t.Errorf("user %+v, want %+v", v.User, want)
	}
	if text, ok := hasCode(r.Notes, "note.user-not-in-directory"); !ok || !strings.Contains(text, typo) {
		t.Errorf("notes %v", r.Notes)
	}
	_, v = userRun(t, idData(t), userFlow(noUser, "192.0.2.11", typo))
	decides(t, v, "the user rule", "interzone-default")
	// A name of no user shape, such as one with a space, is no user of the
	// data either: it keeps no rule in doubt.
	r, v = userRun(t, idData(t), userFlow(noUser, "192.0.2.13", `example.com\alice smith`))
	decides(t, v, "a name with a space", "u-known")
	if len(v.Doubts) != 0 || stage(r, "match-user").Fidelity.Level() != "exact" {
		t.Errorf("doubts %s, stage %s", doubtList(v), stage(r, "match-user").Fidelity)
	}
}

// M2: a mapping in the stored form example\alice matches no user rule, no
// LDAP group, no XML API group and no DUG, and it matches known-user.
func TestTheNetBIOSMappingMatchesNoName(t *testing.T) {
	t.Parallel()
	for _, dst := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.16", "192.0.2.17"} {
		_, v := userRun(t, idData(t), userFlow("198.51.100.10", dst, ""))
		decides(t, v, dst, "interzone-default")
	}
	r, v := userRun(t, idData(t), userFlow("198.51.100.10", "192.0.2.13", ""))
	decides(t, v, "known-user", "u-known")
	if _, ok := hasCode(r.Notes, "note.user-not-in-directory"); !ok || v.User.Directory {
		t.Errorf("notes %v, user %+v", r.Notes, v.User)
	}
}

// M3: known-user matches a mapped user outside the directory.
func TestKnownUserMatchesAnOutsideUser(t *testing.T) {
	t.Parallel()
	_, v := userRun(t, idData(t), userFlow("198.51.100.12", "192.0.2.13", ""))
	decides(t, v, `other\ghost`, "u-known")
}

// M17: a mapped user outside the directory matches the rule that names it.
func TestAnOutsideUserMatchesItsLiteralRule(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow("198.51.100.12", "192.0.2.25", ""))
	decides(t, v, `other\ghost`, "u-ghost")
	if st := stage(r, "match-user"); st.Fidelity.Level() != "exact" {
		t.Errorf("stage %s", st.Fidelity)
	}
}

// Ruling M17: a flow user that equals a rule member as written matches that
// rule when the member names no group and the data can judge it. A member in
// doubt does not decide: the rule stays a candidate in doubt (Task 13 fix
// ruling). A rule with a CIE group and the literal user still matches by the
// literal.
func TestALiteralValueDoesNotDecideAMemberInDoubt(t *testing.T) {
	t.Parallel()
	// Without groups, other\ghost can be a group, so the member is in doubt.
	_, v := userRun(t, without(t, identity.PartGroups), userFlow("198.51.100.12", "192.0.2.25", ""))
	if len(v.Undecided) == 0 || !slices.Contains(doubtCodesOf(v, "u-ghost"), "doubt.user-data-missing") {
		t.Errorf("a member in doubt: first %s, undecided %v, doubts %s", first(v), v.Undecided, doubtList(v))
	}
	// A rule with a CIE group and the literal user.
	path := appConfig(t, "", userRule("u-both", "allow", "any", users(`example-cie\cloud-team`, `other\ghost`)))
	r, v := run(t, userEnv(t, path, idData(t)), userFlow("198.51.100.12", "192.0.2.25", ""))
	decides(t, v, "a CIE group and the literal user", "u-both")
	if len(v.Doubts) != 0 || stage(r, "match-user").Fidelity.Level() != "exact" {
		t.Errorf("doubts %s, stage %s", doubtList(v), stage(r, "match-user").Fidelity)
	}
}

// M12, §5.2: a group name given as the user is no user. As observed on fw01,
// PAN-OS 11.2.5, the short name as source-user matches nothing (spec
// 2026-10-17 M12), so the rule that names the group by that text does not
// match. The same holds for every form of a group and for a DUG.
func TestAGroupNameIsNoUser(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ user, dst, rule string }{
		{`example.com\domain users`, "192.0.2.20", "u-short"},
		{`example.com\domain users`, "192.0.2.19", "u-dn-case"},
		{`example.com\domain users`, "192.0.2.10", "u-ldap-group"},
		{"cn=domain users,cn=users,dc=example,dc=com", "192.0.2.10", "u-ldap-group"},
		{"CN=Domain Users,CN=Users,DC=example,DC=com", "192.0.2.19", "u-dn-case"},
		{"dug-a", "192.0.2.17", "u-dug"},
		{"engineering", "192.0.2.16", "u-xmlapi"},
	} {
		_, v := userRun(t, idData(t), userFlow(noUser, c.dst, c.user))
		decides(t, v, c.user+" at "+c.rule, "interzone-default")
	}
	// A CIE group name as the user keeps the CIE rule in doubt, as any user
	// does (§5.6).
	_, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.24", `example-cie\cloud-team`))
	if len(v.Undecided) == 0 || !slices.Contains(doubtCodesOf(v, "u-cie"), "doubt.user-cie-group") {
		t.Errorf("a CIE group name: first %s, undecided %v, doubts %s", first(v), v.Undecided, doubtList(v))
	}
}

// D6, M4, M5, SG5: with no user, the flow matches unknown and not known-user,
// and the answer is inferred: the device's test command matches known-user
// here.
func TestNoUserMatchesUnknownInferred(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.14", ""))
	decides(t, v, "unknown", "u-unknown")
	if v.User == nil || v.User.Name != "" || v.User.From != "none" || !v.User.Judged {
		t.Errorf("user %+v", v.User)
	}
	if _, ok := hasCode(r.Notes, "note.user-unknown-inferred"); !ok {
		t.Errorf("notes %v", r.Notes)
	}
	if st := stage(r, "match-user"); st.Fidelity.Level() != "inferred" || r.Fidelity.Level() != "inferred" {
		t.Errorf("stage %s, run %s", st.Fidelity, r.Fidelity)
	}
	_, v = userRun(t, idData(t), userFlow(noUser, "192.0.2.13", ""))
	decides(t, v, "known-user", "interzone-default")
}

// SG5: a flow whose candidates name no user keeps its fidelity.
func TestNoUserWithoutUserRulesKeepsTheFidelity(t *testing.T) {
	t.Parallel()
	f := userFlow(noUser, "192.0.2.26", "")
	before, _ := userRun(t, nil, f)
	r, v := userRun(t, idData(t), f)
	decides(t, v, "no source-user", "u-none")
	if r.Fidelity.String() != before.Fidelity.String() || stage(r, "match-user").Fidelity.Level() != "exact" {
		t.Errorf("fidelity %s, before %s", r.Fidelity, before.Fidelity)
	}
	if _, ok := hasCode(r.Notes, "note.user-unknown-inferred"); ok {
		t.Errorf("notes %v", r.Notes)
	}
	if v.User == nil || v.User.Judged {
		t.Errorf("user %+v", v.User)
	}
}

// M6, SG12: pre-logon matches the literal pre-logon only, and the answer is
// inferred.
func TestPreLogon(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.15", "pre-logon"))
	decides(t, v, "pre-logon", "u-prelogon")
	if st := stage(r, "match-user"); st.Fidelity.Level() != "inferred" {
		t.Errorf("stage %s", st.Fidelity)
	}
	if _, ok := hasCode(r.Notes, "note.user-not-in-directory"); ok {
		t.Errorf("notes %v", r.Notes)
	}
	for _, dst := range []string{"192.0.2.13", "192.0.2.14"} {
		_, v = userRun(t, idData(t), userFlow(noUser, dst, "PRE-LOGON"))
		decides(t, v, dst, "interzone-default")
	}
}

// M7: an XML API group matches its members and no other user.
func TestXMLAPIGroup(t *testing.T) {
	t.Parallel()
	_, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.16", `example.com\carol`))
	decides(t, v, "carol", "u-xmlapi")
	_, v = userRun(t, idData(t), userFlow(noUser, "192.0.2.16", `example.com\bob`))
	decides(t, v, "bob", "interzone-default")
}

// M8, D13: U3 lists the DUGs of a user, and they decide.
func TestDUGMatchesByU3(t *testing.T) {
	t.Parallel()
	for dst, rule := range map[string]string{"192.0.2.17": "u-dug", "192.0.2.23": "u-dug-ab"} {
		r, v := userRun(t, idData(t), userFlow("198.51.100.13", dst, ""))
		decides(t, v, dst, rule)
		if st := stage(r, "match-user"); st.Fidelity.Level() != "exact" {
			t.Errorf("%s: stage %s", dst, st.Fidelity)
		}
	}
}

// D13: no code evaluates a DUG filter. dave has the tag tag-a and U3 lists him
// in no DUG, so he is in none, and no doubt is kept.
func TestADUGFilterIsNotEvaluated(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow("198.51.100.14", "192.0.2.17", ""))
	decides(t, v, "dave", "interzone-default")
	if len(v.Doubts) != 0 || stage(r, "match-user").Fidelity.Level() != "exact" {
		t.Errorf("doubts %s, stage %s", doubtList(v), stage(r, "match-user").Fidelity)
	}
}

// M9: the members of one rule combine with OR.
func TestAUserAndAGroupCombineWithOr(t *testing.T) {
	t.Parallel()
	_, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.18", `example.com\bob`))
	decides(t, v, "bob, the user", "u-multi")
	_, v = userRun(t, idData(t), userFlow("198.51.100.11", "192.0.2.18", ""))
	decides(t, v, "alice, in payroll", "u-multi")
	_, v = userRun(t, idData(t), userFlow(noUser, "192.0.2.18", `example.com\carol`))
	decides(t, v, "carol", "interzone-default")
}

// M11: a group DN in another case names the group.
func TestAGroupDNInAnotherCase(t *testing.T) {
	t.Parallel()
	_, v := userRun(t, idData(t), userFlow("198.51.100.11", "192.0.2.19", ""))
	decides(t, v, "alice", "u-dn-case")
}

// M12: the short name of a group names the group.
func TestAShortGroupName(t *testing.T) {
	t.Parallel()
	_, v := userRun(t, idData(t), userFlow("198.51.100.11", "192.0.2.20", ""))
	decides(t, v, "alice", "u-short")
}

// M13: a group without members and a DN that is no group match no user.
func TestAnEmptyOrUnknownGroupMatchesNoUser(t *testing.T) {
	t.Parallel()
	for _, dst := range []string{"192.0.2.21", "192.0.2.22"} {
		_, v := userRun(t, idData(t), userFlow("198.51.100.11", dst, ""))
		decides(t, v, dst, "interzone-default")
	}
}

// D1: a CIE group never decides. The rule stays a candidate in doubt, and an
// action after it that differs leaves the flow undecided.
func TestACIEGroupStaysInDoubt(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow("198.51.100.11", "192.0.2.24", ""))
	if !slices.Contains(doubtCodesOf(v, "u-cie"), "doubt.user-cie-group") || len(v.Undecided) == 0 {
		t.Errorf("doubts %s, undecided %v", doubtList(v), v.Undecided)
	}
	if st := stage(r, "match-user"); !slices.ContainsFunc(st.Fidelity.Reasons(), func(r reason.Reason) bool { return r.Code == "doubt.user-cie-group" }) {
		t.Errorf("stage %s", st.Fidelity)
	}
	// A deny rule with the group, then an allow.
	path := appConfig(t, "", userRule("u-cie-deny", "deny", "any", users(`example-cie\cloud-team`))+userRule("later", "allow", "any", nil))
	_, v = run(t, userEnv(t, path, idData(t)), userFlow("198.51.100.11", "192.0.2.24", ""))
	if first(v) != "later" || len(v.Undecided) == 0 || !slices.Contains(doubtCodesOf(v, "u-cie-deny"), "doubt.user-cie-group") {
		t.Errorf("first %s, undecided %v, doubts %s", first(v), v.Undecided, doubtList(v))
	}
}

// R1: a rule without source-user takes the schema default, any.
func TestARuleWithoutSourceUserTakesTheDefault(t *testing.T) {
	t.Parallel()
	for _, f := range []simulate.Flow{
		userFlow("198.51.100.11", "192.0.2.26", ""),
		userFlow(noUser, "192.0.2.26", `example.com\bob`),
		userFlow(noUser, "192.0.2.26", `exmple.com\alice`),
		userFlow(noUser, "192.0.2.26", ""),
	} {
		_, v := userRun(t, idData(t), f)
		decides(t, v, f.Source.String()+" "+f.User, "u-none")
	}
	cfg, _, err := config.Load(identityFixture)
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleDefault(cfg, "source-user"); got != "any" {
		t.Errorf("default %q", got)
	}
	// A schema without the default keeps such a rule in doubt.
	s := &state{rules: []resolve.Rule{{Name: "r1"}}, userDoubts: map[uint32][]reason.Reason{}}
	match, kept := roaring.New(), roaring.New()
	s.absentUser("", match, kept)
	if !match.IsEmpty() || !kept.Contains(0) || len(s.userDoubts[0]) != 1 || s.userDoubts[0][0].Code != "doubt.not-evaluated.user" {
		t.Errorf("match %v, kept %v, doubts %v", match, kept, s.userDoubts)
	}
}

// §5.3: a local user group still matches its local user.
func TestALocalGroupStillMatches(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, idData(t), userFlow(noUser, "192.0.2.27", "alice"))
	decides(t, v, "local alice", "u-local")
	if _, ok := hasCode(r.Notes, "note.user-not-in-directory"); !ok {
		t.Errorf("notes %v", r.Notes)
	}
}

// Review focus 4: the mapping of the first source address decides; an IPv6
// mapping is found by its address.
func TestTheMappingOfTheCheckedAddressDecides(t *testing.T) {
	t.Parallel()
	f := userFlow(noUser, "192.0.2.16", "")
	f.Source = simulate.Endpoint{Name: "host.example.com", Addrs: []netip.Addr{
		netip.MustParseAddr("198.51.100.13"), netip.MustParseAddr("198.51.100.11"),
	}, Resolved: true}
	_, v := userRun(t, idData(t), f)
	decides(t, v, "carol of the first address", "u-xmlapi")
	if v.User == nil || v.User.Name != `example.com\carol` || v.User.IP != "198.51.100.13" {
		t.Errorf("user %+v", v.User)
	}
	_, v = userRun(t, idData(t), userFlow("2001:db8::11", "192.0.2.18", ""))
	decides(t, v, "bob by IPv6", "u-multi")
	if v.User == nil || v.User.Name != `example.com\bob` {
		t.Errorf("user %+v", v.User)
	}
}

// §5.5: without identity data the user is not evaluated, as before.
func TestWithoutIdentityDataNothingChanges(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, nil, userFlow("198.51.100.11", "192.0.2.11", `example.com\alice`))
	if st := stage(r, "match-user"); st.Fidelity.Level() != "exact" || st.Detail != "no identity data" {
		t.Errorf("stage %s: %s", st.Fidelity, st.Detail)
	}
	if v.User != nil || first(v) != "none" || len(v.Undecided) == 0 {
		t.Errorf("user %+v, first %s, undecided %v", v.User, first(v), v.Undecided)
	}
	if got := doubtList(v); got != `2 u-user: user not evaluated (example.com\alice)` {
		t.Errorf("doubts %s", got)
	}
	if !slices.Contains(stage(r, "first-match").Fidelity.Skipped(), "user") {
		t.Errorf("first-match %s", stage(r, "first-match").Fidelity)
	}
}

// PD19, SG13: a part that is missing never gives an exact answer.
func TestAMissingPartLeavesTheAnswerInDoubt(t *testing.T) {
	t.Parallel()
	// A source without a mapping, while the table is missing, cut or moved,
	// has a user in doubt: with and without --user.
	for _, part := range []string{identity.PartMappings, "mappings-partial"} {
		t.Run(part, func(t *testing.T) {
			t.Parallel()
			for _, user := range []string{"", `example.com\alice`} {
				r, _ := userRun(t, without(t, part), userFlow(noUser, "192.0.2.11", user))
				text, ok := hasCode(r.Notes, "note.identity-part-missing")
				if st := stage(r, "match-user"); !ok || !strings.Contains(text, identity.PartMappings) || st.Fidelity.Level() != "inferred" {
					t.Errorf("user %q: stage %s, notes %v", user, st.Fidelity, r.Notes)
				}
			}
		})
	}
	// The rules whose member a missing part cannot judge stay candidates in
	// doubt, and the flow stays undecided: after an allow rule in doubt the
	// default rule denies, and after the deny rule u-multi an allow follows.
	groupRules := []string{"u-ldap-group", "u-xmlapi", "u-multi", "u-dn-case", "u-short", "u-empty", "u-dug", "u-dug-ab"}
	path := userConfig(t, userRule("later-allow", "allow", "192.0.2.18", nil))
	tg, err := userEnv(t, identityFixture, nil).Load("fw01", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	idx, err := tg.Index(resolve.Security, "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	dsts := map[string]string{}
	for _, r := range idx.Rules() {
		dsts[r.Name] = r.Fields["destination"][0]
	}
	for _, tc := range []struct {
		part  string
		rules []string
	}{
		{identity.PartUserGroups, groupRules},
		{identity.PartGroups, append(slices.Clone(groupRules), "u-no-group", "u-ghost")},
		{identity.PartUserNames, []string{"u-upn"}},
	} {
		t.Run(tc.part, func(t *testing.T) {
			t.Parallel()
			for _, rule := range tc.rules {
				r, v := run(t, userEnv(t, path, without(t, tc.part)), userFlow("198.51.100.11", dsts[rule], ""))
				codes := doubtCodesOf(v, rule)
				if !slices.Contains(codes, "doubt.user-data-missing") || len(v.Undecided) == 0 {
					t.Errorf("%s: doubts %s, undecided %v", rule, doubtList(v), v.Undecided)
				}
				if slices.Contains(codes, "doubt.not-evaluated.user") {
					t.Errorf("%s: the old doubt: %s", rule, doubtList(v))
				}
				if st := stage(r, "match-user"); st.Fidelity.Level() != "overmatch" {
					t.Errorf("%s: stage %s", rule, st.Fidelity)
				}
			}
		})
	}
	// A --user with @ while users.names is missing can be an alternate name.
	r, _ := userRun(t, without(t, identity.PartUserNames), userFlow(noUser, "192.0.2.11", "alice@example.com"))
	if text, ok := hasCode(r.Notes, "note.identity-part-missing"); !ok || !strings.Contains(text, identity.PartUserNames) ||
		stage(r, "match-user").Fidelity.Level() != "inferred" {
		t.Errorf("users.names: stage %s, notes %v", stage(r, "match-user").Fidelity, r.Notes)
	}
	// tags decide no match (D13): the answer does not change.
	for _, src := range []string{"198.51.100.13", "198.51.100.14"} {
		f := userFlow(src, "192.0.2.17", "")
		full, fv := userRun(t, idData(t), f)
		cut, cv := userRun(t, without(t, identity.PartTags), f)
		if first(fv) != first(cv) || full.Fidelity.String() != cut.Fidelity.String() || doubtList(fv) != doubtList(cv) {
			t.Errorf("%s: %s %s, without tags %s %s", src, first(fv), full.Fidelity, first(cv), cut.Fidelity)
		}
	}
}

// PD19: a mapped source stays exact with a partial table: its mapping
// decides.
func TestAMappedSourceStaysExactWithPartialMappings(t *testing.T) {
	t.Parallel()
	r, v := userRun(t, without(t, "mappings-partial"), userFlow("198.51.100.11", "192.0.2.10", ""))
	decides(t, v, "alice", "u-ldap-group")
	if _, ok := hasCode(r.Notes, "note.identity-part-missing"); ok || stage(r, "match-user").Fidelity.Level() != "exact" {
		t.Errorf("stage %s, notes %v", stage(r, "match-user").Fidelity, r.Notes)
	}
}

// PD17, U2: a mapping whose user is unknown is no mapping.
func TestAnUnknownMappingIsNoMapping(t *testing.T) {
	t.Parallel()
	f := idFile(t)
	f.Mappings = append(f.Mappings, identity.Mapping{IP: netip.MustParseAddr("198.51.100.20"), User: "unknown", Type: "Unknown", Timeout: 60})
	r, v := userRun(t, identity.New(f), userFlow("198.51.100.20", "192.0.2.14", ""))
	decides(t, v, "unknown", "u-unknown")
	if v.User == nil || v.User.Name != "" || v.User.From != "none" {
		t.Errorf("user %+v", v.User)
	}
	if _, ok := hasCode(r.Notes, "note.user-from-mapping"); ok {
		t.Errorf("notes %v", r.Notes)
	}
}
