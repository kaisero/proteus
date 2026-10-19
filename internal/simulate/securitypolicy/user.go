package securitypolicy

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
)

// FlowUser is the user of a flow and where it came from (spec 2026-10-17
// §5.1). JSON writes {"name", "from", "given", "ip", "directory"}.
type FlowUser struct {
	Name      string `json:"name,omitempty"`  // the user the rules were compared with; empty: none
	From      string `json:"from"`            // mapping, given or none
	Given     string `json:"given,omitempty"` // --user as given, when it differs from Name
	IP        string `json:"ip,omitempty"`    // the mapped address
	Directory bool   `json:"directory"`       // Name is a primary name of the data
	Judged    bool   `json:"-"`               // a candidate named a source-user other than any
}

// Where the user of a flow comes from (§5.1).
const (
	userFromMapping = "mapping"
	userFromGiven   = "given"
	userFromNone    = "none"
)

// The source-user keywords that name no user (§5.3). The device matches
// pre-logon only for the literal pre-logon (M6), and known-user for an
// identified user (M3).
const (
	preLogon  = "pre-logon"
	knownUser = "known-user"
	unknownKw = "unknown"
)

// userDoubtCodes are the codes of a rule member that the identity data cannot
// judge (index.userResolver): such a rule stays a candidate in doubt (§5.5,
// §5.6), in this order in the stage's fidelity.
var userDoubtCodes = []reason.Code{"doubt.user-cie-group", "doubt.user-data-missing", "doubt.not-evaluated.user"}

// userOf is the user of a flow, the notes that say where it came from, the
// note of a user in doubt (PD19), and whether an email gave it (PD21).
type userOf struct {
	user  FlowUser
	notes simulate.Reasons
	doubt reason.Reason
	email bool
}

// flowUser finds the user of a flow the way the device does (spec 2026-10-17
// §5.1, D5): the mapping of the first source address wins over the user
// given, as observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17 M1). A mapped
// user stays as stored (M2, N4), and a mapping whose user is unknown is no
// mapping (U2, PD17). Without a mapping, the user given resolves to its
// primary name (§5.2, D7, PD18), else it stays as given (SG10).
func flowUser(d *identity.Data, f simulate.Flow) userOf {
	given := strings.TrimSpace(f.User)
	var out userOf
	if len(f.Source.Addrs) > 0 {
		ip := f.Source.Addrs[0]
		if m, ok := d.Mapping(ip); ok && !strings.EqualFold(m.User, unknownKw) {
			out.user = FlowUser{Name: m.User, From: userFromMapping, IP: ip.String(), Directory: primary(d, m.User)}
			text := fmt.Sprintf("the user %s comes from the mapping of %s", m.User, ip)
			if given != "" && given != m.User {
				out.user.Given = given
				text += fmt.Sprintf("; the mapping wins over the given user %s", given)
			}
			out.notes = append(out.notes, reason.New("note.user-from-mapping", text))
			if !out.user.Directory {
				out.notes = append(out.notes, outsideDirectory("mapped user", m.User))
			}
			return out
		}
	}
	// No mapping: the device can hold one that the snapshot lacks (PD19).
	if !d.Complete(identity.PartMappings) {
		out.doubt = reason.New("note.identity-part-missing", fmt.Sprintf(
			"the part %s of the identity data is missing or partial, so the device can hold a mapping of the source %s that decides the user",
			identity.PartMappings, f.Source))
	}
	switch {
	case given == "":
		out.user = FlowUser{From: userFromNone}
		return out
	case strings.EqualFold(given, preLogon):
		out.user = FlowUser{Name: preLogon, From: userFromGiven}
		if given != preLogon {
			out.user.Given = given
		}
		return out
	}
	if strings.Contains(given, "@") && !d.Complete(identity.PartUserNames) && out.doubt.Text == "" {
		out.doubt = reason.New("note.identity-part-missing", fmt.Sprintf(
			"the part %s of the identity data is missing, so the given user %s can be the alternate name of a user",
			identity.PartUserNames, given))
	}
	name, ok := d.Resolve(given)
	if !ok {
		out.user = FlowUser{Name: given, From: userFromGiven}
		out.notes = append(out.notes, outsideDirectory("given user", given))
		return out
	}
	out.user = FlowUser{Name: name, From: userFromGiven, Directory: true}
	if name != given {
		out.user.Given = given
	}
	if !strings.EqualFold(name, given) {
		u, _ := d.User(name)
		out.email = !slices.ContainsFunc(u.Alt, func(a string) bool { return strings.EqualFold(a, given) })
		text := fmt.Sprintf("the given user %s is read as its primary name %s", given, name)
		if out.email {
			// fw01 could not show whether the device resolves an email
			// (spec 2026-10-17 N7), so the answer is inferred (PD21).
			text += "; it is an email, and no device was seen to resolve an email (spec 2026-10-17 N7)"
		}
		out.notes = append(out.notes, reason.New("note.user-resolved", text))
	}
	return out
}

// outsideDirectory is the note of a user that is no primary name of the data:
// as observed on fw01, PAN-OS 11.2.5, only any, known-user and a rule member
// of the same text match it (spec 2026-10-17 M2, M3, M17).
func outsideDirectory(what, name string) reason.Reason {
	return reason.New("note.user-not-in-directory", fmt.Sprintf(
		"the %s %s is no primary name of the identity data: only any, known-user and a rule that names it match it", what, name))
}

// primary reports whether a name is a primary name of the data, in any case
// (N1).
func primary(d *identity.Data, name string) bool {
	p, ok := d.Resolve(name)
	return ok && strings.EqualFold(p, name)
}

// matchUser narrows by the user of the flow (spec 2026-10-17 §5.3). Without
// identity data nothing changes: every rule that names a user keeps
// doubt.not-evaluated.user, as before (§5.5).
//
// With the data, a rule matches when a member of its source-user matches the
// user; the members combine with OR (M9). The user value space of the index
// gives the rules whose members the user satisfies (PD7): a user in any case
// (N1), a UPN (N2), an LDAP or XML API group and a DUG that U3 lists for the
// user (M7, M8, M11, M12, D13), a member of the same text (M17), and a local
// user or group. A rule without source-user takes the schema's default, any
// (R1). known-user matches an identified user, also one outside the directory
// (M3); unknown matches no user (D6, M5); pre-logon matches the literal
// pre-logon only, and it is no identified user (M6, SG12). A member the data
// cannot judge, a CIE group (D1) or a member a missing part touches (PD19),
// keeps its rule in doubt. The facts are those observed on fw01, PAN-OS
// 11.2.5 (spec 2026-10-17 §1.4).
func matchUser(_ context.Context, s *state) (simulate.Outcome, error) {
	if s.users == nil {
		return simulate.Outcome{Fidelity: simulate.Exact, Detail: "no identity data"}, nil
	}
	s.userEvaluated = true
	s.userKept, s.userDoubts = roaring.New(), map[uint32][]reason.Reason{}
	of := flowUser(s.users, s.in.Flow)
	s.verdict.User = &of.user
	s.notes = append(s.notes, of.notes...)
	u := of.user
	what := userText(u)

	named := roaring.New()
	for it := s.cand.Iterator(); it.HasNext(); {
		bit := it.Next()
		if len(notAny(s.rules[bit].Fields[index.SourceUser.String()])) > 0 {
			named.Add(bit)
		}
	}
	if named.IsEmpty() {
		// The user decides nothing here (SG5, SG6).
		return simulate.Outcome{Fidelity: simulate.Exact, Detail: what + "; no candidate names a user", Candidates: s.cand}, nil
	}
	s.verdict.User.Judged = true

	identified := u.Name != "" && u.Name != preLogon
	var match *roaring.Bitmap
	var rep index.Report
	if u.Name != "" {
		match, rep = s.view.Candidates(index.SourceUser, u.Name)
		match.AndNot(s.literalGroups(u.Name, rep))
	} else {
		match = s.idx.RulesWithAny(index.SourceUser)
	}
	kept := roaring.New()
	s.absentUser(ruleDefault(s.target.Config, index.SourceUser.String()), match, kept)
	// The index takes interned names, so the keywords go through
	// RulesReaching.
	switch {
	case identified:
		match.Or(s.idx.RulesReaching(index.SourceUser, knownUser))
	case u.Name == "":
		match.Or(s.idx.RulesReaching(index.SourceUser, unknownKw))
	default:
		match.Or(s.idx.RulesReaching(index.SourceUser, preLogon))
	}
	// A member the data cannot judge keeps its rule, unless another path
	// matches the rule: a member of the same text as the user does (M17).
	for _, un := range rep.Unresolved {
		if un.Code != "doubt.user-cie-group" && un.Code != "doubt.user-data-missing" {
			continue
		}
		b := s.idx.RulesReaching(index.SourceUser, un.Value)
		b.AndNot(match)
		s.keepUser(kept, b, un.Why())
	}
	s.userKept = kept
	s.cand.And(roaring.Or(match, kept))

	out := simulate.Outcome{Fidelity: simulate.Exact, Candidates: s.cand}
	for _, code := range userDoubtCodes {
		still := roaring.New()
		for it := roaring.And(kept, s.cand).Iterator(); it.HasNext(); {
			bit := it.Next()
			if slices.ContainsFunc(s.userDoubts[bit], func(r reason.Reason) bool { return r.Code == code }) {
				still.Add(bit)
			}
		}
		if !still.IsEmpty() {
			out.Fidelity = simulate.Weakest(out.Fidelity, simulate.OverMatchBecause(reason.New(code,
				"kept rules whose source-user the identity data cannot judge: "+names(s.rules, still))))
		}
	}
	if !identified {
		s.notes = append(s.notes, unknownNote(u))
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.Inferred)
	}
	if of.doubt.Text != "" {
		s.notes = append(s.notes, of.doubt)
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.Inferred)
	}
	if of.email {
		out.Fidelity = simulate.Weakest(out.Fidelity, simulate.Inferred)
	}
	out.Detail = fmt.Sprintf("%s; candidates that name a user: %d, kept in doubt: %d", what,
		roaring.And(named, s.cand).GetCardinality(), roaring.And(kept, s.cand).GetCardinality())
	for _, h := range rep.Hits {
		out.Debug = append(out.Debug, fmt.Sprintf("%s (%s) via %s", h.Name, h.Kind, h.Via))
	}
	if !kept.IsEmpty() {
		out.Debug = append(out.Debug, "kept, in doubt: "+names(s.rules, kept))
	}
	out.Debug = append(out.Debug, "left: "+names(s.rules, s.cand))
	return out, nil
}

// literalGroups are the rules that the user value reaches only through a
// member of the same text that names a group, a DUG or a CIE group, or that
// the data cannot judge. A group name is no user: as observed on fw01,
// PAN-OS 11.2.5, the short name of a group as source-user matches nothing
// (spec 2026-10-17 M12, §5.2). A member in doubt can be a group, so its text
// does not decide either; the caller keeps its rule in doubt. A member of the
// same text that names no group, such as other\ghost, still matches (M17).
// The index matches a value by its text, for search too (§6.1), so the
// simulation takes these rules out here.
func (s *state) literalGroups(value string, rep index.Report) *roaring.Bitmap {
	inDoubt := map[string]bool{}
	for _, un := range rep.Unresolved {
		if un.Code == "doubt.user-cie-group" || un.Code == "doubt.user-data-missing" {
			inDoubt[strings.ToLower(un.Value)] = true
		}
	}
	blocked := func(text string) bool {
		if !strings.EqualFold(text, value) {
			return false
		}
		switch s.users.Member(text).Kind {
		case identity.MemberGroup, identity.MemberDUG, identity.MemberCIE, identity.MemberInDoubt:
			return true
		}
		return inDoubt[strings.ToLower(text)]
	}
	literal, other := roaring.New(), s.idx.RulesWithAny(index.SourceUser)
	texts := []string{value}
	for _, un := range rep.Unresolved {
		texts = append(texts, un.Value)
	}
	for _, t := range texts {
		if blocked(t) {
			literal.Or(s.idx.RulesReaching(index.SourceUser, t))
		}
	}
	for _, h := range rep.Hits {
		if blocked(h.Name) {
			literal.Or(s.idx.RulesReaching(index.SourceUser, h.Name))
		} else {
			other.Or(s.idx.RulesReaching(index.SourceUser, h.Name))
		}
	}
	literal.AndNot(other)
	return literal
}

// unknownNote is the note of a flow without an identified user (spec
// 2026-10-17 §5.4, SG5, SG12).
func unknownNote(u FlowUser) reason.Reason {
	if u.Name == preLogon {
		return reason.New("note.user-unknown-inferred",
			"pre-logon is no identified user: it matches pre-logon, and neither known-user nor unknown (spec 2026-10-17 M6, SG12); no traffic test confirms it")
	}
	return reason.New("note.user-unknown-inferred",
		"no user: the flow matches any and unknown, not known-user, as the PAN-OS admin guide defines them (\"Security Policy Rule\"); "+
			"the device's test command matches known-user here (spec 2026-10-17 M4), and no traffic test confirms unknown")
}

// absentUser places the rules exported without a source-user. Such a rule
// takes the schema's default for the field (R1): any in the 11.2.0 digest,
// so it matches. Without that default, it is kept in doubt.
func (s *state) absentUser(def string, match, kept *roaring.Bitmap) {
	absent := s.withoutField(index.SourceUser.String())
	if def == "any" {
		match.Or(absent)
		return
	}
	s.keepUser(kept, absent, reason.New("doubt.not-evaluated.user",
		"the rule has no source-user, and the schema gives the field no default"))
}

// keepUser adds rules to the kept set and gives each the reason.
func (s *state) keepUser(kept, rules *roaring.Bitmap, why reason.Reason) {
	for it := rules.Iterator(); it.HasNext(); {
		bit := it.Next()
		if !slices.Contains(s.userDoubts[bit], why) {
			s.userDoubts[bit] = append(s.userDoubts[bit], why)
		}
	}
	kept.Or(rules)
}

// userText names the user and where it came from, as the stage and the
// output show it.
func userText(u FlowUser) string {
	switch u.From {
	case userFromMapping:
		return fmt.Sprintf("%s, from the mapping of %s", u.Name, u.IP)
	case userFromGiven:
		if u.Given != "" {
			return fmt.Sprintf("%s, given as %s", u.Name, u.Given)
		}
		return u.Name + ", given"
	}
	return "no user"
}
