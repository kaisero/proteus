package index

import (
	"fmt"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
)

// userResolver answers the user value space: which source-user members of the
// rules a user satisfies.
//
// This is the first value space a configuration cannot answer on its own. The
// schema lets a rule's source-user name a local user, a local user group or a
// dynamic user group, and marks the field loose-membership, so a member can
// also name a user or a group that only the directory knows (spec 2026-10-17
// C5). The local database answers from the file. The rest comes from the
// identity data of the device, which the caller supplies in Providers.Users,
// and the answer says so when nobody did.
//
// With the data, a user's hits are the members of the rules, as written, that
// the user satisfies, so the rules naming them follow as for any other value
// space (plan PD7). The caller passes a user as the device compares it: a
// primary name, or a mapped name as stored (PD8).
type userResolver struct {
	scope  config.Scope
	users  map[string]Hit   // lowercased local user name
	groups map[string][]Hit // lowercased member name -> local groups holding it
	// dynamic records dynamic user groups, whose membership is registered at runtime
	// and is never in the file.
	dynamic []Unresolved
	// members are the source-user members of the rules, as written, once each:
	// no keyword, and no name of the local database, whose own users and
	// groups the file answers for.
	members []string
}

const kindUser = "user"

// userKeyword reports whether a source-user value names no user or group: any
// matches every user, and the security check judges the others (spec
// 2026-10-17 §5.3).
func userKeyword(m string) bool {
	switch m {
	case "any", "known-user", "unknown", "pre-logon":
		return true
	}
	return false
}

func newUserResolver(sc config.Scope, users, groups, dynamic []resolve.Object, rules []resolve.Rule) *userResolver {
	r := &userResolver{
		scope:  sc,
		users:  map[string]Hit{},
		groups: map[string][]Hit{},
	}
	local := map[string]bool{}
	for _, u := range users {
		r.users[strings.ToLower(u.Name)] = Hit{Name: u.Name, Kind: kindUser, Scope: u.Scope, Via: u.Name}
		local[strings.ToLower(u.Name)] = true
	}
	for _, g := range groups {
		local[strings.ToLower(g.Name)] = true
		hit := Hit{Name: g.Name, Kind: "user-group", Scope: g.Scope}
		for _, m := range splitMembers(g.Value) {
			h := hit
			h.Via = m
			key := strings.ToLower(m)
			r.groups[key] = append(r.groups[key], h)
		}
	}
	for _, d := range dynamic {
		r.dynamic = append(r.dynamic, NewUnresolved(d.Name, "dynamic-user-group", reason.New("gap.dynamic-user-group",
			"a dynamic user group is filled in at runtime by User-ID, so who is in it "+
				"is not in the configuration and a user cannot be matched against it")))
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		for _, m := range rule.Fields[SourceUser.String()] {
			if userKeyword(m) || local[strings.ToLower(m)] || seen[m] {
				continue
			}
			seen[m] = true
			r.members = append(r.members, m)
		}
	}
	return r
}

func (r *userResolver) kinds() []string {
	return []string{kindUser, "user-group", "dynamic-user-group"}
}

// resolve returns the local user of that name and every local group holding it,
// and, with the identity data, every member of the rules that the user
// satisfies.
//
// A user name is recognised by shape rather than by being known: a name absent from
// the local database is the normal case, not an error, because the local database is
// usually empty and the real users live in a directory. A name the identity
// data knows is recognised whatever its shape: a group DN holds spaces (spec
// 2026-10-17 §6.1).
func (r *userResolver) resolve(value string, p Providers) ([]Hit, []Unresolved, bool) {
	name := strings.TrimSpace(value)
	if name == "" || !looksLikeUser(name) && (p.Users == nil || !p.Users.Known(name)) {
		return nil, nil, false
	}
	key := strings.ToLower(name)

	var hits []Hit
	if h, ok := r.users[key]; ok {
		hits = append(hits, h)
	}
	hits = append(hits, r.groups[key]...)

	if p.Users == nil {
		unresolved := append([]Unresolved{}, r.dynamic...)
		unresolved = append(unresolved, NewUnresolved(name, "user-group", reason.New("gap.no-user-directory",
			"no user directory was supplied, so only the local user database was "+
				"searched. A rule naming a directory group this user belongs to is missing "+
				"from the result")))
		return hits, unresolved, true
	}
	more, unresolved := r.directory(name, p.Users)
	return append(hits, more...), unresolved, true
}

// directory judges each member of the rules for a user by the identity data
// (spec 2026-10-17 §5.2, §5.3). A member that the user satisfies is a hit; a
// member that the data cannot judge is an unresolved entry and no hit
// (doubtOf).
func (r *userResolver) directory(value string, d *identity.Data) ([]Hit, []Unresolved) {
	var hits []Hit
	var unresolved []Unresolved
	for _, m := range r.members {
		mem := d.Member(m)
		if why, ok := doubtOf(d, m, mem); ok {
			unresolved = append(unresolved, NewUnresolved(m, memberKind(mem), why))
			continue
		}
		if !satisfies(d, m, mem, value) {
			continue
		}
		h := Hit{Name: m, Kind: memberKind(mem), Scope: r.scope, Via: value}
		if mem.Kind == identity.MemberGroup || mem.Kind == identity.MemberDUG {
			h.Via = groupVia(d, mem)
		}
		hits = append(hits, h)
	}
	return hits, unresolved
}

// satisfies reports whether a user satisfies a member that the data judges,
// as observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17 §5.2, §5.3):
//
//   - a member of the same text, in any case: a mapped user outside the
//     directory matches the rule that names it (M17), and so does a search
//     term that names a group;
//   - a member that names the user by its primary or alternate name (N1, N2);
//   - a group or a DUG whose name U3 lists among the user's groups (U3, M7,
//     M11, M12). A DUG has no other members, and no code evaluates its tag
//     filter (D13). InGroup gives false for a short name in doubt, which
//     doubtOf takes first.
//
// Nothing else: a group without members and a DN that is no group match no
// user (M13), and a mapped name in another form matches no user and no group
// (M2).
func satisfies(d *identity.Data, m string, mem identity.Member, value string) bool {
	switch mem.Kind {
	case identity.MemberUser:
		if strings.EqualFold(mem.Name, value) {
			return true
		}
	case identity.MemberGroup, identity.MemberDUG:
		if d.InGroup(value, mem.Name) {
			return true
		}
	}
	return strings.EqualFold(m, value)
}

// memberKind is the schema kind of what a member names: a group, a CIE group
// or a short name in doubt is a user group, a DUG a dynamic user group, and a
// user or a name of no group a user.
func memberKind(mem identity.Member) string {
	switch mem.Kind {
	case identity.MemberGroup, identity.MemberCIE, identity.MemberInDoubt:
		return "user-group"
	case identity.MemberDUG:
		return "dynamic-user-group"
	}
	return kindUser
}

// groupVia names the source of a group and its member count, as a search
// finding shows a group (spec 2026-10-17 §6.1). A DUG that the group list
// lacks gets its count from U3.
func groupVia(d *identity.Data, mem identity.Member) string {
	g, ok := d.Group(mem.Name)
	if !ok {
		g.Members = len(d.Members(mem.Name))
	}
	return fmt.Sprintf("%s, %d members", mem.Source, g.Members)
}

// doubtOf says why the identity data cannot judge a member, if it cannot. Such
// a member never decides: it is no hit, and the rule stays a candidate in
// doubt (spec 2026-10-17 §5.5, §5.6, PD19):
//
//   - a CIE group, or a group of source cie, while no CIE lab has passed (D1);
//   - a short name that the data resolves to no one group (ruling Q1);
//   - a group or a DUG while users.groups is missing: U3 holds the members;
//   - a name of no user and no group while groups is missing: it can be a
//     group or a DUG;
//   - a name with @ that is no primary name while users.names is missing: it
//     can be an alternate name.
//
// A missing tags part judges nothing: tags decide no match (D13).
func doubtOf(d *identity.Data, m string, mem identity.Member) (reason.Reason, bool) {
	switch {
	case mem.Kind == identity.MemberCIE:
		return reason.New("doubt.user-cie-group", fmt.Sprintf(
			"%s names a group of a Cloud Identity Engine profile (source %s), which the answer does not evaluate", m, mem.Source)), true
	case mem.Kind == identity.MemberInDoubt && !d.Complete(identity.PartLDAP):
		return missing(identity.PartLDAP, fmt.Sprintf("so the short name %s resolves to no group", m)), true
	case mem.Kind == identity.MemberInDoubt:
		return reason.New("doubt.user-data-missing", fmt.Sprintf(
			"the identity data resolves the short name %s to no one group: the domain of its "+
				"group-mapping profile is unknown, or two groups have this short name", m)), true
	case (mem.Kind == identity.MemberGroup || mem.Kind == identity.MemberDUG) && !d.Complete(identity.PartUserGroups):
		return missing(identity.PartUserGroups, fmt.Sprintf("so the members of %s are not known", m)), true
	case mem.Kind == identity.MemberUnknown && !d.Complete(identity.PartGroups):
		return missing(identity.PartGroups, fmt.Sprintf("so %s can be a group or a dynamic user group", m)), true
	case strings.Contains(m, "@") && !d.Complete(identity.PartUserNames) && !primary(d, m):
		return missing(identity.PartUserNames, fmt.Sprintf("so %s can be the alternate name of a user", m)), true
	}
	return reason.Reason{}, false
}

// missing is the doubt of a member that a missing part cannot judge; it names
// the part.
func missing(part, why string) reason.Reason {
	return reason.New("doubt.user-data-missing", fmt.Sprintf("the part %s of the identity data is missing, %s", part, why))
}

// primary reports whether a name is the primary name of a user of the data.
func primary(d *identity.Data, name string) bool {
	p, ok := d.Resolve(name)
	return ok && strings.EqualFold(p, name)
}

// literalRules returns nothing: a rule's source-user field names a user or group, and
// the value it holds is that name rather than a value to match.
func (r *userResolver) literalRules(Field, string) *roaring.Bitmap { return roaring.New() }

func (r *userResolver) search(substr string) []Hit {
	want := strings.ToLower(substr)
	var out []Hit
	for key, h := range r.users {
		if strings.Contains(key, want) {
			out = append(out, h)
		}
	}
	for key, hits := range r.groups {
		if strings.Contains(key, want) {
			out = append(out, hits...)
		}
	}
	return out
}

// looksLikeUser rejects the shapes that belong to another value space, so a query that
// is plainly an address or a port is not reported as an unknown user.
func looksLikeUser(name string) bool {
	if strings.ContainsAny(name, "/ ") {
		// A prefix, a port specification or a URL path.
		return false
	}
	return true
}
