package index

import (
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/resolve"
)

// userResolver answers the user value space: which users and user groups a name
// belongs to.
//
// This is the first value space a configuration cannot answer on its own. The schema
// lets a rule's source-user name a local user, a local user group or a dynamic user
// group, and that is all a file can offer. In production the membership that matters
// comes from User-ID, which learns it from a directory, so the caller supplies it
// through a UserDirectory and the answer says so when nobody did.
type userResolver struct {
	users  map[string]Hit   // lowercased local user name
	groups map[string][]Hit // lowercased member name -> local groups holding it
	// dynamic records dynamic user groups, whose membership is registered at runtime
	// and is never in the file.
	dynamic []Unresolved
}

const kindUser = "user"

func newUserResolver(users, groups, dynamic []resolve.Object) *userResolver {
	r := &userResolver{
		users:  map[string]Hit{},
		groups: map[string][]Hit{},
	}
	for _, u := range users {
		r.users[strings.ToLower(u.Name)] = Hit{Name: u.Name, Kind: kindUser, Scope: u.Scope, Via: u.Name}
	}
	for _, g := range groups {
		hit := Hit{Name: g.Name, Kind: "user-group", Scope: g.Scope}
		for _, m := range splitMembers(g.Value) {
			h := hit
			h.Via = m
			key := strings.ToLower(m)
			r.groups[key] = append(r.groups[key], h)
		}
	}
	for _, d := range dynamic {
		r.dynamic = append(r.dynamic, Unresolved{
			Value: d.Name,
			Kind:  "dynamic-user-group",
			Reason: "a dynamic user group is filled in at runtime by User-ID, so who is in it " +
				"is not in the configuration and a user cannot be matched against it",
		})
	}
	return r
}

func (r *userResolver) kinds() []string {
	return []string{kindUser, "user-group", "dynamic-user-group"}
}

// resolve returns the local user of that name and every group holding it, from the
// local database and from the caller's directory alike.
//
// A user name is recognised by shape rather than by being known: a name absent from
// the local database is the normal case, not an error, because the local database is
// usually empty and the real users live in a directory.
func (r *userResolver) resolve(value string, p Providers) ([]Hit, []Unresolved, bool) {
	name := strings.TrimSpace(value)
	if name == "" || !looksLikeUser(name) {
		return nil, nil, false
	}
	key := strings.ToLower(name)

	var hits []Hit
	if h, ok := r.users[key]; ok {
		hits = append(hits, h)
	}
	hits = append(hits, r.groups[key]...)

	unresolved := append([]Unresolved{}, r.dynamic...)
	if p.Users == nil {
		unresolved = append(unresolved, Unresolved{
			Value: name,
			Kind:  "user-group",
			Reason: "no user directory was supplied, so only the local user database was " +
				"searched. A rule naming a directory group this user belongs to is missing " +
				"from the result",
		})
		return hits, unresolved, true
	}
	if sr, ok := p.Users.(StaleReporter); ok {
		if reason, stale := sr.Stale(); stale {
			unresolved = append(unresolved, Unresolved{Value: name, Kind: "user-group", Reason: reason})
		}
	}
	for _, g := range p.Users.GroupsOf(name) {
		hits = append(hits, Hit{Name: g, Kind: "user-group", Scope: r.scopeFor(g), Via: name})
	}
	return hits, unresolved, true
}

// scopeFor reports the scope of a group the directory named, when the configuration
// also knows it. A directory group the configuration never mentions has no scope.
func (r *userResolver) scopeFor(group string) (sc config.Scope) {
	for _, hits := range r.groups {
		for _, h := range hits {
			if strings.EqualFold(h.Name, group) {
				return h.Scope
			}
		}
	}
	return sc
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
