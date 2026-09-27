package index

import (
	"net/netip"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/go-panos-schema/config"
)

// A resolver turns a query value into the object names in its own value space that
// the value matches.
//
// This is the only part of a lookup that depends on what kind of value is being
// matched. Everything after it is identical for every value space: a matched name
// expands through group membership, group and name alike become interned ids, the
// ids become a rule bitmap, and the rules whose field is "any" join them.
//
// Resolvers are internal, and the set is closed. A new value space is implemented
// here rather than registered from outside, so every resolver can be held to the
// same obligation: when it recognises a value but cannot evaluate it, it says so
// rather than returning nothing.
type resolver interface {
	// kinds names the schema object kinds this resolver answers for. The schema
	// says which kinds a field accepts; this says which of those can be resolved.
	kinds() []string

	// resolve returns the names whose value matches, each with the value that
	// matched it, plus anything recognised but not evaluated.
	resolve(value string, p Providers) ([]Hit, []Unresolved)

	// literalRules returns the rules whose field holds a matching value directly
	// rather than naming an object. Whether a literal matches is as
	// value-space-specific as whether an object does.
	literalRules(f Field, value string) *roaring.Bitmap
}

// Hit is one object whose value matches a query, with the value that matched.
//
// Via carries that value — the prefix, the URL pattern, the port range — because
// an answer that cannot be checked is an answer that hides its mistakes.
type Hit struct {
	Name  string
	Kind  string
	Scope config.Scope
	Via   string
}

// Providers supply facts a configuration does not contain.
//
// A User-ID mapping and a routing table are not in a configuration file, and they
// change far faster than one. They attach to a View rather than to an Index for
// that reason: an Index is cached per file and scope, and is immutable so that
// concurrent readers need no lock.
//
// The library performs no network access. These are interfaces, and fetching the
// data behind them belongs to the caller.
type Providers struct {
	Users UserDirectory
	Zones ZoneLocator
}

// UserDirectory maps a user to the groups holding it, from User-ID or a snapshot.
type UserDirectory interface {
	GroupsOf(user string) []string
}

// ZoneLocator maps an address to the zones it can arrive on.
type ZoneLocator interface {
	ZonesOf(addr netip.Addr) []string
}

// View pairs an immutable index with the providers for one question.
type View struct {
	idx *Index
	p   Providers
}

// With returns a view of the index that uses the given providers.
func (i *Index) With(p Providers) *View { return &View{idx: i, p: p} }

// Report says how a lookup reached its answer, and what it could not reach.
//
// Hits and Via make the reasoning checkable. Unresolved makes an incomplete answer
// impossible to mistake for a complete one.
type Report struct {
	Value      string
	Hits       []Hit
	Groups     []string
	ViaAny     bool
	Unresolved []Unresolved
}

// resolversFor returns the resolvers that can answer for a field, derived from the
// object kinds the schema allows there.
//
// A field can need more than one: a security rule's source accepts an address, an
// address group, a region, an external list and an IP block list, and those are
// five value spaces, not one.
func (i *Index) resolversFor(f Field) []resolver {
	return i.resolvers[f]
}

// wireResolvers maps each field to the resolvers covering the kinds the schema
// allows there.
func wireResolvers(kinds map[string][]string, byKind map[string]resolver) map[Field][]resolver {
	out := map[Field][]resolver{}
	for f, name := range fieldNames {
		seen := map[resolver]bool{}
		for _, k := range kinds[name] {
			r, ok := byKind[k]
			if !ok || seen[r] {
				continue
			}
			seen[r] = true
			out[f] = append(out[f], r)
		}
	}
	return out
}
