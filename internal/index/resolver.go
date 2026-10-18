package index

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
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
	//
	// The third result says whether this value space recognised the form of the
	// value at all. It is not the same as matching: a URL that belongs to no
	// category is recognised and does not match, and that is a complete answer. A
	// value nothing recognises is an incomplete one.
	resolve(value string, p Providers) ([]Hit, []Unresolved, bool)

	// literalRules returns the rules whose field holds a matching value directly
	// rather than naming an object. Whether a literal matches is as
	// value-space-specific as whether an object does.
	literalRules(f Field, value string) *roaring.Bitmap

	// search returns the objects whose value contains the substring, case
	// insensitively. This is not matching and must never be used for it: PAN-OS
	// matches a URL by tokens, so "wildcard-example.com" does not cover
	// "wildcard-example.com.evil.net" even though one contains the other. Searching
	// answers a human question — where is this value mentioned — and for that,
	// substring is exactly right.
	search(substr string) []Hit
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
// that reason: an Index is built once per scope and kept by its caller, and is
// immutable so that concurrent readers need no lock.
//
// The library performs no network access. These are interfaces, and fetching the
// data behind them belongs to the caller.
type Providers struct {
	Users UserDirectory
	Zones ZoneLocator
	// Apps is the App-ID content data of the device. With it, the application
	// value space answers filters and containers; without it, it reports them
	// (spec 2026-10-16 §4.8).
	Apps *appid.Data
}

// UserDirectory maps a user to the groups holding it, from User-ID or a snapshot.
type UserDirectory interface {
	GroupsOf(user string) []string
}

// A StaleReporter is a provider that knows its data may be out of date. A lookup asks,
// and passes the answer on rather than trusting the data silently. UserSnapshot
// implements it.
type StaleReporter interface {
	Stale() (reason string, stale bool)
}

// ZoneLocator maps an address to the zones it can arrive on.
//
// It returns a set, not an answer, and that is not a shortcoming to be engineered
// away. A firewall can have several logical routers whose address space overlaps, and
// which one applies is decided by the interface a packet arrives on — the very thing
// being worked out. Measured on a lab firewall: 198.19.11.5 is covered by the lte
// router's 198.19.11.0/24, reaching zone int-link-b, and by the default router's
// 0.0.0.0/0, reaching zone transport. Only the device knows which, which is why its
// own test security-policy-match takes the zone as an argument.
type ZoneLocator interface {
	ZonesOf(addr netip.Addr) []ZonePlacement
}

// ZonePlacement is one way an address could arrive, and the reasoning behind it.
//
// Every other answer in this library carries the value that produced it, so a reader
// can check it rather than trust it. A zone placement says which interface, which
// router and which route.
type ZonePlacement struct {
	Zone      string
	Interface string
	Router    string
	Route     string // the forwarding entry that selected the interface
	Vsys      string
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

// SearchValues returns every object whose value contains the substring, case
// insensitively, across every value space.
//
// This is the answer to a name that cannot hold its own value. PAN-OS caps a custom
// URL category name at 31 characters and one of its members at 255, so a long URL
// cannot appear in the name of the category holding it, and searching the values is
// the only way to find it. Other kinds are wider — an address or service name may be
// 63 characters, a tag 127 — but the same problem appears whenever a value is longer
// than the name that holds it.
//
// It is a search, not a match. Use Candidates to ask what a rule would do.
func (i *Index) SearchValues(substr string) []Hit {
	substr = strings.TrimSpace(substr)
	if substr == "" {
		return nil
	}
	var out []Hit
	seen := map[Hit]bool{}
	for _, r := range i.distinctResolvers() {
		for _, h := range r.search(substr) {
			if seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	slices.SortFunc(out, func(a, b Hit) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Via, b.Via))
	})
	return out
}

// distinctResolvers returns each resolver once, however many kinds it covers.
func (i *Index) distinctResolvers() []resolver {
	var out []resolver
	seen := map[resolver]bool{}
	for _, rs := range i.resolvers {
		for _, r := range rs {
			if seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// wireResolvers maps each field to the resolvers covering the kinds the schema
// allows there.
func wireResolvers(kinds map[string][]string, byKind map[string]resolver) map[Field][]resolver {
	out := map[Field][]resolver{}
	for i, name := range fieldNames {
		f := Field(i)
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
