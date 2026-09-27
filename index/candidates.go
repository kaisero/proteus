package index

import (
	"net/netip"

	"github.com/RoaringBitmap/roaring/v2"
)

// CandidatesFor returns every rule whose field could match an address.
//
// A rule field can reach a value by four different paths, and a caller that
// forgets one gets a wrong answer rather than an incomplete one:
//
//  1. the field names an address object whose value covers the address
//  2. the field names a group holding such an object, at any depth, static
//     membership or a tag filter alike
//  3. the field holds the address literally, or a prefix containing it
//  4. the field is "any", which matches every address
//
// The fourth is the one that bites. Checked against fw01: for 198.18.0.5 to
// 198.18.1.5 the device reports rule 3, whose source is "any", while matching on
// objects alone reports rule 8. An any-rule usually sits earlier in a rulebase
// than a specific one.
//
// This is one side of a match. Intersecting the sides, dropping disabled rules,
// and deciding what the first match means — including whether application, service
// and zone agree — belongs to the caller. The library knows only which rules a
// value can reach.
func (i *Index) CandidatesFor(f Field, addr netip.Addr) *roaring.Bitmap {
	out := i.RulesWith(f, i.reachableIDs(addr)...)
	out.Or(i.RulesWithAddr(f, addr))
	out.Or(i.RulesWithAny(f))
	return out
}

// CandidatesForPrefix returns every rule whose field could match any address in a
// prefix. A literal in the field matches when the two overlap.
func (i *Index) CandidatesForPrefix(f Field, p netip.Prefix) *roaring.Bitmap {
	var ids []uint32
	for _, m := range i.Overlapping(p) {
		ids = append(ids, i.in.ID(m.Name))
		for _, g := range i.GroupsOf(m.Name) {
			ids = append(ids, i.in.ID(g))
		}
	}
	out := i.RulesWith(f, ids...)
	out.Or(i.RulesWithPrefix(f, p))
	out.Or(i.RulesWithAny(f))
	return out
}

// CandidatesForName returns every rule whose field could match a named object or
// group: the name itself, any group holding it, and a field of "any".
//
// A literal cannot apply here, because a name is not an address.
func (i *Index) CandidatesForName(f Field, name string) *roaring.Bitmap {
	ids := []uint32{i.in.ID(name)}
	for _, g := range i.GroupsOf(name) {
		ids = append(ids, i.in.ID(g))
	}
	out := i.RulesWith(f, ids...)
	out.Or(i.RulesWithAny(f))
	return out
}

// reachableIDs returns the interned names an address reaches: the objects covering
// it, and every group holding one of those.
func (i *Index) reachableIDs(addr netip.Addr) []uint32 {
	var ids []uint32
	for _, m := range i.Containing(addr) {
		ids = append(ids, i.in.ID(m.Name))
		for _, g := range i.GroupsOf(m.Name) {
			ids = append(ids, i.in.ID(g))
		}
	}
	return ids
}
