package index

import (
	"fmt"
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
	out := i.RulesWith(f, i.idsFor(i.Overlapping(p))...)
	out.Or(i.RulesWithPrefix(f, p))
	out.Or(i.RulesWithAny(f))
	return out
}

// CandidatesForName returns every rule whose field could match a named object or
// group: the name itself, any group holding it, and a field of "any".
//
// A literal cannot apply here, because a name is not an address.
func (i *Index) CandidatesForName(f Field, name string) *roaring.Bitmap {
	var ids []uint32
	if id, known := i.in.Lookup(name); known {
		ids = append(ids, id)
	}
	ids = append(ids, i.idsOf(i.GroupsOf(name))...)
	out := i.RulesWith(f, ids...)
	out.Or(i.RulesWithAny(f))
	return out
}

// reachableIDs returns the interned names an address reaches: the objects covering
// it, and every group holding one of those.
func (i *Index) reachableIDs(addr netip.Addr) []uint32 {
	return i.idsFor(i.Containing(addr))
}

// idsFor returns the interned ids of the matched objects and of every group
// holding one of them.
func (i *Index) idsFor(ms []Match) []uint32 {
	var ids []uint32
	for _, m := range ms {
		if id, known := i.in.Lookup(m.Name); known {
			ids = append(ids, id)
		}
		ids = append(ids, i.idsOf(i.GroupsOf(m.Name))...)
	}
	return ids
}

// idsOf looks names up without interning them.
//
// A query never assigns an id. The interner is a plain map with no lock, and an
// index is documented immutable so that concurrent readers need none, so interning
// on a lookup path is a data race as well as a leak.
func (i *Index) idsOf(names []string) []uint32 {
	ids := make([]uint32, 0, len(names))
	for _, n := range names {
		if id, known := i.in.Lookup(n); known {
			ids = append(ids, id)
		}
	}
	return ids
}

// Candidates returns every rule whose field could match a value, and whatever
// about the value could not be evaluated.
//
// The value is read as an address, then as a prefix, then as the name of an object
// or group. A value that is none of those reaches only the rules whose field is
// "any", and the Unresolved list then says so, because those rules alone look like
// an answer: measured on fw01, a URL value returned nine of ten rules and omitted
// the one naming it.
func (i *Index) Candidates(f Field, value string) (*roaring.Bitmap, []Unresolved) {
	if addr, err := netip.ParseAddr(value); err == nil {
		return i.CandidatesFor(f, addr), nil
	}
	if p, err := netip.ParsePrefix(value); err == nil {
		return i.CandidatesForPrefix(f, p), nil
	}
	if _, known := i.in.Lookup(value); known {
		return i.CandidatesForName(f, value), nil
	}
	return i.RulesWithAny(f), []Unresolved{{
		Value: value,
		Reason: fmt.Sprintf(
			"not an address, not a prefix, and no object of that name is visible in %s. "+
				"Only rules whose %s is \"any\" are reported, so a rule reaching this value "+
				"through a kind the index does not yet resolve, such as a custom URL "+
				"category, a region or an external list, is missing from the result",
			i.scope, f),
	}}
}
