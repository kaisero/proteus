package index

import (
	"fmt"
	"net/netip"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/reason"
)

// Candidates returns every rule whose field could match a value, and a report of
// how it got there.
//
// A rule field can reach a value by four paths, and a caller that forgets one gets
// a wrong answer rather than an incomplete one:
//
//  1. the field names an object whose value matches
//  2. the field names a group holding such an object, at any depth, static
//     membership or a tag filter alike
//  3. the field holds a matching value directly, with no object involved
//  4. the field is "any", which matches everything
//
// The fourth is the one that bites. Checked against a live firewall: for 198.18.0.5
// to 198.18.1.5 the device reports rule 3, whose source is "any", while matching on
// objects alone reports rule 8. An any-rule usually sits earlier in a rulebase than
// a specific one, so leaving it out returns the wrong winner.
//
// Which value spaces a field has is read from the schema, so a field that accepts
// an address, a region and an external list is asked of each. A kind no resolver
// covers is reported in the report rather than ignored.
//
// This is one side of a match. Intersecting the sides, dropping disabled rules, and
// deciding what the first match means — including whether application, service and
// zone agree — belongs to the caller. The library knows only which rules a value
// can reach.
func (i *Index) Candidates(f Field, value string) (*roaring.Bitmap, Report) {
	return i.With(Providers{}).Candidates(f, value)
}

// Candidates answers as Index.Candidates does, using the view's providers for the
// value spaces that need data a configuration does not hold.
func (v *View) Candidates(f Field, value string) (*roaring.Bitmap, Report) {
	i := v.idx
	rep := Report{Value: value}
	out := roaring.New()

	recognised := false
	for _, r := range i.resolversFor(f) {
		hits, un, ok := r.resolve(value, v.p)
		recognised = recognised || ok
		rep.Hits = append(rep.Hits, hits...)
		rep.Unresolved = append(rep.Unresolved, un...)
		for _, h := range hits {
			out.Or(i.RulesWith(f, i.reach(f, h.Name, &rep)...))
		}
		out.Or(r.literalRules(f, value))
	}

	// Whatever its value space, a value can also be the name of an object or group.
	_, named := i.in.Lookup(value)
	if named {
		out.Or(i.RulesWith(f, i.reach(f, value, &rep)...))
	}

	if anyRules := i.RulesWithAny(f); !anyRules.IsEmpty() {
		rep.ViaAny = true
		out.Or(anyRules)
	}

	// Two value spaces can find the same thing. A user belonging to a local group that
	// a directory also reports is the plain case: the answer is one membership, not
	// two, and a report that lists it twice invites a reader to think otherwise.
	rep.Hits = dedupeHits(rep.Hits)
	rep.Groups = dedupeStrings(rep.Groups)
	rep.Unresolved = dedupeUnresolved(rep.Unresolved)
	if i.gap != "" {
		rep.Unresolved = append(rep.Unresolved, NewUnresolved(value, "", reason.New("gap.version", i.gap)))
	}

	// A value nothing recognised is an incomplete answer. A value that was
	// recognised and matched nothing is a complete one, even with no hits: a URL
	// belonging to no category really does reach only the any-rules.
	if !recognised && !named {
		rep.Unresolved = append(rep.Unresolved, NewUnresolved(value, "", reason.New("gap.object-unresolved",
			fmt.Sprintf(
				"no value space of %s recognised this, and no object of that name is visible "+
					"in %s. Only rules whose %s is \"any\" are reported, so a rule reaching "+
					"this value through a kind the index does not yet resolve, such as a "+
					"region or an external list, is missing from the result",
				f, i.scope, f))))
	}
	return out, rep
}

// CandidatesFor returns every rule whose field could match an address.
func (i *Index) CandidatesFor(f Field, addr netip.Addr) *roaring.Bitmap {
	b, _ := i.Candidates(f, addr.String())
	return b
}

// CandidatesForPrefix returns every rule whose field could match any address in a
// prefix. A literal in the field matches when the two overlap.
func (i *Index) CandidatesForPrefix(f Field, p netip.Prefix) *roaring.Bitmap {
	b, _ := i.Candidates(f, p.String())
	return b
}

// CandidatesForName returns every rule whose field could match a named object or
// group: the name itself, any group holding it, and a field of "any".
func (i *Index) CandidatesForName(f Field, name string) *roaring.Bitmap {
	b, _ := i.Candidates(f, name)
	return b
}

func dedupeHits(in []Hit) []Hit {
	if len(in) < 2 {
		return in
	}
	seen := make(map[Hit]bool, len(in))
	out := in[:0:0]
	for _, h := range in {
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

func dedupeStrings(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func dedupeUnresolved(in []Unresolved) []Unresolved {
	if len(in) < 2 {
		return in
	}
	seen := make(map[Unresolved]bool, len(in))
	out := in[:0:0]
	for _, u := range in {
		if seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// reach returns the interned ids a name reaches in a field: the name itself and
// every group holding it, recording the groups in the report. Only groups of a
// kind the field can name count: a service group holds no source address, even
// when an address group of the same name does.
func (i *Index) reach(f Field, name string, rep *Report) []uint32 {
	var ids []uint32
	if id, known := i.in.Lookup(name); known {
		ids = append(ids, id)
	}
	groups := i.groupsReaching(f, name)
	rep.Groups = append(rep.Groups, groups...)
	return append(ids, i.idsOf(groups)...)
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
