package index

import (
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// closureIndex answers transitive group membership.
//
// Membership is held as Roaring bitmaps, never as slices. Measured on 5,000
// groups chained one inside the next, 137.5M logical edges: the slice form cost
// 1,875 ms and 1,193 MB; bitmaps cost 6 ms and 69 MB. See AGENTS.md R11.
//
// The forward closure is built eagerly. Reverse lookups are computed on first ask,
// because inverting a dense closure eagerly cost 26 s and 294 MB on the same data.
type closureIndex struct {
	direct  map[uint32][]uint32        // group -> direct members
	forward map[uint32]*roaring.Bitmap // group -> transitive members

	unparsed []UnparsedFilter

	mu      sync.Mutex
	reverse map[uint32]*roaring.Bitmap // member -> ancestor groups, memoised
}

// UnparsedFilter is a dynamic group whose filter this build could not read, so it
// contributed no members.
type UnparsedFilter struct {
	Group  string
	Filter string
	Reason string
}

// newClosureIndex builds the membership of one group kind. Address groups come
// in two sorts, static and dynamic; the other group kinds are static only.
//
// A static group lists its members. A dynamic group carries a tag filter, and its
// members are the visible objects whose tags satisfy it — which is why the closure
// is scope-bound: the same filter selects different objects in different device
// groups. A filter this build cannot parse contributes no members and is recorded
// in UnparsedFilters rather than guessed at.
// addrs are the objects a tag filter selects from; nil for a group kind without
// one.
func newClosureIndex(in *Interner, groups, addrs []resolve.Object) *closureIndex {
	c := &closureIndex{
		direct:  map[uint32][]uint32{},
		forward: map[uint32]*roaring.Bitmap{},
		reverse: map[uint32]*roaring.Bitmap{},
	}
	for _, g := range groups {
		gid := in.ID(g.Name)
		if g.Dynamic {
			filter, err := resolve.ParseTagFilter(g.Value)
			if err != nil {
				c.unparsed = append(c.unparsed, UnparsedFilter{
					Group:  g.Name,
					Filter: g.Value,
					Reason: err.Error(),
				})
				continue
			}
			for _, a := range addrs {
				if filter.Match(a.Tags) {
					c.direct[gid] = append(c.direct[gid], in.ID(a.Name))
				}
			}
			continue
		}
		for m := range strings.SplitSeq(g.Value, ", ") {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			c.direct[gid] = append(c.direct[gid], in.ID(m))
		}
	}
	cut := false
	for gid := range c.direct {
		c.expand(gid, map[uint32]bool{}, &cut)
	}
	if cut {
		c.settle()
	}
	return c
}

// expand builds one group's transitive membership, guarding against a cycle. A
// cycle stops the walk and sets cut: the groups on it then miss members, and
// which ones depends on the group the walk started from.
func (c *closureIndex) expand(g uint32, onPath map[uint32]bool, cut *bool) *roaring.Bitmap {
	if b, done := c.forward[g]; done {
		return b
	}
	if onPath[g] {
		*cut = true
		return roaring.New() // a cycle: stop rather than recurse
	}
	onPath[g] = true
	b := roaring.New()
	for _, m := range c.direct[g] {
		b.Add(m)
		if _, isGroup := c.direct[m]; isGroup {
			b.Or(c.expand(m, onPath, cut))
		}
	}
	delete(onPath, g)
	c.forward[g] = b
	return b
}

// settle completes the membership after a cycle was cut: it ORs each group's
// direct members' sets into its own until no set grows, so every group on a
// cycle holds what any of them holds, whatever group the walk started from. A
// group on a cycle reaches itself; that is no membership, so it is dropped.
func (c *closureIndex) settle() {
	for grew := true; grew; {
		grew = false
		for g, members := range c.direct {
			b := c.forward[g]
			before := b.GetCardinality()
			for _, m := range members {
				if mb, isGroup := c.forward[m]; isGroup {
					b.Or(mb)
				}
			}
			grew = grew || b.GetCardinality() != before
		}
	}
	for g, b := range c.forward {
		b.Remove(g)
	}
}

// ancestors returns the groups holding a member, computing them on first ask.
func (c *closureIndex) ancestors(member uint32) *roaring.Bitmap {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.reverse[member]; ok {
		return b
	}
	b := roaring.New()
	for g, members := range c.forward {
		if members.Contains(member) {
			b.Add(g)
		}
	}
	c.reverse[member] = b
	return b
}

// addressGroups is the group kind whose closure reads tag filters too.
const addressGroups = "address-group"

// groupFamily is the closure of one group kind and the kinds its members can be.
type groupFamily struct {
	kind    string   // the group kind: address-group, service-group, application-group
	members []string // the kinds its member list can name, from the schema
	closure *closureIndex
}

// memberKinds reads from the schema the kinds a group kind's member list can name.
// Groups nest, so the member list is the group's field that can name the group
// kind itself; a group's tag field cannot.
func memberKinds(cfg *config.Config, group string) []string {
	fields := cfg.FieldKinds("/" + group)
	for _, f := range slices.Sorted(maps.Keys(fields)) {
		if slices.Contains(fields[f], group) {
			return fields[f]
		}
	}
	return nil
}

// fieldFamilies picks, for each rule field, the group families whose groups the
// field can name, as the schema declares. reach asks only those.
func fieldFamilies(kinds map[string][]string, fams []*groupFamily) map[Field][]*groupFamily {
	out := map[Field][]*groupFamily{}
	for n, name := range fieldNames {
		for _, fam := range fams {
			if slices.Contains(kinds[name], fam.kind) {
				out[Field(n)] = append(out[Field(n)], fam)
			}
		}
	}
	return out
}

// holders returns the groups of the families that hold an id, in id order. The
// closures' bitmaps are memoised and shared, so a union works on a copy, made
// only when a second family holds the id too.
func (i *Index) holders(fams []*groupFamily, id uint32) []string {
	var b *roaring.Bitmap
	copied := false
	for _, fam := range fams {
		a := fam.closure.ancestors(id)
		switch {
		case a.IsEmpty():
		case b == nil:
			b = a
		case !copied:
			b, copied = roaring.Or(b, a), true
		default:
			b.Or(a)
		}
	}
	if b == nil {
		return []string{}
	}
	return i.names(b)
}

// names turns a bitmap of ids into names, in id order.
func (i *Index) names(b *roaring.Bitmap) []string {
	out := make([]string, 0, b.GetCardinality())
	for it := b.Iterator(); it.HasNext(); {
		out = append(out, i.in.Name(it.Next()))
	}
	return out
}

// Group is a group holding a member, with the group's kind.
type Group struct {
	Kind string
	Name string
}

// GroupsHolding returns the groups holding an object of a kind: at any depth, or
// with direct only the groups that name it. Only the group kinds that can hold
// that kind are asked, so an address group and a service group of one name stay
// two groups. The groups come by kind, then name.
func (i *Index) GroupsHolding(kind, name string, direct bool) []Group {
	id, known := i.in.Lookup(name)
	if !known {
		return nil
	}
	var out []Group
	for _, fam := range i.families {
		if !slices.Contains(fam.members, kind) {
			continue
		}
		var names []string
		if direct {
			names = fam.closure.directGroups(id, i.in)
		} else {
			names = i.names(fam.closure.ancestors(id))
			slices.Sort(names)
		}
		for _, n := range names {
			out = append(out, Group{Kind: fam.kind, Name: n})
		}
	}
	return out
}

// GroupsOf returns every group holding the named object, directly or through
// nesting, in any group family.
func (i *Index) GroupsOf(name string) []string {
	id, known := i.in.Lookup(name)
	if !known {
		return nil
	}
	return i.holders(i.families, id)
}

// groupsReaching returns the groups of the field's families holding a name.
func (i *Index) groupsReaching(f Field, name string) []string {
	id, known := i.in.Lookup(name)
	if !known {
		return nil
	}
	return i.holders(i.fieldFamilies[f], id)
}

// UnparsedFilters returns the dynamic groups whose filters could not be read.
// Their membership is missing from the index, and this is how a caller finds out.
func (i *Index) UnparsedFilters() []UnparsedFilter {
	out := []UnparsedFilter{}
	for _, fam := range i.families {
		out = append(out, fam.closure.unparsed...)
	}
	return out
}

// directGroups returns the groups that name a member directly, sorted.
func (c *closureIndex) directGroups(id uint32, in *Interner) []string {
	var out []string
	for g, members := range c.direct {
		if slices.Contains(members, id) {
			out = append(out, in.Name(g))
		}
	}
	slices.Sort(out)
	return out
}

// DirectGroupsOf returns the groups that name a member directly, not through
// another group, in any group family. It answers "which group do I edit", which
// the transitive list of GroupsOf hides.
func (i *Index) DirectGroupsOf(name string) []string {
	id, known := i.in.Lookup(name)
	if !known {
		return nil
	}
	var out []string
	for _, fam := range i.families {
		out = append(out, fam.closure.directGroups(id, i.in)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// MembersOf returns the transitive members of a group, of every group kind that
// has a group of that name.
func (i *Index) MembersOf(group string) []string {
	id, known := i.in.Lookup(group)
	if !known {
		return nil
	}
	b := roaring.New()
	found := false
	for _, fam := range i.families {
		if m, ok := fam.closure.forward[id]; ok {
			b.Or(m)
			found = true
		}
	}
	if !found {
		return nil
	}
	return i.names(b)
}
