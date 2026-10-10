package index

import (
	"slices"
	"strings"
	"sync"

	"github.com/RoaringBitmap/roaring/v2"

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

// newClosureIndex builds group membership from both kinds of group.
//
// A static group lists its members. A dynamic group carries a tag filter, and its
// members are the visible objects whose tags satisfy it — which is why the closure
// is scope-bound: the same filter selects different objects in different device
// groups. A filter this build cannot parse contributes no members and is recorded
// in UnparsedFilters rather than guessed at.
// A group set other than address groups carries no tag filter, so only the first is
// checked for one. PAN-OS gives a dynamic filter to address groups alone.
func newClosureIndex(in *Interner, groups, addrs []resolve.Object, others ...[]resolve.Object) *closureIndex {
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
	for _, set := range others {
		for _, g := range set {
			gid := in.ID(g.Name)
			for m := range strings.SplitSeq(g.Value, ", ") {
				if m = strings.TrimSpace(m); m != "" {
					c.direct[gid] = append(c.direct[gid], in.ID(m))
				}
			}
		}
	}
	for gid := range c.direct {
		c.expand(gid, map[uint32]bool{})
	}
	return c
}

// expand builds one group's transitive membership, guarding against a cycle.
func (c *closureIndex) expand(g uint32, onPath map[uint32]bool) *roaring.Bitmap {
	if b, done := c.forward[g]; done {
		return b
	}
	if onPath[g] {
		return roaring.New() // a cycle: stop rather than recurse
	}
	onPath[g] = true
	b := roaring.New()
	for _, m := range c.direct[g] {
		b.Add(m)
		if _, isGroup := c.direct[m]; isGroup {
			b.Or(c.expand(m, onPath))
		}
	}
	delete(onPath, g)
	c.forward[g] = b
	return b
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

// GroupsOf returns every group holding the named object, directly or through
// nesting.
func (i *Index) GroupsOf(name string) []string {
	id, known := i.in.Lookup(name)
	if !known {
		return nil
	}
	b := i.closure.ancestors(id)
	out := make([]string, 0, b.GetCardinality())
	it := b.Iterator()
	for it.HasNext() {
		out = append(out, i.in.Name(it.Next()))
	}
	return out
}

// UnparsedFilters returns the dynamic groups whose filters could not be read.
// Their membership is missing from the index, and this is how a caller finds out.
func (i *Index) UnparsedFilters() []UnparsedFilter {
	return append([]UnparsedFilter{}, i.closure.unparsed...)
}

// DirectGroupsOf returns the groups that name a member directly, not through
// another group. It answers "which group do I edit", which the transitive list of
// GroupsOf hides.
func (i *Index) DirectGroupsOf(name string) []string {
	id, known := i.in.Lookup(name)
	if !known {
		return nil
	}
	var out []string
	for g, members := range i.closure.direct {
		if slices.Contains(members, id) {
			out = append(out, i.in.Name(g))
		}
	}
	slices.Sort(out)
	return out
}

// MembersOf returns the transitive members of a group.
func (i *Index) MembersOf(group string) []string {
	id, known := i.in.Lookup(group)
	if !known {
		return nil
	}
	b, ok := i.closure.forward[id]
	if !ok {
		return nil
	}
	out := make([]string, 0, b.GetCardinality())
	it := b.Iterator()
	for it.HasNext() {
		out = append(out, i.in.Name(it.Next()))
	}
	return out
}
