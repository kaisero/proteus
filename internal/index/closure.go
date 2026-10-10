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
	direct  map[uint32]*roaring.Bitmap // group -> direct members
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
		direct:  map[uint32]*roaring.Bitmap{},
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
					c.add(gid, in.ID(a.Name))
				}
			}
			continue
		}
		for m := range strings.SplitSeq(g.Value, ", ") {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			c.add(gid, in.ID(m))
		}
	}
	c.settle()
	return c
}

// add records a direct member. A group becomes one with its first member.
func (c *closureIndex) add(g, m uint32) {
	b, ok := c.direct[g]
	if !ok {
		b = roaring.New()
		c.direct[g] = b
	}
	b.Add(m)
}

// settle builds every group's transitive membership in one pass. Groups may form
// a cycle, which the configuration allows: the groups of a strongly connected
// component hold each other, so they share one set, built once. The components
// come from components in an order where a component follows every component it
// holds, so the sets a group's members need are always complete. A group on a
// cycle reaches itself; that is no membership, so it is dropped.
//
// Measured on 20,000 addresses and 5,000 rules beside one cycle of 5,000 groups
// (BenchmarkIndexBuildGroupCycle): the build took 29 s while it ORed the
// members' sets until none grew; with one pass over the components it takes
// 73 ms.
func (c *closureIndex) settle() {
	// A member that is a group leads the walk on; any other member ends it.
	groups := func(g uint32) []uint32 {
		var out []uint32
		for it := c.direct[g].Iterator(); it.HasNext(); {
			if m := it.Next(); c.direct[m] != nil {
				out = append(out, m)
			}
		}
		return out
	}
	for _, comp := range components(slices.Sorted(maps.Keys(c.direct)), groups) {
		b := roaring.New()
		for _, g := range comp {
			b.Or(c.direct[g])
			for it := c.direct[g].Iterator(); it.HasNext(); {
				// A member of this component has no set yet; its members are
				// the component's own, added by this loop.
				if mb, done := c.forward[it.Next()]; done {
					b.Or(mb)
				}
			}
		}
		for _, g := range comp {
			if !b.Contains(g) {
				c.forward[g] = b // a group on no cycle: the set is its own
				continue
			}
			own := b.Clone()
			own.Remove(g)
			c.forward[g] = own
		}
	}
}

// components returns the strongly connected components of a graph, by Tarjan's
// algorithm, each after every component its nodes lead to. next gives the nodes
// a node leads to. The walk keeps its own stack rather than recursing, so a long
// chain costs no call depth.
func components[N comparable](nodes []N, next func(N) []N) [][]N {
	type frame struct {
		n    N
		next []N // the nodes still to visit from n
	}
	order := map[N]int{} // visit order
	low := map[N]int{}   // lowest visit order the node reaches on the stack
	onStack := map[N]bool{}
	var stack []N
	var out [][]N
	visit := func(n N) frame {
		order[n], low[n] = len(order), len(order)
		stack = append(stack, n)
		onStack[n] = true
		return frame{n: n, next: next(n)}
	}
	for _, root := range nodes {
		if _, seen := order[root]; seen {
			continue
		}
		walk := []frame{visit(root)}
		for len(walk) > 0 {
			f := &walk[len(walk)-1]
			if len(f.next) > 0 {
				m := f.next[0]
				f.next = f.next[1:]
				if _, seen := order[m]; !seen {
					walk = append(walk, visit(m))
				} else if onStack[m] {
					low[f.n] = min(low[f.n], order[m])
				}
				continue
			}
			n := f.n
			walk = walk[:len(walk)-1]
			if len(walk) > 0 {
				p := walk[len(walk)-1].n
				low[p] = min(low[p], low[n])
			}
			if low[n] != order[n] {
				continue
			}
			var comp []N
			for {
				top := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[top] = false
				comp = append(comp, top)
				if top == n {
					break
				}
			}
			out = append(out, comp)
		}
	}
	return out
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
// kind itself; a group's tag field cannot. It is nil when the schema has no such
// field; GroupsHolding then asks that group kind for every kind.
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
		// A group kind whose members the schema does not name is asked for
		// every kind: a group too many beats a group missing (spec S12).
		if fam.members != nil && !slices.Contains(fam.members, kind) {
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
		if members.Contains(id) {
			out = append(out, in.Name(g))
		}
	}
	slices.Sort(out)
	return out
}
