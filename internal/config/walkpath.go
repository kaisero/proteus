package config

import (
	"strings"

	"github.com/okaiser/proteus/internal/schema"
)

// pathNode is one segment of an entry array's reference paths, held as a trie so
// that one descent of an entry finds every leaf.
//
// Resolving each declared path separately costs a fresh descent per path, and an
// entry array declares up to 30 of them, so the trie is not an optimisation kept
// for later: measured on a 29 MB Panorama configuration it is roughly four times
// the speed.
type pathNode struct {
	kids       map[string]*pathNode
	candidates []string // non-nil at a leaf
	predefined []bool
	path       []string
}

// pathTable is the schema side table: for an entry-array path, the trie of its
// reference leaves.
type pathTable map[string]*pathNode

func buildPathTable(root *schema.Node) pathTable {
	pt := pathTable{}
	for _, arr := range schema.EntryTypes(root) {
		refs := schema.ReferencePaths(arr.EntrySequence())
		if len(refs) == 0 {
			continue
		}
		trie := &pathNode{kids: map[string]*pathNode{}}
		for _, pr := range refs {
			cur := trie
			for _, seg := range pr.Path {
				next, ok := cur.kids[seg]
				if !ok {
					next = &pathNode{kids: map[string]*pathNode{}}
					cur.kids[seg] = next
				}
				cur = next
			}
			cur.candidates = pr.Candidates
			cur.predefined = pr.Predefined
			cur.path = pr.Path
		}
		pt[arr.Path()] = trie
	}
	return pt
}

// WalkPaths yields every reference value in the configuration, scoped, locating
// each by its path below the entry that holds it.
//
// It replaces Walk. Walk sees one shape, entry/<field>/member, which is 397 of
// the firewall schema's 1,991 reference leaves: it cannot see a leaf that is an
// element's text, such as a rule's log-setting, nor one below a named union,
// such as a rule's profile-setting/group/member.
func (c *Config) WalkPaths(fn func(Event) bool) error {
	stop := false
	walkPathElement(c.root, c.schema.paths, Scope{Sort: ScopeConfig}, fn, &stop)
	return nil
}

func walkPathElement(e *Element, pt pathTable, scope Scope, fn func(Event) bool, stop *bool) {
	if *stop || e == nil {
		return
	}
	if sc, ok := scopeOf(e); ok {
		scope = sc
	}
	if e.Name == "entry" && e.Parent != nil {
		if trie, known := pt[e.Parent.SchemaPath()]; known {
			emitPaths(e, trie, e.Parent.SchemaPath(), scope, fn, stop)
			if *stop {
				return
			}
		}
	}
	for _, c := range e.Children {
		walkPathElement(c, pt, scope, fn, stop)
		if *stop {
			return
		}
	}
}

// fieldName names a leaf for display and for the reference key.
//
// A member list's path ends at member, which says nothing a reader wants, so it
// is dropped: source/member is source, exactly what Walk reported. What remains
// is a path only where the leaf really is nested, as in profile-setting/group.
// Trimming cannot collide, because an element is either a member list or a text
// leaf and never both.
func fieldName(path []string) string {
	if n := len(path); n > 1 && path[n-1] == "member" {
		path = path[:n-1]
	}
	return strings.Join(path, "/")
}

// emitPaths descends one entry along its trie, emitting a value wherever a leaf
// matches.
//
// A value is always an element's text. A member list needs no special case: its
// path ends at member and the descent visits each <member> sibling in turn,
// which is the same loop. EntryPath is built at most once per entry, because
// InstancePath walks to the root and an entry can hold many values.
func emitPaths(entry *Element, trie *pathNode, schemaPath string, scope Scope, fn func(Event) bool, stop *bool) {
	epath := ""
	var descend func(el *Element, node *pathNode)
	descend = func(el *Element, node *pathNode) {
		if *stop {
			return
		}
		for _, child := range el.Children {
			sub, ok := node.kids[child.Name]
			if !ok {
				continue
			}
			if sub.candidates != nil {
				v := strings.TrimSpace(child.Text)
				if v != "" && !Keywords[v] {
					if epath == "" {
						epath = entry.InstancePath()
					}
					if !fn(Event{
						Kind:       EventReference,
						Scope:      scope,
						EntryPath:  epath,
						SchemaPath: schemaPath,
						Field:      fieldName(sub.path),
						Path:       sub.path,
						Values:     []string{v},
						Candidates: sub.candidates,
					}) {
						*stop = true
						return
					}
				}
			}
			if len(sub.kids) > 0 {
				descend(child, sub)
				if *stop {
					return
				}
			}
		}
	}
	descend(entry, trie)
}
