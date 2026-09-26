package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// maxShapeDepth bounds fingerprint recursion. The deepest observed entry path in
// cms-schema.xml is 22 segments; 24 leaves headroom without risking a cycle.
const maxShapeDepth = 24

// EntryTypes returns every entry-keyed array in the tree, in document order.
func EntryTypes(root *Node) []*Node {
	var out []*Node
	root.Walk(func(n *Node) {
		if n.Kind == KindArray && n.IsEntryList() {
			out = append(out, n)
		}
	})
	return out
}

// MemberLists returns every member-list array in the tree, in document order.
func MemberLists(root *Node) []*Node {
	var out []*Node
	root.Walk(func(n *Node) {
		if n.Kind == KindArray && n.IsMemberList() {
			out = append(out, n)
		}
	})
	return out
}

// Fingerprint returns a stable hash of a subtree's structure: element names,
// node kinds and leaf types, recursively. Two subtrees with the same fingerprint
// generate one Go type.
//
// Children are sorted, so field order in the schema does not change the
// fingerprint. Help strings, defaults, limits and reference targets are
// excluded: they annotate a field without changing its Go shape.
func Fingerprint(n *Node) string {
	sum := sha256.Sum256([]byte(shapeString(n, 0)))
	return hex.EncodeToString(sum[:16])
}

func shapeString(n *Node, depth int) string {
	if n == nil {
		return "()"
	}
	if depth > maxShapeDepth {
		return "(...)"
	}
	kids := make([]string, 0, len(n.Children))
	for _, c := range n.Children {
		switch c.Kind {
		case KindEnum, KindMemberOf:
			continue // annotations, not structure
		}
		kids = append(kids, shapeString(c, depth+1))
	}
	sort.Strings(kids)
	var sb strings.Builder
	sb.WriteByte('(')
	sb.WriteString(n.Kind.String())
	sb.WriteByte('|')
	sb.WriteString(n.Name)
	sb.WriteByte('|')
	sb.WriteString(n.Type)
	sb.WriteByte(':')
	sb.WriteString(strings.Join(kids, ","))
	sb.WriteByte(')')
	return sb.String()
}

// GroupByShape groups entry-keyed arrays by the fingerprint of their entry
// sequence. The returned slices keep document order, so the first element is the
// shallowest occurrence when the input came from EntryTypes.
func GroupByShape(entries []*Node) map[string][]*Node {
	out := make(map[string][]*Node, len(entries))
	for _, e := range entries {
		fp := Fingerprint(e.EntrySequence())
		out[fp] = append(out[fp], e)
	}
	return out
}
