package schema

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
