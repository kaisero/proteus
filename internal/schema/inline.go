package schema

// InlineSequences returns every named sequence that is not an entry sequence and
// not the root.
//
// These outnumber entry arrays roughly three to one — 6,720 against 2,291 in
// cms-schema.xml — and they repeat heavily: `no`, `none`, `dhcpv6`, `target` and
// `manual` each recur 48 to 78 times. Naming each after its owner produced about
// 7,200 types. Deduplicating them by shape produces 1,737.
func InlineSequences(root *Node) []*Node {
	entrySeq := map[*Node]bool{}
	for _, arr := range EntryTypes(root) {
		entrySeq[arr.EntrySequence()] = true
	}
	var res []*Node
	root.Walk(func(n *Node) {
		switch {
		case n == root:
			return
		case n.Kind != KindSequence:
			return
		case n.Name == "" || n.Name == "entry":
			return
		case entrySeq[n]:
			return
		}
		res = append(res, n)
	})
	return res
}
