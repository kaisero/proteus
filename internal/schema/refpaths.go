package schema

// PathRefs is one reference leaf, located by its path relative to an entry.
//
// References groups by top-level field name, which is lossy in two ways that
// matter: a named choice or union is a real element in the configuration but
// Fields() flattens it away, and a leaf several levels down collapses onto the
// field that contains it. profile-setting is both at once — it is a named union
// holding group and profiles — so a rule's profile edges cannot be located from
// a FieldRefs at all. PathRefs keeps the path, so each leaf stands on its own and
// carries only the candidates the schema declares for it.
type PathRefs struct {
	Path       []string // relative to the entry sequence, e.g. profile-setting/group/member
	Candidates []string // in the order the schema lists them
	Predefined []bool   // Predefined[i] reports whether Candidates[i] is predefined content
}

// PathFields returns a node's children with anonymous choice and union nodes
// flattened away, unlike Fields, which flattens named ones too.
//
// A named choice or union is an element in the configuration: profile-setting is
// a union, and the rule holds <profile-setting> with group or profiles beneath
// it. Flattening it loses a path segment and the remaining path then matches
// nothing. An anonymous one is pure grammar and has no element, so it is
// transparent here as well. The firewall schema has 358 named and 325 anonymous.
func PathFields(n *Node) []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, c := range n.Children {
		switch {
		case (c.Kind == KindChoice || c.Kind == KindUnion) && c.Name == "":
			out = append(out, PathFields(c)...)
		default:
			out = append(out, c)
		}
	}
	return out
}

// ReferencePaths returns every reference leaf beneath an entry sequence, each
// located by its own path.
//
// The walk stops at a nested entry array, so a leaf belongs to the entry array
// that holds it most closely. That is the attribution the configuration walk
// uses, and it is what lets a nested object's edges name the nested object
// rather than its grandparent.
//
// The stop is a kind check, not a name check. An element named entry is not
// necessarily an entry list: prefix-list holds <prefix><entry><network/></entry>,
// where entry is a bare sequence with no name attribute.
func ReferencePaths(seq *Node) []PathRefs {
	var out []PathRefs
	var rec func(n *Node, rel []string)
	rec = func(n *Node, rel []string) {
		if n.Kind == KindArray && n.IsEntryList() {
			return // a nested entry array owns its own leaves
		}
		if len(n.MemberOf) > 0 && len(rel) > 0 {
			pr := PathRefs{Path: append([]string(nil), rel...)}
			seen := map[string]bool{}
			for _, raw := range n.MemberOf {
				ref, err := ParseTarget(raw)
				if err != nil || seen[ref.Kind] {
					continue
				}
				seen[ref.Kind] = true
				pr.Candidates = append(pr.Candidates, ref.Kind)
				pr.Predefined = append(pr.Predefined, ref.Predefined)
			}
			if len(pr.Candidates) > 0 {
				out = append(out, pr)
			}
		}
		for _, c := range PathFields(n) {
			next := rel
			if c.Name != "" {
				next = append(append([]string(nil), rel...), c.Name)
			}
			rec(c, next)
		}
	}
	for _, f := range PathFields(seq) {
		if f.Name == "" {
			continue
		}
		rec(f, []string{f.Name})
	}
	return out
}
