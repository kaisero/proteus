package schema

import "testing"

// Step finds the node of a child element: through an anonymous choice or
// union, but not into a named one, and never onto an attribute.
func TestStep(t *testing.T) {
	t.Parallel()
	seq := &Node{Kind: KindSequence, Name: "entry"}
	entries := &Node{Kind: KindArray, Name: "address", Children: []*Node{seq}}
	member := &Node{Kind: KindElement, Name: "member"}
	members := &Node{Kind: KindArray, Name: "tag", Children: []*Node{member}}
	inChoice := &Node{Kind: KindElement, Name: "fqdn"}
	group := &Node{Kind: KindElement, Name: "group"}
	named := &Node{Kind: KindUnion, Name: "profile-setting", Children: []*Node{group}}
	root := &Node{Kind: KindSequence, Name: "config", Children: []*Node{
		{Kind: KindAttrReq, Name: "name"},
		entries, members, named,
		{Kind: KindChoice, Children: []*Node{{Kind: KindUnion, Children: []*Node{inChoice}}}},
	}}
	cases := []struct {
		from *Node
		name string
		want *Node
	}{
		{root, "address", entries},
		{entries, "entry", seq},
		{members, "member", member},
		{members, "entry", nil},
		{root, "fqdn", inChoice},
		{root, "profile-setting", named},
		{root, "group", nil},
		{named, "group", group},
		{root, "name", nil},
		{root, "missing", nil},
		{nil, "address", nil},
	}
	for _, c := range cases {
		if got := c.from.Step(c.name); got != c.want {
			t.Errorf("Step(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// EntrySequence looks through choices and unions, as Fields does, and finds
// nothing in an array of members or in a node that is not an array.
func TestEntrySequence(t *testing.T) {
	t.Parallel()
	seq := &Node{Kind: KindSequence, Name: "entry"}
	wrapped := &Node{Kind: KindArray, Children: []*Node{
		{Kind: KindChoice, Children: []*Node{{Kind: KindElement, Name: "x"}}},
		{Kind: KindUnion, Name: "u", Children: []*Node{seq}},
	}}
	if got := wrapped.EntrySequence(); got != seq {
		t.Errorf("wrapped: got %v", got)
	}
	members := &Node{Kind: KindArray, Children: []*Node{
		{Kind: KindSequence, Name: "other"}, {Kind: KindElement, Name: "member"},
	}}
	for name, n := range map[string]*Node{
		"members": members, "sequence": {Kind: KindSequence, Children: []*Node{seq}}, "nil": nil,
	} {
		if got := n.EntrySequence(); got != nil {
			t.Errorf("%s: got %v, want nil", name, got)
		}
	}
}
