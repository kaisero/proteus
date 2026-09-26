package schema

import "strings"

// Kind is the grammar construct a node represents.
type Kind int

// The grammar constructs a PAN-OS schema uses.
const (
	KindSequence Kind = iota // a container
	KindArray                // a list, either entry-keyed or of members
	KindElement              // a leaf value
	KindChoice               // mutually exclusive alternatives
	KindUnion                // alternative representations of one value
	KindAttrReq              // a required XML attribute, in practice always name
	KindEnum                 // one permitted value of an enum element
	KindMemberOf             // a reference target declaration
)

var kindNames = map[Kind]string{
	KindSequence: "sequence", KindArray: "array", KindElement: "element",
	KindChoice: "choice", KindUnion: "union", KindAttrReq: "attr-req",
	KindEnum: "enum", KindMemberOf: "memberof",
}

func (k Kind) String() string {
	if s, ok := kindNames[k]; ok {
		return s
	}
	return "unknown"
}

// Node is one grammar construct. A Node is read-only once parsed.
type Node struct {
	Kind     Kind
	Name     string
	Type     string // schema leaf type: string, bool, enum, rangedint, float, ...
	Optional bool
	Default  string
	MaxLen   int
	Min      string
	Max      string
	Help     string
	Regex    string
	SubType  string

	EnumValues []string // permitted values, when Type is enum
	MemberOf   []string // reference targets declared on this node

	memberOfTarget string // memberof given as an attribute rather than text

	Children []*Node
	Parent   *Node
}

// Path returns the config xpath of the node, built from named ancestors.
func (n *Node) Path() string {
	return "/" + strings.Join(n.Segments(), "/")
}

// Segments returns the named path segments from the root down to the node.
func (n *Node) Segments() []string {
	var segs []string
	for cur := n; cur != nil; cur = cur.Parent {
		if cur.Name != "" {
			segs = append(segs, cur.Name)
		}
	}
	for i, j := 0, len(segs)-1; i < j; i, j = i+1, j-1 {
		segs[i], segs[j] = segs[j], segs[i]
	}
	return segs
}

// Child returns the named child, or nil. Choice and union wrappers are
// transparent: their children are ordinary optional siblings in the XML, so a
// lookup passes straight through them.
func (n *Node) Child(name string) *Node {
	if n == nil {
		return nil
	}
	for _, c := range n.Children {
		switch c.Kind {
		case KindChoice, KindUnion:
			if got := c.Child(name); got != nil {
				return got
			}
		default:
			if c.Name == name {
				return c
			}
		}
	}
	return nil
}

// Fields returns the node's children with choice and union wrappers flattened.
func (n *Node) Fields() []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, c := range n.Children {
		switch c.Kind {
		case KindChoice, KindUnion:
			out = append(out, c.Fields()...)
		default:
			out = append(out, c)
		}
	}
	return out
}

// EntrySequence returns the <sequence name="entry"> of an entry-keyed array.
func (n *Node) EntrySequence() *Node {
	if n == nil || n.Kind != KindArray {
		return nil
	}
	for _, c := range n.Fields() {
		if c.Kind == KindSequence && c.Name == "entry" {
			return c
		}
	}
	return nil
}

// IsEntryList reports whether the array holds named entries.
func (n *Node) IsEntryList() bool { return n.EntrySequence() != nil }

// IsMemberList reports whether the array holds plain string members.
func (n *Node) IsMemberList() bool {
	if n == nil || n.Kind != KindArray {
		return false
	}
	for _, c := range n.Fields() {
		if c.Kind == KindElement && c.Name == "member" {
			return true
		}
	}
	return false
}

// Walk calls fn for the node and every descendant, depth first.
func (n *Node) Walk(fn func(*Node)) {
	if n == nil {
		return
	}
	fn(n)
	for _, c := range n.Children {
		c.Walk(fn)
	}
}
