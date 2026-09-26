package codegen

import (
	"sort"
	"strings"

	"github.com/okaiser/go-panos-schema/internal/schema"
)

// ModelPackage is the single package every generated type lives in.
//
// Splitting by configuration area was tried and does not compile: a device group
// holds address objects whose shape lives in shared, and shared holds shapes
// reached from a device group, so the two packages import each other. devices and
// template-stack form a second cycle. Go forbids both.
const ModelPackage = "model"

// maxNameLen bounds an emitted name. Measured over 576 Panorama names: p50 17,
// p90 27, p99 38, longest 49.
const maxNameLen = 50

// skipSegment holds path segments that carry no naming information.
var skipSegment = map[string]bool{"config": true, "entry": true}

// reservedTypeNames are the types the generator declares itself. A shape that
// would take one of these names is lengthened instead.
var reservedTypeNames = []string{"Config", "MemberList", "RawNode"}

// ShapeKind distinguishes a named entry from an inline sequence. An entry has a
// name attribute and a list wrapper; an inline sequence has neither.
type ShapeKind int

// The two kinds of shape the generator names.
const (
	KindEntry ShapeKind = iota
	KindInline
)

func (k ShapeKind) String() string {
	if k == KindInline {
		return "inline"
	}
	return "entry"
}

// Shapes holds both kinds of deduplicated shape, keyed by fingerprint.
type Shapes struct {
	Entry  map[string][]*schema.Node // the ARRAY node, whose EntrySequence is the shape
	Inline map[string][]*schema.Node // the SEQUENCE node itself
}

// AllShapes groups every entry array and every inline sequence by shape.
func AllShapes(root *schema.Node) Shapes {
	return Shapes{
		Entry:  schema.GroupByShape(schema.EntryTypes(root)),
		Inline: groupInline(schema.InlineSequences(root)),
	}
}

func groupInline(nodes []*schema.Node) map[string][]*schema.Node {
	out := make(map[string][]*schema.Node, len(nodes))
	for _, n := range nodes {
		fp := schema.Fingerprint(n)
		out[fp] = append(out[fp], n)
	}
	return out
}

// TypeName is one generated Go type: a canonical name, plus the aliases other
// paths of the same shape contribute.
type TypeName struct {
	Fingerprint string
	Kind        ShapeKind
	Package     string
	Canonical   string
	Aliases     []string
	Paths       []string
	Shallowest  string
}

// Pascal converts a schema name to a Go identifier.
func Pascal(s string) string {
	var sb strings.Builder
	up := true
	for _, r := range s {
		switch {
		case r == '-' || r == '_' || r == '.' || r == ' ':
			up = true
		case up:
			sb.WriteString(strings.ToUpper(string(r)))
			up = false
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func meaningful(n *schema.Node) []string {
	var out []string
	for _, s := range n.Segments() {
		if skipSegment[s] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// shallower ranks paths for rule 1: fewest segments first, then segment by
// segment. Comparing the joined path string instead would pick template-stack
// over template, because '-' sorts before '/'.
func shallower(a, b *schema.Node) bool {
	sa, sb := meaningful(a), meaningful(b)
	if len(sa) != len(sb) {
		return len(sa) < len(sb)
	}
	for i := range sa {
		if sa[i] != sb[i] {
			return sa[i] < sb[i]
		}
	}
	return a.Path() < b.Path()
}

// Names applies the naming rules to every shape, entry and inline alike.
//
// Entry shapes are named first, so an entry keeps the plainer name when an entry
// and an inline sequence compete for it. Within each group the shallowest path
// wins.
func Names(shapes Shapes) []TypeName {
	out := make([]TypeName, 0, len(shapes.Entry)+len(shapes.Inline))
	out = append(out, nameGroup(shapes.Entry, KindEntry, true)...)
	out = append(out, nameGroup(shapes.Inline, KindInline, false)...)
	resolveAllCollisions(out, shapes)
	return out
}

// nameGroup produces unresolved names for one group. suffix adds "Entry", which
// only entry shapes carry.
func nameGroup(group map[string][]*schema.Node, kind ShapeKind, suffix bool) []TypeName {
	fps := make([]string, 0, len(group))
	for fp := range group {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	out := make([]TypeName, 0, len(group))
	for _, fp := range fps {
		nodes := append([]*schema.Node{}, group[fp]...)
		sort.Slice(nodes, func(i, j int) bool { return shallower(nodes[i], nodes[j]) })
		head := nodes[0]

		tn := TypeName{
			Fingerprint: fp,
			Kind:        kind,
			Package:     ModelPackage,
			Canonical:   name(head.Name, suffix),
			Shallowest:  head.Path(),
		}
		seen := map[string]bool{head.Name: true}
		for _, n := range nodes {
			tn.Paths = append(tn.Paths, n.Path())
			if !seen[n.Name] {
				seen[n.Name] = true
				tn.Aliases = append(tn.Aliases, name(n.Name, suffix))
			}
		}
		sort.Strings(tn.Aliases)
		out = append(out, tn)
	}
	return out
}

func name(schemaName string, suffix bool) string {
	if suffix {
		return Pascal(schemaName) + "Entry"
	}
	return Pascal(schemaName)
}

// resolveAllCollisions applies rule 2 to every emitted name, canonical and alias
// alike, across both groups. Two shapes can each contribute the same name — arp
// and neighbour share a shape, and a different shape also ends in neighbour.
//
// Names are claimed entry shapes first, then shallowest first, canonical before
// alias, so the result does not depend on map order.
func resolveAllCollisions(names []TypeName, shapes Shapes) {
	claimed := map[string]bool{}
	// The generator declares these itself, so no shape may take them. The real
	// schema does contain an inline sequence named "config", under
	// mgt-config/users/entry/preferences/saved-log-query.
	for _, r := range reservedTypeNames {
		claimed[r] = true
	}

	nodesOf := func(tn TypeName) []*schema.Node {
		if tn.Kind == KindEntry {
			return shapes.Entry[tn.Fingerprint]
		}
		return shapes.Inline[tn.Fingerprint]
	}

	order := make([]int, len(names))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		na, nb := names[order[a]], names[order[b]]
		if na.Kind != nb.Kind {
			return na.Kind == KindEntry
		}
		la := len(meaningful(nodesOf(na)[0]))
		lb := len(meaningful(nodesOf(nb)[0]))
		if la != lb {
			return la < lb
		}
		return na.Shallowest < nb.Shallowest
	})

	for _, i := range order {
		tn := &names[i]
		nodes := nodesOf(*tn)
		sort.Slice(nodes, func(a, b int) bool { return shallower(nodes[a], nodes[b]) })
		suffix := tn.Kind == KindEntry

		tn.Canonical = lengthen(claimed, nodes[0], tn.Canonical, suffix)
		claimed[tn.Canonical] = true

		owner := map[string]*schema.Node{}
		for _, n := range nodes {
			alias := name(n.Name, suffix)
			if _, dup := owner[alias]; !dup {
				owner[alias] = n
			}
		}
		fixed := make([]string, 0, len(tn.Aliases))
		for _, alias := range tn.Aliases {
			src := owner[alias]
			if src == nil {
				src = nodes[0]
			}
			got := lengthen(claimed, src, alias, suffix)
			if got == tn.Canonical {
				continue
			}
			claimed[got] = true
			fixed = append(fixed, got)
		}
		sort.Strings(fixed)
		tn.Aliases = fixed
	}
}

// lengthen returns a free name, prepending parent segments until it finds one.
func lengthen(claimed map[string]bool, node *schema.Node, base string, suffix bool) string {
	if !claimed[base] {
		return base
	}
	tail := ""
	if suffix {
		tail = "Entry"
	}
	segs := meaningful(node)
	for extra := 1; extra < len(segs); extra++ {
		var cand strings.Builder
		for _, s := range segs[len(segs)-1-extra:] {
			cand.WriteString(Pascal(s))
		}
		cand.WriteString(tail)
		if c := cand.String(); !claimed[c] && len(c) <= maxNameLen {
			return c
		}
	}
	// The path is exhausted. Fall back to a fingerprint suffix, which is stable
	// across runs because it is content-derived.
	return strings.TrimSuffix(base, tail) + "X" + shortFPOf(node) + tail
}

// shortFPOf fingerprints whichever subtree the node represents.
func shortFPOf(n *schema.Node) string {
	target := n
	if seq := n.EntrySequence(); seq != nil {
		target = seq
	}
	fp := schema.Fingerprint(target)
	if len(fp) > 6 {
		return strings.ToUpper(fp[:6])
	}
	return strings.ToUpper(fp)
}
