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

// TypeName is one generated Go type: a canonical name, plus the aliases other
// paths of the same shape contribute.
type TypeName struct {
	Fingerprint string
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

// Names applies the naming rules to grouped shapes.
func Names(groups map[string][]*schema.Node) []TypeName {
	fps := make([]string, 0, len(groups))
	for fp := range groups {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	out := make([]TypeName, 0, len(groups))
	for _, fp := range fps {
		nodes := append([]*schema.Node{}, groups[fp]...)
		sort.Slice(nodes, func(i, j int) bool { return shallower(nodes[i], nodes[j]) })
		head := nodes[0]

		tn := TypeName{
			Fingerprint: fp,
			Package:     ModelPackage,
			Canonical:   Pascal(head.Name) + "Entry",
			Shallowest:  head.Path(),
		}
		seen := map[string]bool{head.Name: true}
		for _, n := range nodes {
			tn.Paths = append(tn.Paths, n.Path())
			if !seen[n.Name] {
				seen[n.Name] = true
				tn.Aliases = append(tn.Aliases, Pascal(n.Name)+"Entry")
			}
		}
		sort.Strings(tn.Aliases)
		out = append(out, tn)
	}
	resolveCollisions(out, groups)
	return out
}

// resolveCollisions applies rule 2 to every emitted name, canonical and alias
// alike. Two shapes can each contribute the same name — arp and neighbour share a
// shape, and a different shape also ends in neighbour.
//
// Names are claimed shallowest first, canonical before alias, so the result does
// not depend on map order.
func resolveCollisions(names []TypeName, groups map[string][]*schema.Node) {
	claimed := map[string]bool{}

	order := make([]int, len(names))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		na, nb := names[order[a]], names[order[b]]
		la := len(meaningful(groups[na.Fingerprint][0]))
		lb := len(meaningful(groups[nb.Fingerprint][0]))
		if la != lb {
			return la < lb
		}
		return na.Shallowest < nb.Shallowest
	})

	lengthen := func(node *schema.Node, base string) string {
		if !claimed[base] {
			return base
		}
		segs := meaningful(node)
		for extra := 1; extra < len(segs); extra++ {
			var cand strings.Builder
			for _, s := range segs[len(segs)-1-extra:] {
				cand.WriteString(Pascal(s))
			}
			cand.WriteString("Entry")
			if c := cand.String(); !claimed[c] && len(c) <= maxNameLen {
				return c
			}
		}
		// The path is exhausted. Fall back to a fingerprint suffix, which is
		// stable across runs because it is content-derived. Measured on both 11.2
		// schemas this never triggers; it is a guard, not a routine path.
		return strings.TrimSuffix(base, "Entry") + "X" + shortFP(node) + "Entry"
	}

	for _, i := range order {
		tn := &names[i]
		nodes := groups[tn.Fingerprint]
		sort.Slice(nodes, func(a, b int) bool { return shallower(nodes[a], nodes[b]) })

		tn.Canonical = lengthen(nodes[0], tn.Canonical)
		claimed[tn.Canonical] = true

		owner := map[string]*schema.Node{}
		for _, n := range nodes {
			alias := Pascal(n.Name) + "Entry"
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
			got := lengthen(src, alias)
			if got == tn.Canonical {
				continue // the alias resolved onto its own canonical
			}
			claimed[got] = true
			fixed = append(fixed, got)
		}
		sort.Strings(fixed)
		tn.Aliases = fixed
	}
}

func shortFP(n *schema.Node) string {
	fp := schema.Fingerprint(n.EntrySequence())
	if len(fp) > 6 {
		return strings.ToUpper(fp[:6])
	}
	return strings.ToUpper(fp)
}
