package fetch

import (
	"bytes"
	"cmp"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/runlog"
	"github.com/kaisero/proteus/internal/schema"
	"github.com/kaisero/proteus/internal/task"
)

// MergeStats counts what a merge did: the template elements it added, each
// with its subtree, and the base elements it kept over the template element
// of their place: template objects, leaves and member lists.
type MergeStats struct{ Added, KeptLocal int }

// MergeTemplate merges the config element of a pushed template into the base,
// the running configuration or its export (spec 2026-10-17 §2.2, D2). It
// starts at the two config elements and compares the children of each pair of
// matched elements. Two elements match when they have the same name under
// matched parents, and two entries also the same name attribute. For a
// template element, in this order:
//
//   - a template object that the base also holds, an element whose schema node
//     in root has the mark tlo="yes": the base element stays whole, and no
//     template value of it shows. A local value of a template object needs a
//     local copy of the whole object, and the merged view then shows the local
//     copy only (as observed on fw01, PAN-OS 11.2.5, C6, C11);
//   - a leaf that the base also holds, or a member list that holds a member in
//     the base: the base value, whole;
//   - another element that the base also holds, the device entry and the vsys
//     entry among them, and an element that the digest does not describe: the
//     merge goes on in their children (C11);
//   - an element that the base lacks: it joins the matched base parent with its
//     subtree, after the parent's children, in the order of the template.
//
// The result is the base, byte for byte, with the bytes of the template
// elements inserted, each with the indent before it in the template. An empty
// base element that takes a template element gets an end tag. The merge never
// writes an element again and adds no attribute, so the root keeps the base's
// version. An error names no value of either document.
func MergeTemplate(base, template []byte, root *schema.Node) ([]byte, MergeStats, error) {
	b, err := scanElements(base)
	if err != nil {
		return nil, MergeStats{}, fmt.Errorf("the base configuration: %w", err)
	}
	t, err := scanElements(template)
	if err != nil {
		return nil, MergeStats{}, fmt.Errorf("the template: %w", err)
	}
	if b.name != "config" || t.name != "config" {
		return nil, MergeStats{}, errors.New("the base or the template is no config element")
	}
	m := merger{base: base, template: template}
	m.merge(b, t, root)
	return m.result(), m.stats, nil
}

// merger collects the edits of one merge.
type merger struct {
	base, template []byte
	edits          []edit
	stats          MergeStats
}

// edit replaces the base bytes from at to at+cut with text.
type edit struct {
	at, cut int
	text    []byte
}

// merge merges the children of a template element into those of the base
// element it matched; n is the schema node of both, nil when the digest does
// not describe them.
func (m *merger) merge(b, t *node, n *schema.Node) {
	local := make(map[nodeKey]*node, len(b.children))
	for _, c := range b.children {
		if _, seen := local[c.key()]; !seen {
			local[c.key()] = c
		}
	}
	var add [][]byte
	for _, tc := range t.children {
		cn := n.Step(tc.name)
		bc := local[tc.key()]
		switch {
		case bc == nil:
			add = append(add, m.template[tc.lead:tc.end])
			m.stats.Added++
		case cn != nil && cn.TemplateObject, tc.leaf() || bc.leaf(), cn.IsMemberList() && bc.holds("member"):
			m.stats.KeptLocal++
		default:
			m.merge(bc, tc, cn)
		}
	}
	if len(add) > 0 {
		m.insert(b, bytes.Join(add, nil))
	}
}

// insert puts template bytes into a base element after its children, or after
// its start tag when it has none. An empty element, <name/>, gets an end tag.
func (m *merger) insert(b *node, text []byte) {
	if b.empty {
		tag := m.base[b.start+1 : b.open]
		name := tag[:bytes.IndexAny(tag, " \t\r\n/")]
		m.edits = append(m.edits, edit{at: b.open - 2, cut: 2, text: slices.Concat([]byte(">"), text, []byte("</"), name, []byte(">"))})
		return
	}
	at := b.open
	if len(b.children) > 0 {
		at = b.children[len(b.children)-1].end
	}
	m.edits = append(m.edits, edit{at: at, text: text})
}

// result is the base with the edits made, in the order of the base.
func (m *merger) result() []byte {
	slices.SortStableFunc(m.edits, func(x, y edit) int { return cmp.Compare(x.at, y.at) })
	var out bytes.Buffer
	last := 0
	for _, e := range m.edits {
		out.Write(m.base[last:e.at])
		out.Write(e.text)
		last = e.at + e.cut
	}
	out.Write(m.base[last:])
	return out.Bytes()
}

// node is one element of a document that the merge reads: where its bytes
// are, and its children.
type node struct {
	name  string // the local name
	entry string // the name attribute of an entry
	lead  int    // where the space before it starts; its start when there is none
	start int    // its '<'
	open  int    // the end of its start tag
	end   int    // the end of its end tag
	empty bool   // written <name/>
	text  bool   // it holds text other than space
	// children are its child elements, in order.
	children []*node
}

// nodeKey is what matches a template element with a base element.
type nodeKey struct{ name, entry string }

func (n *node) key() nodeKey { return nodeKey{n.name, n.entry} }

// leaf reports whether the element holds text and no child element.
func (n *node) leaf() bool { return n.text && len(n.children) == 0 }

// holds reports whether the element holds a child element of the name.
func (n *node) holds(name string) bool {
	return slices.ContainsFunc(n.children, func(c *node) bool { return c.name == name })
}

// scanElements reads the first element of a document and its subtree, with
// the byte offsets of each element.
func scanElements(b []byte) (*node, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	var open []*node
	space := -1 // where the space token just read starts, or -1
	for {
		off := int(dec.InputOffset())
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("it holds no element")
		}
		if err != nil {
			return nil, err
		}
		next := int(dec.InputOffset())
		lead := space
		space = -1
		switch t := tok.(type) {
		case xml.StartElement:
			n := &node{name: t.Name.Local, lead: off, start: off, open: next}
			if lead >= 0 {
				n.lead = lead
			}
			if n.name == "entry" {
				for _, a := range t.Attr {
					if a.Name.Local == "name" {
						n.entry = a.Value
					}
				}
			}
			if len(open) > 0 {
				p := open[len(open)-1]
				p.children = append(p.children, n)
			}
			open = append(open, n)
		case xml.CharData:
			switch {
			case len(bytes.TrimSpace(t)) == 0:
				space = off
			case len(open) > 0:
				open[len(open)-1].text = true
			}
		case xml.EndElement:
			n := open[len(open)-1]
			open = open[:len(open)-1]
			n.end, n.empty = next, off == next
			if len(open) == 0 {
				return n, nil
			}
		}
	}
}

// holdsElement reports whether the first element of a document holds a child
// element.
func holdsElement(b []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(b))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch tok.(type) {
		case xml.StartElement:
			if depth++; depth == 2 {
				return true
			}
		case xml.EndElement:
			return false
		}
	}
}

// templateStep merges the pushed template into the configuration and names
// where the configuration came from (spec 2026-10-17 §2.1, PD2). It never
// returns an error, so the snapshot is stored in every case.
//
//   - No configuration: there is nothing to merge into, and no source.
//   - No template: the device refused it or it failed, as the documents step
//     says; the device has none (C7); or its config holds no element. The base
//     is the configuration.
//   - A template: the merge is the configuration, and the template's config
//     element is the document template.
//   - A digest that does not load, or a merge that fails: the base stays, the
//     step is partial, and the log names the error, which holds no value.
func templateStep(_ context.Context, s *State) (task.Result, error) {
	tpl, none := s.template()
	base, ok := s.Result.Docs[RunningConfig.Name]
	if !ok {
		return task.Result{Status: task.Skipped, Detail: "no configuration to merge into"}, nil
	}
	source := "running"
	if slices.Contains(s.fellBack, RunningConfig.Name) {
		source = "export"
	}
	s.Result.ConfigSource = source
	if tpl == nil {
		return task.Result{Detail: none}, nil
	}
	load := s.schemaRoot
	if load == nil {
		load = config.SchemaRoot
	}
	root, err := load()
	var merged []byte
	var st MergeStats
	if err == nil {
		merged, st, err = MergeTemplate(base, tpl, root)
	}
	if err != nil {
		s.Log.Warnf(runlog.TagAPI, "%s: template not merged: %v", s.Target.Name, err)
		return task.Result{Status: task.Partial, Detail: "the template was not merged: " + err.Error()}, nil
	}
	s.Result.Docs[RunningConfig.Name] = merged
	s.Result.ConfigSource = source + "+template"
	detail := fmt.Sprintf("%s added, %s kept", plural(st.Added, "template element"), plural(st.KeptLocal, "local element"))
	s.Log.Infof(runlog.TagAPI, "%s: template: %s", s.Target.Name, detail)
	return task.Result{Detail: detail}, nil
}

// template returns the config element of the pushed template, which takes the
// place of the answer, or nil and why there is none. An answer without a
// template is no document: the device has none (C7), or the config holds no
// element, which counts the same (spec 2026-10-17 §2.1).
func (s *State) template() ([]byte, string) {
	b, ok := s.Result.Docs[PushedTemplate.Name]
	if !ok {
		return nil, "no template arrived"
	}
	t, err := unwrapTemplate(b)
	if err == nil && holdsElement(t) {
		s.Result.Docs[PushedTemplate.Name] = t
		return t, ""
	}
	s.drop(PushedTemplate.Name)
	if err != nil {
		// The check of the documents step passed: this is the answer of a
		// device without a template.
		return nil, "no template pushed to the device"
	}
	return nil, "the template holds no element"
}

// drop forgets a document that arrived but holds nothing to keep.
func (s *State) drop(name string) {
	delete(s.Result.Docs, name)
	s.Result.Outcomes = slices.DeleteFunc(s.Result.Outcomes, func(o Outcome) bool { return o.Name == name })
}
