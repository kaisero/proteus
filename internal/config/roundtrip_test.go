package config

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// R3. The tree holds everything the file holds: written back, it gives the same
// elements, attributes and text, in the same order, as the file it came from,
// and parsed again it gives the same tree. Every configuration fixture is
// checked, so a shape the parser drops shows here.
func TestRoundTripLosesNothing(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("../../testdata/config/*.xml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tree, err := parseTree(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			out := writeTree(tree)

			want, got := xmlEvents(t, raw), xmlEvents(t, out)
			if !slices.Equal(got, want) {
				i := 0
				for i < min(len(got), len(want)) && got[i] == want[i] {
					i++
				}
				t.Fatalf("written tree differs from the file at event %d of %d: got %q, want %q",
					i, len(want), at(got, i), at(want, i))
			}

			again, err := parseTree(bytes.NewReader(out))
			if err != nil {
				t.Fatalf("parse the written tree: %v", err)
			}
			if p := treeDiff(tree, again); p != "" {
				t.Errorf("the tree parsed again differs at %s", p)
			}
		})
	}
}

// The test helpers below check themselves: a dropped attribute, a changed text,
// a missing or reordered child each show as a difference.
func TestRoundTripHelpersSeeALoss(t *testing.T) {
	t.Parallel()
	const doc = `<config version="11.2.0"><shared><address>` +
		`<entry name="a"><ip-netmask>10.88.0.1</ip-netmask></entry>` +
		`<entry name="b"><fqdn>fw01</fqdn></entry></address></shared></config>`
	base := func() *Element {
		e, err := parseTree(strings.NewReader(doc))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	entries := func(e *Element) []*Element { return e.Find("shared", "address", "entry") }
	cases := map[string]func(e *Element){
		"attribute": func(e *Element) { entries(e)[0].Attrs = nil },
		"text":      func(e *Element) { entries(e)[0].Children[0].Text = "10.88.0.2" },
		"child":     func(e *Element) { a := entries(e)[0].Parent; a.Children = a.Children[:1] },
		"order": func(e *Element) {
			a := entries(e)[0].Parent
			a.Children[0], a.Children[1] = a.Children[1], a.Children[0]
		},
		"name": func(e *Element) { entries(e)[1].Children[0].Name = "ip-netmask" },
	}
	for name, mutate := range cases {
		e := base()
		mutate(e)
		if treeDiff(base(), e) == "" {
			t.Errorf("%s: treeDiff saw no difference", name)
		}
		if slices.Equal(xmlEvents(t, []byte(doc)), xmlEvents(t, writeTree(e))) {
			t.Errorf("%s: the written tree read as the file", name)
		}
	}
	if !slices.Equal(xmlEvents(t, []byte(doc)), xmlEvents(t, writeTree(base()))) {
		t.Error("an untouched tree must write back as the file")
	}
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "(end)"
}

// writeTree writes an element tree back as XML. It returns bytes and writes to
// no device: the package's API stays read-only (AGENTS.md R2).
func writeTree(root *Element) []byte {
	var b bytes.Buffer
	var write func(e *Element)
	write = func(e *Element) {
		b.WriteString("<" + e.Name)
		for _, a := range e.Attrs {
			b.WriteString(" " + attrName(a.Name) + `="`)
			_ = xml.EscapeText(&b, []byte(a.Value))
			b.WriteString(`"`)
		}
		b.WriteString(">")
		_ = xml.EscapeText(&b, []byte(e.Text))
		for _, c := range e.Children {
			write(c)
		}
		b.WriteString("</" + e.Name + ">")
	}
	write(root)
	return b.Bytes()
}

func attrName(n xml.Name) string {
	if n.Space != "" {
		return n.Space + ":" + n.Local
	}
	return n.Local
}

// xmlEvents reads a document from its first config element to its close as a
// list of events: each start with its attributes, and at each end the
// element's text, trimmed and joined as parseTree joins it. Whitespace between
// elements and comments carry no configuration.
func xmlEvents(t *testing.T, doc []byte) []string {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(doc))
	var out []string
	var texts []string
	depth := 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch tv := tok.(type) {
		case xml.StartElement:
			if depth == 0 && tv.Name.Local != "config" {
				continue
			}
			ev := "start " + tv.Name.Local
			for _, a := range tv.Attr {
				ev += " " + attrName(a.Name) + "=" + a.Value
			}
			out = append(out, ev)
			texts = append(texts, "")
			depth++
		case xml.CharData:
			if depth > 0 {
				texts[depth-1] += strings.TrimSpace(string(tv))
			}
		case xml.EndElement:
			if depth == 0 {
				continue
			}
			depth--
			out = append(out, "text "+texts[depth], "end "+tv.Name.Local)
			texts = texts[:depth]
			if depth == 0 {
				return out
			}
		}
	}
	return out
}

// treeDiff returns the instance path of the first place two trees differ in
// name, attributes, text or children, or "" when they are the same.
func treeDiff(a, b *Element) string {
	if a.Name != b.Name || a.Text != b.Text || !slices.Equal(a.Attrs, b.Attrs) ||
		len(a.Children) != len(b.Children) {
		return a.InstancePath()
	}
	for i := range a.Children {
		if p := treeDiff(a.Children[i], b.Children[i]); p != "" {
			return p
		}
		if b.Children[i].Parent != b {
			return b.Children[i].InstancePath() + " (parent)"
		}
	}
	return ""
}
