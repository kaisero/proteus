package config

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Element is one node of a parsed configuration.
//
// The whole file is parsed once, by Load, and every reader works on the result.
// Reading the file per query instead cost 17 parses for a single index build:
// 18.7 ms on a 41 KB configuration, where the size of the file barely mattered.
//
// An Element is read-only once parsed. Nil is a valid receiver for every accessor,
// so a lookup chain does not need a check at each step.
type Element struct {
	Name     string
	Text     string // trimmed character data, empty for a container
	Attrs    []xml.Attr
	Children []*Element
	Parent   *Element
}

// Attr returns an attribute value, or the empty string.
func (e *Element) Attr(name string) string {
	if e == nil {
		return ""
	}
	for _, a := range e.Attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// Child returns the first child with the name, or nil.
func (e *Element) Child(name string) *Element {
	if e == nil {
		return nil
	}
	for _, c := range e.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// ChildrenNamed returns every child with the name, in document order.
func (e *Element) ChildrenNamed(name string) []*Element {
	if e == nil {
		return nil
	}
	var out []*Element
	for _, c := range e.Children {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

// Members returns the text of every member child, which is how PAN-OS writes a
// list of names.
func (e *Element) Members() []string {
	if e == nil {
		return nil
	}
	var out []string
	for _, c := range e.Children {
		if c.Name == "member" {
			out = append(out, c.Text)
		}
	}
	return out
}

// Find follows a fixed path of element names from this element and returns every
// element the path reaches. It matches exactly, so a nested configuration inside a
// template cannot be mistaken for a top-level one.
func (e *Element) Find(path ...string) []*Element {
	cur := []*Element{e}
	if e == nil {
		return nil
	}
	for _, name := range path {
		var next []*Element
		for _, c := range cur {
			next = append(next, c.ChildrenNamed(name)...)
		}
		if len(next) == 0 {
			return nil
		}
		cur = next
	}
	return cur
}

// SchemaPath returns the path with element names only, which is what the schema
// itself uses: an entry stays "entry".
func (e *Element) SchemaPath() string {
	return "/" + strings.Join(e.segments(false), "/")
}

// InstancePath returns the path with each entry replaced by its name, so two
// device groups holding an object of the same name are distinguishable.
func (e *Element) InstancePath() string {
	return "/" + strings.Join(e.segments(true), "/")
}

func (e *Element) segments(named bool) []string {
	if e == nil {
		return nil
	}
	var segs []string
	for cur := e; cur != nil; cur = cur.Parent {
		seg := cur.Name
		if named && cur.Name == "entry" {
			if n := cur.Attr("name"); n != "" {
				seg = n
			}
		}
		segs = append(segs, seg)
	}
	for i, j := 0, len(segs)-1; i < j; i, j = i+1, j-1 {
		segs[i], segs[j] = segs[j], segs[i]
	}
	return segs
}

// parseTree reads a configuration and returns its config element.
//
// A configuration arrives bare, from an export, or wrapped in
// <response><result>, from the XML API. Parsing starts at the first config
// element either way. A nested config element is kept as an ordinary child, so
// it never ends the parse.
func parseTree(r io.Reader) (*Element, error) { return parseTreeAt(r, "config") }

// errNoElement says a well-formed document holds no element of the name asked.
var errNoElement = errors.New("no such element")

// parseTreeAt reads a document and returns the first element of the name, in
// either shape parseTree reads. A well-formed document without one gives an
// error that matches errNoElement.
func parseTreeAt(r io.Reader, rootName string) (*Element, error) {
	dec := xml.NewDecoder(r)
	var root *Element
	var stack []*Element

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}
		switch tv := tok.(type) {
		case xml.StartElement:
			if root == nil && tv.Name.Local != rootName {
				continue
			}
			e := &Element{Name: tv.Name.Local}
			if len(tv.Attr) > 0 {
				e.Attrs = append(e.Attrs, tv.Attr...)
			}
			if root == nil {
				root = e
			} else {
				parent := stack[len(stack)-1]
				e.Parent = parent
				parent.Children = append(parent.Children, e)
			}
			stack = append(stack, e)
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			if t := strings.TrimSpace(string(tv)); t != "" {
				cur := stack[len(stack)-1]
				cur.Text += t
			}
		case xml.EndElement:
			if len(stack) == 0 {
				continue
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return root, nil // the outermost root element closed
			}
		}
	}
	if root == nil {
		return nil, fmt.Errorf("no <%s> element found: %w", rootName, errNoElement)
	}
	return root, nil
}

// TextOr returns the element's text, or the fallback when the element is absent.
func (e *Element) TextOr(fallback string) string {
	if e == nil {
		return fallback
	}
	return e.Text
}
