package config

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/okaiser/go-panos-schema/internal/schema"
)

// Keywords are values that appear in reference fields but name no object. They
// must never become index edges.
//
// The list is explicit rather than read from the schema's enum values, because a
// field can accept any without declaring it.
var Keywords = map[string]bool{
	"any":                 true,
	"application-default": true,
	"none":                true,
}

// EventKind is what a walk event describes.
type EventKind int

// The kinds of event a walk yields.
const (
	EventReference EventKind = iota // a field naming other objects
)

// Event is one thing the walk found.
type Event struct {
	Kind       EventKind
	Scope      Scope
	EntryPath  string   // instance path, with entry names
	SchemaPath string   // the schema path of the containing array
	Field      string   // source, destination, tag, ...
	Values     []string // the members, keywords already removed
	Candidates []string // the object kinds the schema allows for this field
}

// refTable is the schema side table: for an entry-array path, which fields are
// references and what they may name.
type refTable map[string]map[string]schema.FieldRefs

func buildRefTable(root *schema.Node) refTable {
	rt := refTable{}
	for _, arr := range schema.EntryTypes(root) {
		refs := schema.References(arr.EntrySequence())
		if len(refs) == 0 {
			continue
		}
		byField := make(map[string]schema.FieldRefs, len(refs))
		for _, fr := range refs {
			byField[fr.Field] = fr
		}
		rt[arr.Path()] = byField
	}
	return rt
}

// Walk reads the configuration file once and yields every reference field it
// finds, scoped. It returns when the file ends or the callback returns false.
//
// Two constraints, both established by prototype:
//
// It never consumes an element wholesale. Decoding an entry with DecodeElement
// swallows the entries nested inside it, and a device group contains a rulebase
// which contains rules. A consuming walk found 1 edge on the lab configuration
// where this one finds 24.
//
// Paths are anchored at <config>, because a configuration arrives bare or
// wrapped in <response><result>.
func (c *Config) Walk(fn func(Event) bool) error {
	f, err := os.Open(c.path)
	if err != nil {
		return fmt.Errorf("config: open %s: %w", c.path, err)
	}
	defer func() { _ = f.Close() }()

	rt := buildRefTable(c.root)
	dec := xml.NewDecoder(f)

	var elems []string   // element names, anchored at config
	var entries []string // the name attribute of each open entry, innermost last
	var scopes []Scope   // the scope in force at each open entry
	inConfig := false
	var pending *Event // the reference field currently open

	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			return nil
		}
		if terr != nil {
			return fmt.Errorf("config: read %s: %w", c.path, terr)
		}
		switch tv := tok.(type) {
		case xml.StartElement:
			if !inConfig {
				if tv.Name.Local != "config" {
					continue
				}
				inConfig = true
			}
			elems = append(elems, tv.Name.Local)

			if tv.Name.Local == "entry" {
				entries = append(entries, attr(tv, "name"))
				scopes = append(scopes, scopeAt(elems, entries))
				continue
			}

			// A reference field opens when the enclosing array path is known.
			if len(elems) >= 3 && elems[len(elems)-2] == "entry" {
				arrayPath := "/" + strings.Join(elems[:len(elems)-2], "/")
				if byField, known := rt[arrayPath]; known {
					if fr, isRef := byField[tv.Name.Local]; isRef {
						pending = &Event{
							Kind:       EventReference,
							Scope:      currentScope(scopes),
							EntryPath:  instancePath(elems[:len(elems)-1], entries),
							SchemaPath: arrayPath,
							Field:      tv.Name.Local,
							Candidates: fr.Candidates,
						}
					}
				}
			}

		case xml.CharData:
			if pending == nil || len(elems) == 0 || elems[len(elems)-1] != "member" {
				continue
			}
			v := strings.TrimSpace(string(tv))
			if v == "" || Keywords[v] {
				continue
			}
			pending.Values = append(pending.Values, v)

		case xml.EndElement:
			if !inConfig || len(elems) == 0 {
				continue
			}
			closing := elems[len(elems)-1]
			if pending != nil && closing == pending.Field {
				if len(pending.Values) > 0 && !fn(*pending) {
					return nil
				}
				pending = nil
			}
			if closing == "entry" && len(entries) > 0 {
				entries = entries[:len(entries)-1]
				scopes = scopes[:len(scopes)-1]
			}
			elems = elems[:len(elems)-1]
			// Stop only when the OUTERMOST config closes. A Panorama
			// configuration holds several nested <config> elements: a template
			// embeds a whole firewall configuration, and an admin role's webui
			// permissions have one too. Stopping at the first of those ends the
			// walk after a handful of elements.
			if len(elems) == 0 {
				return nil
			}
		}
	}
}

func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// instancePath builds a path that identifies the instance, replacing each entry
// segment with that entry's name.
func instancePath(elems, entries []string) string {
	var sb strings.Builder
	used := 0
	for _, e := range elems {
		if e == "entry" {
			if used < len(entries) {
				sb.WriteString("/")
				sb.WriteString(entries[used])
				used++
			}
			continue
		}
		sb.WriteString("/")
		sb.WriteString(e)
	}
	return sb.String()
}

// scopeAt names the scope the innermost open entry sits in.
func scopeAt(elems, entries []string) Scope {
	for i := len(elems) - 1; i >= 0; i-- {
		switch elems[i] {
		case "shared":
			return Scope{Sort: ScopeShared}
		case "vsys":
			return Scope{Sort: ScopeVsys, Name: entryAfter(elems, entries, i)}
		case "device-group":
			return Scope{Sort: ScopeDeviceGroup, Name: entryAfter(elems, entries, i)}
		case "template":
			return Scope{Sort: ScopeTemplate, Name: entryAfter(elems, entries, i)}
		case "template-stack":
			return Scope{Sort: ScopeTemplateStack, Name: entryAfter(elems, entries, i)}
		}
	}
	return Scope{Sort: ScopeConfig}
}

// entryAfter returns the entry name that follows elems[i], which is the scope's
// own name.
func entryAfter(elems, entries []string, i int) string {
	depth := 0
	for j := 0; j <= i; j++ {
		if elems[j] == "entry" {
			depth++
		}
	}
	if depth < len(entries) {
		return entries[depth]
	}
	return ""
}

func currentScope(scopes []Scope) Scope {
	if len(scopes) == 0 {
		return Scope{Sort: ScopeConfig}
	}
	return scopes[len(scopes)-1]
}
