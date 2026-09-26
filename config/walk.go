package config

import (
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

// Walk yields every reference field in the configuration, scoped. It returns when
// the tree is exhausted or the callback returns false.
//
// The tree is already parsed, so this walks memory rather than the file. Two
// details still matter and are covered by tests. Nested config elements are
// ordinary children — a template embeds a whole firewall configuration, and a
// Panorama file holds several — so nothing here treats one as a boundary. And an
// event's EntryPath names its entries, because two device groups can each hold an
// object of the same name.
func (c *Config) Walk(fn func(Event) bool) error {
	rt := c.schema.refs
	stop := false
	walkElement(c.root, rt, Scope{Sort: ScopeConfig}, fn, &stop)
	return nil
}

func walkElement(e *Element, rt refTable, scope Scope, fn func(Event) bool, stop *bool) {
	if *stop || e == nil {
		return
	}
	if sc, ok := scopeOf(e); ok {
		scope = sc
	}
	if e.Name == "entry" {
		emitRefs(e, rt, scope, fn, stop)
		if *stop {
			return
		}
	}
	for _, c := range e.Children {
		walkElement(c, rt, scope, fn, stop)
		if *stop {
			return
		}
	}
}

// emitRefs yields the reference fields of one entry.
func emitRefs(entry *Element, rt refTable, scope Scope, fn func(Event) bool, stop *bool) {
	array := entry.Parent
	if array == nil {
		return
	}
	byField, known := rt[array.SchemaPath()]
	if !known {
		return
	}
	for _, field := range entry.Children {
		fr, isRef := byField[field.Name]
		if !isRef {
			continue
		}
		var values []string
		for _, v := range field.Members() {
			if v == "" || Keywords[v] {
				continue
			}
			values = append(values, v)
		}
		if len(values) == 0 {
			continue
		}
		if !fn(Event{
			Kind:       EventReference,
			Scope:      scope,
			EntryPath:  entry.InstancePath(),
			SchemaPath: array.SchemaPath(),
			Field:      field.Name,
			Values:     values,
			Candidates: fr.Candidates,
		}) {
			*stop = true
			return
		}
	}
}

// scopeOf reports the scope an element introduces, if it introduces one.
//
// shared is a scope by itself. The others name their scope with the entry
// beneath them, so the scope changes at the entry, not at the container.
func scopeOf(e *Element) (Scope, bool) {
	if e.Name == "shared" {
		return Scope{Sort: ScopeShared}, true
	}
	if e.Name != "entry" || e.Parent == nil {
		return Scope{}, false
	}
	sort, ok := map[string]ScopeSort{
		"vsys":           ScopeVsys,
		"device-group":   ScopeDeviceGroup,
		"template":       ScopeTemplate,
		"template-stack": ScopeTemplateStack,
	}[e.Parent.Name]
	if !ok {
		return Scope{}, false
	}
	return Scope{Sort: sort, Name: e.Attr("name")}, true
}
