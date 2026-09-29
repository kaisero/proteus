package config

import (
	"cmp"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/schema"
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
	Field      string   // source, destination, tag, ... or a path: profile-setting/group/member
	Path       []string // the field's path below the entry, nil from Walk
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
// details still matter and are covered by tests. A nested config element is an
// ordinary child, so nothing here treats one as a boundary. And an event's
// EntryPath names its entries, because two vsys can each hold an object of the
// same name.
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
// shared is a scope by itself. A vsys names its scope with the entry beneath it,
// so the scope changes at the entry, not at the container.
func scopeOf(e *Element) (Scope, bool) {
	if e.Name == "shared" {
		return Scope{Sort: ScopeShared}, true
	}
	if e.Name != "entry" || e.Parent == nil || e.Parent.Name != "vsys" {
		return Scope{}, false
	}
	return Scope{Sort: ScopeVsys, Name: e.Attr("name")}, true
}

// FieldKinds returns the object kinds each reference field may name, for every
// entry array whose schema path ends with suffix.
//
// This comes from the schema, not from the configuration, because a field the
// configuration leaves at "any" yields no walk event: a rulebase whose every rule
// has "source any" would otherwise look as though source names nothing. Kinds from
// several matching arrays are merged, so one call covers every rules array the
// suffix matches.
func (c *Config) FieldKinds(suffix string) map[string][]string {
	out := map[string][]string{}
	seen := map[string]map[string]bool{}
	for path, byField := range c.schema.refs {
		if !strings.HasSuffix(path, suffix) {
			continue
		}
		for field, fr := range byField {
			if seen[field] == nil {
				seen[field] = map[string]bool{}
			}
			for _, k := range fr.Candidates {
				if seen[field][k] {
					continue
				}
				seen[field][k] = true
				out[field] = append(out[field], k)
			}
		}
	}
	for _, ks := range out {
		slices.Sort(ks)
	}
	return out
}

// scopeAnchors are the schema paths a scope's objects hang from.
var scopeAnchors = []string{
	"/config/shared/",
	"/config/devices/entry/vsys/entry/",
}

// KindContainer returns the path from a scope container down to a kind's entry
// array, as element names.
//
// Most kinds sit directly under the scope, so address returns ["address"]. Some do
// not: a custom URL category lives at profiles/custom-url-category, and so does every
// security profile. The path comes from the schema rather than a list kept here, so a
// kind added later needs no code change.
//
// A few kind names appear in more than one place under a scope, and this returns the
// shallowest, which is a guess. "user" is one: the schema has both
// local-user-database/user and a separate user array under a vsys, and they are
// different things. Use KindContainers and choose when the kind might be ambiguous.
//
// It returns nil for a kind the schema does not place under any scope.
func (c *Config) KindContainer(kind string) []string {
	all := c.KindContainers(kind)
	if len(all) == 0 {
		return nil
	}
	return all[0]
}

// KindContainers returns every path under a scope at which a kind's entry array
// appears, shallowest first and then alphabetically. kind is one name, such as
// "address" or "custom-url-category".
//
// More than one means the name is ambiguous and the caller has to choose. Returning
// only the first would be a silent wrong answer, which is exactly what it was before
// this existed: asking for "user" gave a vsys-level user array rather than the local
// user database, and the difference is not visible in the result.
func (c *Config) KindContainers(kind string) [][]string {
	paths := c.schema.kinds[kind]
	if len(paths) == 0 {
		return nil
	}
	out := make([][]string, len(paths))
	for i, p := range paths {
		out[i] = slices.Clone(p) // the table is shared by every Config of this schema
	}
	return out
}

// kindTable maps a kind to the paths under a scope at which its entry array
// appears, shallowest first and then alphabetically. It depends only on the
// schema, so it is built once with it. Building the paths on every call made each
// search rebuild the path of every entry array in the schema.
type kindTable map[string][][]string

func buildKindTable(root *schema.Node) kindTable {
	out := kindTable{}
	seen := map[string]bool{}
	for _, arr := range schema.EntryTypes(root) {
		path := arr.Path()
		kind := path[strings.LastIndex(path, "/")+1:]
		for _, anchor := range scopeAnchors {
			rest, ok := cutPrefix(path, anchor)
			if !ok || strings.Contains(rest, "/entry/") {
				// Anything with a further entry level is nested inside another
				// object, not a kind the scope holds directly.
				continue
			}
			if seen[kind+" "+rest] {
				continue
			}
			seen[kind+" "+rest] = true
			out[kind] = append(out[kind], strings.Split(rest, "/"))
		}
	}
	for _, paths := range out {
		slices.SortFunc(paths, func(a, b []string) int {
			return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(strings.Join(a, "/"), strings.Join(b, "/")))
		})
	}
	return out
}

func cutPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	return s[len(prefix):], true
}
