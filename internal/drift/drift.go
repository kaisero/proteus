// Package drift compares two configurations of one scope: which objects and rules
// were added, removed or changed between two snapshots. It answers "what changed
// since Tuesday" in the schema's terms rather than as an XML diff. Spec §15 C9.
package drift

import (
	"cmp"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/schema"
)

// Op is what happened to one object or rule.
type Op string

// The operations a change can be.
const (
	Added   Op = "added"
	Removed Op = "removed"
	Changed Op = "changed"
)

// Change is one object or rule that differs.
//
// An added or removed entry carries a short line in New or Old. A changed entry
// carries Fields instead: each setting that differs, old and new.
type Change struct {
	Op     Op            `json:"op" jsonschema:"added, removed or changed"`
	Kind   string        `json:"kind" jsonschema:"the object's container name, such as address or zone, or the rulebase and rule, such as security rule"`
	Name   string        `json:"name" jsonschema:"the object's or rule's name"`
	Old    string        `json:"old,omitempty" jsonschema:"a removed entry in one line"`
	New    string        `json:"new,omitempty" jsonschema:"an added entry in one line"`
	Fields []FieldChange `json:"fields,omitempty" jsonschema:"the settings of a changed entry that differ"`
}

// FieldChange is one setting of a changed entry. A setting present on one side
// only has an empty other side.
type FieldChange struct {
	Path string `json:"path" jsonschema:"the setting's path below the entry, such as negate-destination or destination-translation/translated-address; an attribute's last segment starts with @"`
	Old  string `json:"old" jsonschema:"the value before: empty when the setting was absent, (set) for an element present without a value; a member list's members are sorted"`
	New  string `json:"new" jsonschema:"the value after: empty when the setting is absent, (set) for an element present without a value; a member list's members are sorted"`
	// Secret marks a setting whose value is never shown: Old and New read
	// (secret) where it is present.
	Secret bool `json:"secret,omitempty" jsonschema:"true for a key, password or other secret: its values read (secret) and are never shown"`
	// Undescribed marks a setting the schema digest does not describe: an
	// element or attribute it does not know, such as one from a newer PAN-OS
	// release. It is compared, but Old and New stay empty, because nothing
	// says whether it holds a secret.
	Undescribed bool `json:"undescribed,omitempty" jsonschema:"true for a setting the schema does not describe: it changed, but its values are never shown, as it may hold a secret"`
}

// Set is the value of an element that is present but holds nothing, such as
// a choice like <type><ssl-forward-proxy/></type>. It differs from an absent
// element, whose value is empty.
const Set = "(set)"

// Hidden stands in for the value of a secret: a setting the schema marks
// encrypt="yes", or a hand-modelled one such as a password hash
// (schema.IsSecret). A secret is compared, but its value is never shown.
const Hidden = "(secret)"

// NotShown stands in for a value the schema does not describe, in an added or
// removed entry's short line.
const NotShown = "(not shown)"

// OrderSuffix ends the path of a nested entry list's order field: server
// order is the order of a server profile's servers.
const OrderSuffix = " order"

// ignoredAttrs are the attributes PAN-OS writes for its own bookkeeping. They
// say which element it is or who changed it and when, not what it does, so a
// change in them alone is not a change.
//
// uuid: as observed on fw01 (PAN-OS 11.2.5, 2026-10-08), rule entries carry a
// uuid attribute. admin, time and dirtyId name the administrator and the time
// of an uncommitted change; they are ignored when they occur (owner decision
// for snapshot diff, 2026-10-10; not yet seen on a lab device).
var ignoredAttrs = map[string]bool{
	"uuid":    true,
	"admin":   true,
	"time":    true,
	"dirtyId": true,
}

// pushedRulebases are the shared containers of rules pushed from Panorama. The
// firewall schema does not declare them; they hold the shape of a vsys rulebase
// (PAN-OS documentation, "Device Group Policies"), and they are read with its
// schema node, as resolve reads their rules. Both are registered in
// schema.HandModelled (AGENTS.md R8).
var pushedRulebases = map[string]bool{"pre-rulebase": true, "post-rulebase": true}

// Compare returns what differs between two configurations in one scope, sorted by
// kind and name.
//
// Every entry the scope defines counts: each object of every kind, profiles,
// zones and schedules included, and each rule of every rulebase. The lists come
// from walking the scope with the schema digest, not from a list kept here. Only
// definitions in the scope itself count, so a vsys comparison does not repeat
// every shared change; compare shared for those. The device's predefined
// services are not configuration and are not compared.
//
// A rule's position is not compared: one inserted rule would otherwise mark
// every rule below it as changed.
func Compare(before, after *config.Config, sc config.Scope) []Change {
	a, b := entries(before, sc), entries(after, sc)
	type keyed struct {
		k key
		c Change
	}
	var all []keyed
	for k, old := range a {
		nu, ok := b[k]
		switch {
		case !ok:
			all = append(all, keyed{k, Change{Op: Removed, Kind: k.kind, Name: k.name, Old: old.line}})
		default:
			if fs := diffFields(old.form, nu.form); len(fs) > 0 {
				all = append(all, keyed{k, Change{Op: Changed, Kind: k.kind, Name: k.name, Fields: fs}})
			}
		}
	}
	for k, nu := range b {
		if _, ok := a[k]; !ok {
			all = append(all, keyed{k, Change{Op: Added, Kind: k.kind, Name: k.name, New: nu.line}})
		}
	}
	// The container breaks a tie of kind and name, such as a pushed pre-rule
	// and post-rule of one name, so the order does not depend on map order.
	slices.SortFunc(all, func(x, y keyed) int {
		return cmp.Or(cmp.Compare(x.k.kind, y.k.kind), cmp.Compare(x.k.name, y.k.name),
			cmp.Compare(x.k.container, y.k.container), cmp.Compare(x.c.Op, y.c.Op))
	})
	var out []Change
	for _, kc := range all {
		out = append(out, kc.c)
	}
	return out
}

// key names one entry of a scope. The container path keeps apart two lists
// whose kind has the same name, such as local-user-database/user and user.
type key struct{ container, kind, name string }

// entry is one entry's canonical form and its short line.
type entry struct {
	form form
	line string
}

// entries reads every entry the scope defines.
func entries(cfg *config.Config, sc config.Scope) map[key]entry {
	out := map[key]entry{}
	lines := objectLines(cfg, sc)
	for _, el := range scopeElements(cfg, sc) {
		w := walker{cfg: cfg, sc: sc, out: out, lines: lines}
		w.container(el, schemaNode(cfg.Digest(), el), nil)
	}
	return out
}

// scopeElements returns the elements that hold a scope's definitions.
func scopeElements(cfg *config.Config, sc config.Scope) []*config.Element {
	switch sc.Sort {
	case config.ScopeShared:
		return cfg.Root().Find("shared")
	case config.ScopeVsys:
		var out []*config.Element
		for _, v := range cfg.Root().Find("devices", "entry", "vsys", "entry") {
			if v.Attr("name") == sc.Name {
				out = append(out, v)
			}
		}
		return out
	}
	return nil
}

// schemaNode finds an element's node in the digest, following its path from
// the root; nil when the digest does not describe it.
func schemaNode(root *schema.Node, el *config.Element) *schema.Node {
	var chain []*config.Element
	for cur := el; cur != nil; cur = cur.Parent {
		chain = append(chain, cur)
	}
	n := root // the configuration's root element, config
	for i := len(chain) - 2; i >= 0 && n != nil; i-- {
		n = step(n, chain[i].Name)
	}
	return n
}

// step returns the node of a child element: an entry of an entry list, or a
// named field. Anonymous choices and unions are pure grammar and are passed
// through; a named one is an element of its own (schema.PathFields).
func step(n *schema.Node, name string) *schema.Node {
	if n == nil {
		return nil
	}
	if n.Kind == schema.KindArray {
		if name == "entry" {
			return n.EntrySequence()
		}
		return nil
	}
	for _, c := range schema.PathFields(n) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// walker finds the entry lists under one scope element.
type walker struct {
	cfg   *config.Config
	sc    config.Scope
	out   map[key]entry
	lines map[key]string
}

// container descends an element that is not an entry, looking for entry lists.
// An entry list's entries are compared whole, so the descent stops there. An
// element the digest does not describe is compared whole as one entry named by
// its path, so a change in it is not lost.
func (w walker) container(el *config.Element, n *schema.Node, path []string) {
	for _, c := range el.Children {
		cn := step(n, c.Name)
		if cn == nil && len(path) == 0 && w.sc.Sort == config.ScopeShared && pushedRulebases[c.Name] {
			cn = w.rulebaseNode()
		}
		cpath := append(slices.Clone(path), c.Name)
		switch {
		case cn == nil:
			w.add(strings.Join(cpath, "/"), strings.Join(cpath, "/"), "", c, nil)
		case cn.IsEntryList():
			kind := c.Name
			if c.Name == "rules" && c.Parent.Parent != nil && strings.HasSuffix(c.Parent.Parent.Name, "rulebase") {
				kind = c.Parent.Name + " rule"
			}
			seq := cn.EntrySequence()
			for _, e := range c.ChildrenNamed("entry") {
				w.add(strings.Join(cpath, "/"), kind, e.Attr("name"), e, seq)
			}
		case cn.Kind == schema.KindArray || cn.Kind == schema.KindElement:
			// A setting of the scope, not an entry.
		default:
			w.container(c, cn, cpath)
		}
	}
}

// rulebaseNode is the schema node of a vsys rulebase.
func (w walker) rulebaseNode() *schema.Node {
	n := w.cfg.Digest()
	for _, seg := range []string{"devices", "entry", "vsys", "entry", "rulebase"} {
		n = step(n, seg)
	}
	return n
}

func (w walker) add(container, kind, name string, el *config.Element, n *schema.Node) {
	k := key{container, kind, name}
	line, ok := w.lines[k]
	if !ok && strings.HasSuffix(kind, " rule") {
		line = ruleLine(el, n)
	}
	f := canonical(el, n)
	w.out[k] = entry{form: f, line: redact(line, f)}
}

// redact hides any value of the entry that must not show and that its short
// line holds: a secret, or a value the schema does not describe. The short
// lines read described fields only, so this is a second guard.
//
// A value is replaced only where it stands as a whole token of the line,
// bounded by the line's ends, a space, a comma or an equals sign, which is how
// a short line joins the values it shows. A plain substring replace would
// also hit a short value inside an unrelated one, such as 1 in 10.88.0.1.
func redact(line string, f form) string {
	for _, p := range f.paths {
		h := f.hidden[p]
		if h == visible {
			continue
		}
		mark := Hidden
		if h == undescribed {
			mark = NotShown
		}
		line = replaceToken(line, f.values[p], mark)
	}
	return line
}

// isBoundary reports whether a byte ends a token of a short line.
func isBoundary(b byte) bool { return b == ' ' || b == ',' || b == '=' }

// replaceToken replaces each whole-token occurrence of v in line.
func replaceToken(line, v, mark string) string {
	if v == "" {
		return line
	}
	var b strings.Builder
	for i := 0; i < len(line); {
		j := strings.Index(line[i:], v)
		if j < 0 {
			b.WriteString(line[i:])
			break
		}
		start, end := i+j, i+j+len(v)
		whole := (start == 0 || isBoundary(line[start-1])) && (end == len(line) || isBoundary(line[end]))
		if whole {
			b.WriteString(line[i:start])
			b.WriteString(mark)
			i = end
			continue
		}
		b.WriteString(line[i : start+1])
		i = start + 1
	}
	return b.String()
}

// objectLines is each object's short line, as resolve reads it: its value and
// its tags, keyed as the walk keys the entry.
func objectLines(cfg *config.Config, sc config.Scope) map[key]string {
	out := map[key]string{}
	for _, kind := range resolve.ObjectKinds(cfg) {
		container := strings.Join(cfg.KindContainer(kind), "/")
		for _, o := range resolve.ObjectsInScope(cfg, sc, kind) {
			if o.Scope != sc {
				continue
			}
			line := o.Value
			if len(o.Tags) > 0 {
				line += " tags=" + strings.Join(o.Tags, ",")
			}
			out[key{container, kind, o.Name}] = line
		}
	}
	return out
}

// ruleLine is a rule's short line: its action, whether it is disabled, and its
// member lists.
func ruleLine(el *config.Element, n *schema.Node) string {
	var fields []string
	for _, c := range el.Children {
		if !step(n, c.Name).IsMemberList() {
			continue
		}
		if m := c.Members(); len(m) > 0 {
			fields = append(fields, c.Name+"="+strings.Join(m, ","))
		}
	}
	slices.Sort(fields)
	s := ""
	if step(n, "action") != nil {
		s = el.Child("action").TextOr("")
	}
	if step(n, "disabled") != nil && el.Child("disabled").TextOr("") == "yes" {
		s += " disabled"
	}
	return strings.TrimSpace(s + " " + strings.Join(fields, " "))
}

// form is an entry's canonical form: each setting's path and value, in
// document order.
type form struct {
	paths  []string
	values map[string]string
	hidden map[string]hiding   // paths whose value is never shown, and why
	orders map[string][]string // an order path's entry names, in document order
}

// hiding says why a value is never shown.
type hiding int

const (
	visible     hiding = iota
	secret             // schema.IsSecret
	undescribed        // the digest does not describe it
)

func (f *form) put(path, value string, h hiding) {
	if f.values == nil {
		f.values = map[string]string{}
		f.hidden = map[string]hiding{}
	}
	if h != visible {
		f.hidden[path] = max(f.hidden[path], h)
	}
	if prev, ok := f.values[path]; ok {
		// Repeated siblings the digest does not describe: kept in document
		// order, so a reorder shows rather than hides.
		f.values[path] = prev + ", " + value
		return
	}
	f.paths = append(f.paths, path)
	f.values[path] = value
}

// putOrder records the order of a nested entry list's entries.
func (f *form) putOrder(path string, names []string, h hiding) {
	if f.orders == nil {
		f.orders = map[string][]string{}
	}
	p := strings.TrimSpace(path + OrderSuffix) // "order" for a list at the top
	f.orders[p] = names
	f.put(p, strings.Join(names, ", "), h)
}

// canonical reduces an entry to its form. A member list (the digest says
// which, AGENTS.md R4) is one value, its members sorted, so a reorder is no
// change. A nested entry is named by its name, as an instance path is, and
// its list's order is one more setting: the order of a server profile's
// servers is configuration. A secret is compared but marked, and so is a
// value the digest does not describe: an element it does not know, or an
// attribute it does not declare.
func canonical(el *config.Element, n *schema.Node) form {
	var f form
	var walk func(el *config.Element, n *schema.Node, path string)
	walk = func(el *config.Element, n *schema.Node, path string) {
		h := visible
		if n == nil {
			h = undescribed
		}
		if n != nil && n.IsMemberList() {
			if m, plain := members(el); m != "" {
				if !plain {
					h = undescribed
				}
				f.put(path, m, h)
			}
			return
		}
		if schema.IsSecret(n) {
			f.put(path, cmp.Or(el.Text, Set), secret)
			return
		}
		isEntry := el.Name == "entry" && (n != nil && n.Parent != nil && n.Parent.Kind == schema.KindArray || n == nil && el.Attr("name") != "")
		for _, a := range el.Attrs {
			if ignoredAttrs[a.Name.Local] || isEntry && a.Name.Local == "name" {
				continue
			}
			ah := undescribed
			if declaresAttr(n, a.Name.Local) {
				ah = visible
			}
			f.put(join(path, "@"+a.Name.Local), a.Value, ah)
		}
		if path != "" && (el.Text != "" || len(el.Children) == 0) {
			f.put(path, cmp.Or(el.Text, Set), h)
		}
		var names []string
		for _, c := range el.Children {
			seg := c.Name
			if c.Name == "entry" && c.Attr("name") != "" && (n == nil || n.Kind == schema.KindArray) {
				seg = c.Attr("name")
				names = append(names, seg)
			}
			walk(c, step(n, c.Name), join(path, seg))
		}
		if len(names) > 1 {
			f.putOrder(path, names, h)
		}
	}
	walk(el, n, "")
	return f
}

// declaresAttr reports whether the schema declares an attribute of the node.
func declaresAttr(n *schema.Node, name string) bool {
	for _, c := range schema.PathFields(n) {
		if c.Kind == schema.KindAttrReq && c.Name == name {
			return true
		}
	}
	return false
}

// members is a member list's value: its members sorted and once each. A
// member's own attributes, other than bookkeeping, stay with it; the schema
// declares none, so plain is false when one has any.
func members(el *config.Element) (value string, plain bool) {
	var out []string
	plain = true
	for _, c := range el.ChildrenNamed("member") {
		v := c.Text
		for _, a := range c.Attrs {
			if !ignoredAttrs[a.Name.Local] {
				v += " [" + a.Name.Local + "=" + a.Value + "]"
				plain = false
			}
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), ", "), plain
}

func join(path, seg string) string {
	if path == "" {
		return seg
	}
	return path + "/" + seg
}

// diffFields lists the settings that differ: those of the old form in its
// order, then those only the new form has, in its order.
//
// A secret's values are replaced by Hidden where present; a value the digest
// does not describe is left empty on both sides. A nested list's order counts
// only for the entries both sides hold, so an added or removed entry shows as
// itself, not as a reorder too.
func diffFields(old, nu form) []FieldChange {
	var out []FieldChange
	field := func(p string) FieldChange {
		fc := FieldChange{Path: p, Old: old.values[p], New: nu.values[p]}
		switch max(old.hidden[p], nu.hidden[p]) {
		case secret:
			fc.Secret = true
			fc.Old, fc.New = hide(old, p), hide(nu, p)
		case undescribed:
			fc.Undescribed = true
			fc.Old, fc.New = "", ""
		}
		return fc
	}
	for _, p := range old.paths {
		if names, ok := old.orders[p]; ok {
			if !sameOrder(names, nu.orders[p]) {
				out = append(out, field(p))
			}
			continue
		}
		if o, n := old.values[p], nu.values[p]; o != n {
			out = append(out, field(p))
		}
	}
	for _, p := range nu.paths {
		if _, ok := old.values[p]; !ok && nu.orders[p] == nil {
			out = append(out, field(p))
		}
	}
	return out
}

// sameOrder reports whether the names both lists hold come in the same order.
func sameOrder(a, b []string) bool {
	return slices.Equal(common(a, b), common(b, a))
}

// common keeps the names of a that b also holds, in a's order.
func common(a, b []string) []string {
	var out []string
	for _, n := range a {
		if slices.Contains(b, n) {
			out = append(out, n)
		}
	}
	return out
}

// hide is a secret's shown value: Hidden where the form holds it, else empty.
func hide(f form, path string) string {
	if _, ok := f.values[path]; ok {
		return Hidden
	}
	return ""
}
