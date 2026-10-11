// Package card builds the whole picture of one configuration element for lookup:
// a security rule as the firewall's rule editor shows it, or an object with its
// value, members and the groups holding it. Spec §16.
//
// A card is data, computed to full depth once: every name carries its value, and
// every group its members. How much of it to show — values in parentheses, how
// deep a tree, how long a list — is the renderer's choice, so a script reading the
// card as JSON always gets all of it.
package card

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
)

// KindRule is the kind name of a security rule.
const KindRule = "security-rule"

// Item is one name on a card: an object, a literal value, or a keyword.
type Item struct {
	Name       string `json:"name"`
	Kind       string `json:"kind,omitempty"`
	Value      string `json:"value,omitempty"`   // what --expand shows in parentheses
	Literal    bool   `json:"literal,omitempty"` // a value written into the rule itself
	Predefined bool   `json:"predefined,omitempty"`
	Children   []Item `json:"children,omitempty"`
}

// Row is one labelled line of a section.
type Row struct {
	Label   string `json:"label"`
	Negated bool   `json:"negated,omitempty"`
	Items   []Item `json:"items,omitempty"`
	Text    string `json:"text,omitempty"` // prose, such as "at session end"
}

// Section is one block of a card: source, destination, application.
type Section struct {
	Title string `json:"title"`
	Rows  []Row  `json:"rows"`
}

// Card is one element.
type Card struct {
	Kind        string       `json:"kind"`
	Name        string       `json:"name"`
	Scope       config.Scope `json:"-"`
	Position    int          `json:"position,omitempty"`
	Of          int          `json:"of,omitempty"`
	Layer       string       `json:"layer,omitempty"`
	Disabled    bool         `json:"disabled,omitempty"`
	UUID        string       `json:"uuid,omitempty"`
	Tags        []string     `json:"tags,omitempty"`
	Description string       `json:"description,omitempty"`
	Shadows     string       `json:"shadows,omitempty"`
	Sections    []Section    `json:"sections"`
}

// builder resolves names in one scope, caching the objects of each kind. One
// builder builds one card.
type builder struct {
	cfg    *config.Config
	idx    *index.Index
	sc     config.Scope
	byKind map[string]map[string]resolve.Object
	kinds  map[string][]string // rule field -> the object kinds it may name

	// path holds the groups being opened, from the card's top down, and opened
	// every group the card has opened. depth is each group's shallowest place
	// on the card, where it opens. All key on kind and name.
	path, opened map[string]bool
	depth        map[string]int
}

func newBuilder(cfg *config.Config, idx *index.Index) *builder {
	return &builder{
		cfg: cfg, idx: idx, sc: idx.Scope(),
		byKind: map[string]map[string]resolve.Object{},
		kinds:  cfg.FieldKinds("rulebase/security/rules"),
		path:   map[string]bool{},
		opened: map[string]bool{},
		depth:  map[string]int{},
	}
}

// object returns the object of a kind visible in the scope, by name.
func (b *builder) object(kind, name string) (resolve.Object, bool) {
	if _, ok := b.byKind[kind]; !ok {
		kinds := []string{kind}
		if kind == "service" || kind == "service-group" {
			// A service name resolves by scope first, kind second: a vsys
			// service hides a shared service group of its name, and the other
			// way round (L9).
			kinds = []string{"service", "service-group"}
		}
		for k, objs := range resolve.ObjectsOfKindsInScope(b.cfg, b.sc, kinds...) {
			m := map[string]resolve.Object{}
			for _, o := range objs {
				m[o.Name] = o
			}
			b.byKind[k] = m
		}
	}
	o, ok := b.byKind[kind][name]
	return o, ok
}

// fieldsWithPredefined are the rule fields where a name no object defines is a
// value PAN-OS or its content database defines: a predefined service, a PAN-DB
// category, a region. Applications, zones and users show by name only (K7).
var fieldsWithPredefined = map[string]bool{
	"source": true, "destination": true, "service": true, "category": true,
}

// item resolves one name a rule field holds.
func (b *builder) item(field, name string) Item {
	if config.Keywords[name] {
		return Item{Name: name}
	}
	if o, ok := b.named(field, name); ok {
		return b.objectItem(o)
	}
	if (field == "source" || field == "destination") && len(index.PrefixesOf(name)) > 0 {
		return Item{Name: name, Literal: true}
	}
	return Item{Name: name, Predefined: fieldsWithPredefined[field]}
}

// named is the object a name in a rule field means, of the first of the field's
// kinds that defines it.
func (b *builder) named(field, name string) (resolve.Object, bool) {
	for _, kind := range b.kinds[field] {
		if o, ok := b.object(kind, name); ok {
			return o, true
		}
	}
	return resolve.Object{}, false
}

// memberField is the rule field whose kinds a static group's members are read
// as; empty for a kind whose members are not opened as objects.
func memberField(kind string) string {
	switch kind {
	case "address-group":
		return "source"
	case "service-group":
		return "service"
	}
	return ""
}

// plan finds each group's shallowest place on the card, breadth first from
// the card's top objects, so members opens the group there. A rendered card
// cuts deep levels and long lists; a group opened where the card names it
// first, at the top, keeps its members in view.
func (b *builder) plan(level []resolve.Object) {
	for d := 0; len(level) > 0; d++ {
		var next []resolve.Object
		for _, o := range level {
			key := o.Kind + "/" + o.Name
			field := memberField(o.Kind)
			if _, seen := b.depth[key]; seen || field == "" || o.Dynamic {
				continue
			}
			b.depth[key] = d
			for _, n := range splitList(o.Value) {
				if m, ok := b.named(field, n); ok {
					next = append(next, m)
				}
			}
		}
		level = next
	}
}

// objectItem is an object with its value and, for a group, its members.
func (b *builder) objectItem(o resolve.Object) Item {
	it := Item{Name: o.Name, Kind: o.Kind}
	switch o.Kind {
	case "address":
		it.Value = addressValue(o.Value)
	case "address-group":
		// A dynamic group's value is its tag filter, a static group's its
		// member list. The card shows the filter as written.
		if o.Dynamic {
			if o.Value != "" {
				it.Value = "dynamic, filter " + o.Value
			}
			break
		}
		it.Children, it.Value = b.members(o, memberField(o.Kind))
	case "service":
		it.Value = o.Value
	case "service-group":
		it.Children, it.Value = b.members(o, memberField(o.Kind))
	case "application-group":
		for _, n := range splitList(o.Value) {
			it.Children = append(it.Children, Item{Name: n})
		}
	case "custom-url-category":
		it.Value = urlCategoryValue(o)
	case "external-list":
		it.Value = "external list"
		if o.Subtype != "" {
			it.Value += ", " + o.Subtype
		}
	default:
		it.Value = o.Value
	}
	return it
}

// members opens a group: its members, each resolved as the field names it. A
// card opens each group once, at its shallowest place (plan). A group met
// elsewhere shows no members and says where they are; a group met inside
// itself, which the configuration allows, is a cycle. So a card grows with the
// groups it holds, not with the paths that reach them. Measured on groups that
// each hold three others (BenchmarkObjectCardDenseGroups): opening a group on
// every path took 1.1 s and 1.8 GB for the card of one of 24; opening each once
// takes 10 ms for one of 30.
func (b *builder) members(o resolve.Object, field string) ([]Item, string) {
	key := o.Kind + "/" + o.Name
	d, planned := b.depth[key]
	switch {
	case b.path[key]:
		return nil, "cycle"
	case b.opened[key] || planned && len(b.path) > d:
		return nil, "members shown elsewhere on this card"
	}
	b.path[key], b.opened[key] = true, true
	defer delete(b.path, key)
	var out []Item
	for _, n := range splitList(o.Value) {
		out = append(out, b.item(field, n))
	}
	return out, ""
}

// addressValue names what an address object holds. An ip-netmask and an
// ip-wildcard read as they are, a range as "range a-b", anything else as an FQDN.
func addressValue(v string) string {
	if _, err := netip.ParsePrefix(v); err == nil {
		return v
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	if strings.Contains(v, "-") && len(index.PrefixesOf(v)) > 0 {
		return "range " + v
	}
	if strings.Contains(v, "/") {
		return "wildcard " + v
	}
	return "fqdn " + v
}

func urlCategoryValue(o resolve.Object) string {
	n := len(splitList(o.Value))
	if strings.EqualFold(o.Subtype, "Category Match") {
		return "category match, " + plural(n, "category", "categories")
	}
	return "custom, " + plural(n, "entry", "entries")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

// splitList undoes the ", " join resolve.Object.Value uses for a member list.
func splitList(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ", ")
}

func sorted(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
