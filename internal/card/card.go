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
	// every group the card has opened. Both key on kind and name.
	path, opened map[string]bool
}

func newBuilder(cfg *config.Config, idx *index.Index) *builder {
	return &builder{
		cfg: cfg, idx: idx, sc: idx.Scope(),
		byKind: map[string]map[string]resolve.Object{},
		kinds:  cfg.FieldKinds("rulebase/security/rules"),
		path:   map[string]bool{},
		opened: map[string]bool{},
	}
}

// object returns the object of a kind visible in the scope, by name.
func (b *builder) object(kind, name string) (resolve.Object, bool) {
	m, ok := b.byKind[kind]
	if !ok {
		m = map[string]resolve.Object{}
		objs := resolve.ObjectsInScope(b.cfg, b.sc, kind)
		for _, o := range objs {
			m[o.Name] = o
		}
		b.byKind[kind] = m
	}
	o, ok := m[name]
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
	for _, kind := range b.kinds[field] {
		if o, ok := b.object(kind, name); ok {
			return b.objectItem(o)
		}
	}
	if (field == "source" || field == "destination") && len(index.PrefixesOf(name)) > 0 {
		return Item{Name: name, Literal: true}
	}
	return Item{Name: name, Predefined: fieldsWithPredefined[field]}
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
		it.Children, it.Value = b.members(o, "source")
	case "service":
		it.Value = o.Value
	case "service-group":
		it.Children, it.Value = b.members(o, "service")
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
// card opens each group once. A group met again shows no members and says they
// are shown above; a group met inside itself, which the configuration allows,
// is a cycle. So a card grows with the groups it holds, not with the paths that
// reach them. Measured on groups that each hold three others
// (BenchmarkObjectCardDenseGroups): opening a group on every path took 1.1 s
// and 1.8 GB for the card of one of 24; opening each once takes 9 ms for one
// of 30.
func (b *builder) members(o resolve.Object, field string) ([]Item, string) {
	key := o.Kind + "/" + o.Name
	switch {
	case b.path[key]:
		return nil, "cycle"
	case b.opened[key]:
		return nil, "members shown above"
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
