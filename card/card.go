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
	"sort"
	"strings"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/resolve"
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

// builder resolves names in one scope, caching the objects of each kind.
type builder struct {
	cfg    *config.Config
	idx    *index.Index
	sc     config.Scope
	byKind map[string]map[string]resolve.Object
	kinds  map[string][]string // rule field -> the object kinds it may name
}

func newBuilder(cfg *config.Config, idx *index.Index) *builder {
	return &builder{
		cfg: cfg, idx: idx, sc: idx.Scope(),
		byKind: map[string]map[string]resolve.Object{},
		kinds:  cfg.FieldKinds("rulebase/security/rules"),
	}
}

// object returns the object of a kind visible in the scope, by name.
func (b *builder) object(kind, name string) (resolve.Object, bool) {
	m, ok := b.byKind[kind]
	if !ok {
		m = map[string]resolve.Object{}
		objs, _ := resolve.ObjectsInScope(b.cfg, b.sc, kind)
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
func (b *builder) item(field, name string, seen map[string]bool) Item {
	if config.Keywords[name] {
		return Item{Name: name}
	}
	for _, kind := range b.kinds[field] {
		if o, ok := b.object(kind, name); ok {
			return b.objectItem(o, seen)
		}
	}
	if (field == "source" || field == "destination") && len(index.PrefixesOf(name)) > 0 {
		return Item{Name: name, Literal: true}
	}
	return Item{Name: name, Predefined: fieldsWithPredefined[field]}
}

// objectItem is an object with its value and, for a group, its members. seen cuts
// a group cycle; the configuration allows one and the tree must not loop.
func (b *builder) objectItem(o resolve.Object, seen map[string]bool) Item {
	it := Item{Name: o.Name, Kind: o.Kind}
	key := o.Kind + "/" + o.Name
	if seen[key] {
		it.Value = "cycle"
		return it
	}
	seen = with(seen, key)
	switch o.Kind {
	case "address":
		it.Value = addressValue(o.Value)
	case "address-group":
		m, err := resolve.GroupInScope(b.cfg, b.sc, o.Name)
		switch {
		case err != nil:
			it.Value = err.Error()
		case m.Filter != "":
			it.Value = "dynamic, filter " + m.Filter
		default:
			for _, n := range m.Static {
				it.Children = append(it.Children, b.item("source", n, seen))
			}
		}
	case "service":
		it.Value = o.Value
	case "service-group":
		for _, n := range splitList(o.Value) {
			it.Children = append(it.Children, b.item("service", n, seen))
		}
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

func with(seen map[string]bool, key string) map[string]bool {
	out := make(map[string]bool, len(seen)+1)
	for k := range seen {
		out[k] = true
	}
	out[key] = true
	return out
}

func sorted(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
