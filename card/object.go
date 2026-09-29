package card

import (
	"fmt"
	"slices"
	"sort"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/resolve"
)

// Object builds the card of one object: its value, its members, the profiles a
// profile group holds, and the groups holding it directly. Where the object is used
// is search's answer, not the card's.
func Object(cfg *config.Config, idx *index.Index, o resolve.Object) Card {
	b := newBuilder(cfg, idx)
	c := Card{Kind: o.Kind, Name: o.Name, Scope: o.Scope, Tags: o.Tags, Description: o.Description}
	if o.ShadowedFrom != nil {
		c.Shadows = o.ShadowedFrom.String()
	}
	it := b.objectItem(o, nil)
	switch {
	case o.Kind == "profile-group":
		groups, _ := resolve.ProfileGroupsInScope(cfg, b.sc)
		for _, g := range groups {
			if g.Name == o.Name {
				c.Sections = append(c.Sections, Section{Title: "profiles", Rows: []Row{{Items: profileItems(g.Kinds)}}})
			}
		}
	case o.Kind == "custom-url-category":
		var entries []Item
		for _, e := range splitList(o.Value) {
			entries = append(entries, Item{Name: e})
		}
		kind := o.Subtype
		if kind == "" {
			kind = "URL List"
		}
		c.Sections = append(c.Sections,
			Section{Title: "type", Rows: []Row{{Text: kind}}},
			Section{Title: "entries", Rows: []Row{{Items: entries}}})
	case len(it.Children) > 0:
		c.Sections = append(c.Sections, Section{Title: "members", Rows: []Row{{Items: it.Children}}})
	case it.Value != "":
		title := "value"
		if o.Kind == "address-group" {
			title = "members"
		}
		c.Sections = append(c.Sections, Section{Title: title, Rows: []Row{{Text: it.Value}}})
	}
	if held := idx.DirectGroupsOf(o.Name); len(held) > 0 {
		var items []Item
		for _, g := range held {
			items = append(items, Item{Name: g})
		}
		c.Sections = append(c.Sections, Section{Title: "held by", Rows: []Row{{Items: items}}})
	}
	return c
}

// Kinds lists what lookup can find: security rules and every object kind a rule
// can name that the configuration can define (K10).
func Kinds(cfg *config.Config) []string {
	return append([]string{KindRule}, resolve.ObjectKinds(cfg)...)
}

// Find returns a card for every element of that name visible in the index's scope,
// filtered to one kind when kind is set: the kind is inferred otherwise (K11).
func Find(cfg *config.Config, idx *index.Index, name, kind string) ([]Card, error) {
	kinds := Kinds(cfg)
	if kind != "" && !slices.Contains(kinds, kind) {
		return nil, fmt.Errorf("unknown kind %q; lookup knows %v", kind, kinds)
	}
	var out []Card
	if kind == "" || kind == KindRule {
		rules := idx.Rules()
		for _, r := range rules {
			if r.Name == name {
				out = append(out, Rule(cfg, idx, r, len(rules)))
			}
		}
	}
	b := newBuilder(cfg, idx)
	for _, k := range kinds[1:] {
		if kind != "" && kind != k {
			continue
		}
		if o, ok := b.object(k, name); ok {
			out = append(out, Object(cfg, idx, o))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out, nil
}
