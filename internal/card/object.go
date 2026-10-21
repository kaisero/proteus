package card

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/resolve"
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
	b.plan([]resolve.Object{o})
	it := b.objectItem(o)
	switch {
	case o.Kind == "profile-group":
		groups := resolve.ProfileGroupsInScope(cfg, b.sc)
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
	// Only groups that can hold the object's kind: a service group of the
	// same name as an address group holds no address.
	if held := idx.GroupsHolding(o.Kind, o.Name, true); len(held) > 0 {
		var items []Item
		for _, g := range held {
			items = append(items, Item{Name: g.Name})
		}
		c.Sections = append(c.Sections, Section{Title: "held by", Rows: []Row{{Items: items}}})
	}
	return c
}

// Kinds lists what lookup can find: security rules, every object kind a rule
// can name that the configuration can define (K10), the application
// containers, which only the App-ID content data defines (spec 2026-10-16
// §5.2), and the identity users and groups, which only the identity data
// defines (spec 2026-10-17 §6.2).
func Kinds(cfg *config.Config) []string {
	kinds := resolve.ObjectKinds(cfg)
	for _, k := range []string{KindContainer, KindIdentityGroup, KindIdentityUser} {
		if i, found := slices.BinarySearch(kinds, k); !found {
			kinds = slices.Insert(kinds, i, k)
		}
	}
	return append([]string{KindRule}, kinds...)
}

// identityKind reports whether lookup finds a kind in the identity data
// (FindIdentity), not in the configuration.
func identityKind(kind string) bool {
	return kind == KindIdentityUser || kind == KindIdentityGroup
}

// Find returns a card for every element of that name visible in the index's scope,
// filtered to one kind when kind is set: the kind is inferred otherwise (K11).
//
// apps is the App-ID content data, or nil. With it, Find also finds the
// predefined applications and the containers, and a filter card lists the
// applications the filter selects (spec 2026-10-16 §5.2). A custom
// application has its application card either way. The identity kinds pass
// the kind check, and FindIdentity finds them.
func Find(cfg *config.Config, idx *index.Index, apps *appid.Data, name, kind string) ([]Card, error) {
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
		if kind != "" && kind != k || identityKind(k) {
			continue
		}
		switch o, ok := b.object(k, name); {
		case k == KindApplication:
			if c, ok := b.application(apps, name); ok {
				out = append(out, c)
			}
		case ok && k == KindFilter:
			out = append(out, FilterCard(cfg, idx, apps, o))
		case ok:
			out = append(out, Object(cfg, idx, o))
		case k == KindContainer && apps != nil:
			if ct, ok := apps.Container(name); ok {
				out = append(out, containerCard(ct))
			}
		}
	}
	slices.SortStableFunc(out, func(a, b Card) int { return cmp.Compare(a.Kind, b.Kind) })
	return out, nil
}
