package card

import (
	"fmt"

	"github.com/kaisero/proteus/internal/identity"
)

// The kinds of the identity cards (spec 2026-10-17 §6.2, PD14). The identity
// data of the device defines them, not the configuration.
const (
	KindIdentityUser  = "identity-user"
	KindIdentityGroup = "identity-group"
)

// FindIdentity returns the identity cards of a name: the user that the name
// names, as --user reads a name (Resolve, PD18), and the group or DUG that it
// names, by its name in any case or by its short name (M11, M12). kind picks
// one of the two kinds; nil data, another kind and a name the data does not
// know give nil.
func FindIdentity(ids *identity.Data, name, kind string) []Card {
	if ids == nil || kind != "" && kind != KindIdentityUser && kind != KindIdentityGroup {
		return nil
	}
	var out []Card
	if kind != KindIdentityGroup {
		if u, ok := ids.User(name); ok {
			out = append(out, userCard(ids, u))
		}
	}
	if kind != KindIdentityUser {
		if c, ok := groupCard(ids, name); ok {
			out = append(out, c)
		}
	}
	return out
}

// userCard is the card of a user: the primary name, the alternate names, the
// email, the groups and DUGs with their source (U3, D13), the mapped
// addresses with type and timeout (U1), and the registered tags (U9). Every
// section is on the card; an empty one has no row.
func userCard(ids *identity.Data, u identity.User) Card {
	text := func(s string) []Row {
		if s == "" {
			return []Row{}
		}
		return []Row{{Text: s}}
	}
	items := func(its []Item) []Row {
		if len(its) == 0 {
			return []Row{}
		}
		return []Row{{Items: its}}
	}
	var alt, groups, mapped, tags []Item
	for _, a := range u.Alt {
		alt = append(alt, Item{Name: a})
	}
	for _, g := range u.Groups {
		groups = append(groups, Item{Name: g, Value: groupSource(ids, g)})
	}
	// A mapping keeps its user as the device stores it: example\alice is no
	// mapping of example.com\alice, as observed on fw01, PAN-OS 11.2.5 (spec
	// 2026-10-17 M2).
	for _, m := range ids.MappingsOf(u.Name) {
		mapped = append(mapped, Item{Name: m.IP.String(), Value: fmt.Sprintf("%s, timeout %d s", m.Type, m.Timeout)})
	}
	for _, t := range ids.TagsOf(u.Name) {
		tags = append(tags, Item{Name: t})
	}
	return Card{Kind: KindIdentityUser, Name: u.Name, Sections: []Section{
		{Title: "primary", Rows: text(u.Name)},
		{Title: "alternate names", Rows: items(alt)},
		{Title: "email", Rows: text(u.Email)},
		{Title: "groups", Rows: items(groups)},
		{Title: "mapped addresses", Rows: items(mapped)},
		{Title: "tags", Rows: items(tags)},
	}}
}

// groupCard is the card of a group or a DUG: its source, and its members, a
// count row and then the primary names (U3, D13).
func groupCard(ids *identity.Data, name string) (Card, bool) {
	g, ok := ids.Group(name)
	if !ok {
		mem := ids.Member(name)
		if mem.Kind != identity.MemberDUG {
			return Card{}, false
		}
		g = identity.Group{Name: mem.Name, Source: mem.Source}
	}
	members := []Row{{Text: identity.MembersText(0)}}
	if names := ids.Members(g.Name); len(names) > 0 {
		items := make([]Item, len(names))
		for i, n := range names {
			items[i] = Item{Name: n}
		}
		members = []Row{{Text: identity.MembersText(len(names))}, {Items: items}}
	}
	return Card{Kind: KindIdentityGroup, Name: g.Name, Sections: []Section{
		{Title: "source", Rows: []Row{{Text: g.Source}}},
		{Title: "members", Rows: members},
	}}, true
}

// groupSource is the source of a group of a user (§3.3): as groups[] records
// it, else by its form, as when the part groups is missing.
func groupSource(ids *identity.Data, name string) string {
	if g, ok := ids.Group(name); ok {
		return g.Source
	}
	f := ids.File()
	return identity.Classify(name, f.Sources.LDAP, !ids.Complete(identity.PartLDAP), f.DUGs, f.Sources.CIE, !ids.Complete(identity.PartCIE))
}
