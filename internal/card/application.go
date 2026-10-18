package card

import (
	"slices"
	"strings"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/resolve"
)

// The kinds of the App-ID cards.
const (
	KindApplication = "application"
	KindFilter      = "application-filter"
	KindContainer   = "application-container"
)

// predefinedScope is the scope of a content application or container: the
// device defines them.
var predefinedScope = config.Scope{Sort: config.ScopePredefined}

// App builds the card of one application, predefined or custom (spec
// 2026-10-16 §5.2). The card shows a as given: the caller adds to a.Tags the
// tags that application-tag gives it. parent and tunnels show the names as
// the content writes them: a parent can be no application, and a tunnel name
// can be unknown (F15).
func App(a appid.App, sc config.Scope) Card {
	c := Card{Kind: KindApplication, Name: a.Name, Scope: sc, Description: a.Description}
	text := func(title, v string) {
		if v != "" {
			c.Sections = append(c.Sections, Section{Title: title, Rows: []Row{{Text: v}}})
		}
	}
	names := func(title string, ns []string) {
		if len(ns) > 0 {
			c.Sections = append(c.Sections, Section{Title: title, Rows: []Row{{Items: nameItems(ns)}}})
		}
	}
	text("category", a.Category)
	text("subcategory", a.Subcategory)
	text("technology", a.Technology)
	if a.Risk != 0 {
		text("risk", itoa(a.Risk))
	}
	// The flags that hold yes, with ident-by-dport and ident-by-sport (F12).
	var flags []string
	for f, on := range a.Flags {
		if on {
			flags = append(flags, f)
		}
	}
	slices.Sort(flags)
	names("flags", flags)
	names("tags", a.Tags)
	text("default", a.Default.String())
	if a.Obsolete {
		text("obsolete", "yes")
	}
	text("container", a.Container)
	text("parent", a.Parent)
	names("uses", a.Use)
	names("implicit uses", a.ImplicitUse)
	names("tunnels", a.Tunnel)
	return c
}

// FilterCard builds the card of an application filter: its criteria and the
// applications it selects, each by name, with their count (spec 2026-10-16
// §5.2). Without the App-ID data the applications are unknown: a filter
// selects predefined applications by their content metadata.
func FilterCard(cfg *config.Config, idx *index.Index, apps *appid.Data, o resolve.Object) Card {
	sc := idx.Scope()
	c := Card{Kind: o.Kind, Name: o.Name, Scope: o.Scope, Tags: o.Tags, Description: o.Description}
	if o.ShadowedFrom != nil {
		c.Shadows = o.ShadowedFrom.String()
	}
	var f appid.Filter
	for _, af := range resolve.ApplicationFilters(cfg, sc) {
		if af.Name == o.Name {
			f = af.Filter
		}
	}
	var criteria []Row
	for _, field := range sorted(f.Criteria) {
		criteria = append(criteria, Row{Label: field, Text: strings.Join(f.Criteria[field], ", ")})
	}
	if len(f.Exclude) > 0 {
		criteria = append(criteria, Row{Label: "exclude", Text: strings.Join(f.Exclude, ", ")})
	}
	if len(criteria) > 0 {
		c.Sections = append(c.Sections, Section{Title: "criteria", Rows: criteria})
	}
	rows := []Row{{Text: "unknown: no application data"}}
	if apps != nil {
		sel := selected(cfg, sc, apps, f)
		rows = []Row{{Text: plural(len(sel), "application", "applications")}}
		if len(sel) > 0 {
			rows = append(rows, Row{Items: nameItems(sel)})
		}
	}
	c.Sections = append(c.Sections, Section{Title: "applications", Rows: rows})
	if held := idx.GroupsHolding(o.Kind, o.Name, true); len(held) > 0 {
		var items []Item
		for _, g := range held {
			items = append(items, Item{Name: g.Name})
		}
		c.Sections = append(c.Sections, Section{Title: "held by", Rows: []Row{{Items: items}}})
	}
	return c
}

// selected is the applications a filter selects in a scope, by name: the
// custom applications and the content applications, each with the tags
// application-tag adds (S5, S12). A custom application hides a content
// application of its name in any case, as the index resolves them.
func selected(cfg *config.Config, sc config.Scope, apps *appid.Data, f appid.Filter) []string {
	tags := resolve.ApplicationTags(cfg, sc)
	custom := map[string]bool{}
	var out []string
	consider := func(a appid.App) {
		a.Tags = append(slices.Clone(a.Tags), tags[a.Name]...)
		if f.Selects(a).Selected {
			out = append(out, a.Name)
		}
	}
	for _, a := range resolve.Applications(cfg, sc) {
		custom[strings.ToLower(a.Name)] = true
		consider(a.App)
	}
	for _, a := range apps.Apps() {
		if !custom[strings.ToLower(a.Name)] {
			consider(a)
		}
	}
	slices.Sort(out)
	return out
}

// containerCard builds the card of an application container: its functions
// (S9).
func containerCard(ct appid.Container) Card {
	return Card{Kind: KindContainer, Name: ct.Name, Scope: predefinedScope, Sections: []Section{
		{Title: "functions", Rows: []Row{{Items: nameItems(ct.Functions)}}},
	}}
}

// application is the card of an application of the scope: a custom
// application of the configuration by its name, or else a content
// application in any case (P14). The card counts the tags application-tag
// adds (S12).
func (b *builder) application(apps *appid.Data, name string) (Card, bool) {
	tags := resolve.ApplicationTags(b.cfg, b.sc)
	for _, a := range resolve.Applications(b.cfg, b.sc) {
		if a.Name != name {
			continue
		}
		app := a.App
		app.Tags = append(slices.Clone(app.Tags), tags[app.Name]...)
		c := App(app, a.Scope)
		c.Tags = a.Tags
		if a.ShadowedFrom != nil {
			c.Shadows = a.ShadowedFrom.String()
		}
		return c, true
	}
	if apps == nil {
		return Card{}, false
	}
	a, ok := apps.App(name)
	if !ok {
		return Card{}, false
	}
	a.Tags = append(slices.Clone(a.Tags), tags[a.Name]...)
	return App(a, predefinedScope), true
}

func nameItems(ns []string) []Item {
	out := make([]Item, len(ns))
	for i, n := range ns {
		out[i] = Item{Name: n}
	}
	return out
}
