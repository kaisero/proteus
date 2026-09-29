package card

import (
	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
)

// Rule builds the card of one security rule, as the firewall's rule editor lays
// it out (K1). rules is how many rules the vsys evaluates, for "position P of N".
func Rule(cfg *config.Config, idx *index.Index, r resolve.Rule, rules int) Card {
	b := newBuilder(cfg, idx)
	c := Card{
		Kind: KindRule, Name: r.Name, Scope: r.Scope, Position: r.Position, Of: rules,
		Layer: r.Layer.String(), Disabled: r.Disabled, UUID: r.UUID,
		Tags: r.Fields["tag"], Description: r.Description,
	}
	row := func(label, field string) Row {
		out := Row{Label: label}
		for _, n := range r.Fields[field] {
			out.Items = append(out.Items, b.item(field, n, nil))
		}
		return out
	}
	optional := func(rows ...Row) []Row {
		var out []Row
		for i, r := range rows {
			if i < 2 || len(r.Items) > 0 { // zones and addresses always show
				out = append(out, r)
			}
		}
		return out
	}

	src := row("addresses", "source")
	src.Negated = r.NegateSource
	dst := row("addresses", "destination")
	dst.Negated = r.NegateDestination
	c.Sections = []Section{
		{Title: "source", Rows: optional(row("zones", "from"), src, row("users", "source-user"), row("hip", "source-hip"))},
		{Title: "destination", Rows: optional(row("zones", "to"), dst, row("hip", "destination-hip"))},
		{Title: "application", Rows: []Row{row("", "application")}},
		{Title: "service", Rows: []Row{row("", "service")}},
		{Title: "url category", Rows: []Row{row("", "category")}},
	}
	if p := b.profiles(r); len(p.Items) > 0 {
		c.Sections = append(c.Sections, Section{Title: "profile", Rows: []Row{p}})
	}
	c.Sections = append(c.Sections,
		Section{Title: "action", Rows: []Row{{Text: r.Action}}},
		Section{Title: "log", Rows: []Row{{Text: logText(r)}}},
	)
	if r.Schedule != "" {
		c.Sections = append(c.Sections, Section{Title: "schedule", Rows: []Row{{Text: r.Schedule}}})
	}
	return c
}

// profiles is the rule's profile setting: a profile group expanded into its
// profiles by kind (K9), or the profiles the rule names directly.
func (b *builder) profiles(r resolve.Rule) Row {
	row := Row{}
	if len(r.ProfileGroups) > 0 {
		groups, _ := resolve.ProfileGroupsInScope(b.cfg, b.sc)
		for _, name := range r.ProfileGroups {
			it := Item{Name: name, Kind: "profile-group"}
			for _, g := range groups {
				if g.Name == name {
					it.Children = profileItems(g.Kinds)
				}
			}
			row.Label = "group"
			row.Items = append(row.Items, it)
		}
		return row
	}
	row.Items = profileItems(r.Profiles)
	return row
}

func profileItems(byKind map[string][]string) []Item {
	var out []Item
	for _, kind := range sorted(byKind) {
		for _, n := range byKind[kind] {
			out = append(out, Item{Name: n, Kind: kind, Value: kind})
		}
	}
	return out
}

// logText renders the rule's logging the way the editor's options read.
func logText(r resolve.Rule) string { return logTextFor(r.LogStart, r.LogEnd, r.LogSetting) }

func logTextFor(start, end, setting string) string {
	var s string
	switch {
	case start == "yes" && end != "no":
		s = "at session start and end"
	case start == "yes":
		s = "at session start"
	case end == "no":
		s = "not logged"
	default:
		// PAN-OS logs at session end unless told otherwise: log-end defaults to yes.
		// Source: PAN-OS documentation, "Security Policy Rule", Actions tab.
		s = "at session end"
	}
	if setting != "" {
		s += ", forwarded to " + setting
	}
	return s
}
