package main

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/card"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/runlog"
)

// Limits of a rendered card (spec §16 K3, K5). JSON always carries the whole card.
const (
	maxItems = 5
	maxDepth = 3
)

func (a *app) lookupCmd() *cobra.Command {
	var sel selection
	var kind string
	var expand, full bool
	cmd := &cobra.Command{
		Use:   "lookup <name>",
		Short: "Show the whole rule or object a name refers to",
		Long: "Lookup prints the element a search result points to: a security rule laid out\n" +
			"like the firewall's rule editor, or an object with its value, its members and the\n" +
			"groups holding it.\n\n" +
			"The kind is inferred from the name. When several kinds share the name, --kind\n" +
			"picks one. --expand shows each name's value and every group's members; --full\n" +
			"lifts the five-item limit on lists.",
		Args: args(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, argv []string) error {
			name := argv[0]
			s, err := a.settings(sel.file == "")
			if err != nil {
				return err
			}
			ts, holes, err := a.targets(c.Context(), sel, s, a.stderr)
			if err != nil {
				return err
			}
			type result struct {
				target
				Scope string    `json:"scope"`
				Card  card.Card `json:"card"`
			}
			var results []result
			byTarget := make([][]card.Card, len(ts))
			kinds := map[string][]string{} // kind -> where it was found
			for i, t := range ts {
				idx, err := index.For(t.Config, t.Scope)
				if err != nil {
					holes = append(holes, estate.Hole{Device: t.Device, Vsys: t.Vsys, Reason: err.Error()})
					continue
				}
				cs, err := card.Find(t.Config, idx, name, kind)
				if err != nil {
					return usageErr("--kind: %v", err)
				}
				byTarget[i] = cs
				var found []string
				for _, cd := range cs {
					found = append(found, cd.Kind)
					kinds[cd.Kind] = append(kinds[cd.Kind], where(t.Device, t.Vsys))
					results = append(results, result{target: targetOf(t), Scope: cd.Scope.String(), Card: cd})
				}
				a.log.Infof(runlog.TagFind, "%s/%s: lookup %q found %v", t.Device, t.Vsys, name, found)
			}
			if len(kinds) > 1 {
				var lines []string
				for _, k := range sorted(kinds) {
					lines = append(lines, fmt.Sprintf("  %s on %s", k, strings.Join(kinds[k], ", ")))
				}
				return usageErr("%q names more than one kind; pick one with --kind:\n%s", name, strings.Join(lines, "\n"))
			}
			un, notes := qualifiers(ts)
			if len(results) == 0 && len(holes)+len(un) == 0 {
				return fmt.Errorf("no element named %q in the selection", name)
			}
			if s.output == "json" {
				in := map[string]any{"name": name, "kind": kind, "expand": expand, "full": full, "selection": sel.input()}
				if results == nil {
					results = []result{}
				}
				if err := writeJSON(a.stdout, envelope{Command: "lookup", Input: in, Results: results, Holes: holes, Unresolved: un, Notes: notes}); err != nil {
					return err
				}
				return finish(holes, un)
			}
			r := renderer{w: a.stdout, expand: expand, full: full}
			with, without := 0, 0
			for i, t := range ts {
				if len(byTarget[i]) == 0 {
					without++
					continue
				}
				with++
				fmt.Fprintln(a.stdout, header(t, a.now()))
				printNotes(a, t)
				for _, cd := range byTarget[i] {
					r.card(cd)
					if cd.Kind != card.KindRule {
						fmt.Fprintf(a.stdout, "  where it is used: panos-analyst search %s %s\n", name, selectorOf(t))
					}
					fmt.Fprintln(a.stdout)
				}
			}
			printQualifiers(a, holes, un, notes)
			fmt.Fprintf(a.stdout, "%d with it, %d without, %d holes\n", with, without, len(holes))
			return finish(holes, un)
		},
	}
	sel.bind(cmd.Flags(), true)
	f := cmd.Flags()
	f.StringVar(&kind, "kind", "", "the kind of element: security-rule or an object kind")
	f.BoolVar(&expand, "expand", false, "show each name's value and every group's members")
	f.BoolVar(&full, "full", false, "show every item of a list")
	return cmd
}

// selectorOf is the selector that names the same configuration again.
func selectorOf(t estate.Target) string {
	if t.Snapshot == nil {
		return "--file " + t.Config.Path()
	}
	return "--device " + t.Device + " --vsys " + t.Vsys
}

// renderer writes a card as text. Three columns: the section title, the row
// label, and the items.
type renderer struct {
	w      io.Writer
	expand bool
	full   bool
}

const (
	titleWidth = 13 // "url category "
	labelWidth = 11 // "addresses  "
)

func (r renderer) card(c card.Card) {
	var head []string
	if c.Kind == card.KindRule {
		state := "enabled"
		if c.Disabled {
			state = "DISABLED"
		}
		head = append(head, fmt.Sprintf("position %d of %d", c.Position, c.Of), c.Layer, state)
	} else {
		head = append(head, c.Scope.String())
		if c.Shadows != "" {
			head = append(head, "shadows "+c.Shadows)
		}
	}
	fmt.Fprintf(r.w, "%-*s  %-28s %s\n", titleWidth, strings.ReplaceAll(c.Kind, "-", " "), c.Name, strings.Join(head, ", "))
	for _, f := range []struct{ title, text string }{
		{"uuid", c.UUID}, {"tags", strings.Join(c.Tags, ", ")}, {"description", c.Description},
	} {
		if f.text != "" {
			fmt.Fprintf(r.w, "  %-*s%s\n", titleWidth, f.title, f.text)
		}
	}
	fmt.Fprintln(r.w)
	for _, s := range c.Sections {
		for i, row := range s.Rows {
			title := ""
			if i == 0 {
				title = s.Title
			}
			r.row(title, row, c.Kind != card.KindRule)
		}
	}
}

// row writes one row. A row whose items have children is a tree, one item per
// line; any other row is one line.
func (r renderer) row(title string, row card.Row, object bool) {
	indent := 2 + titleWidth
	prefix := fmt.Sprintf("  %-*s", titleWidth, title)
	if row.Label != "" {
		prefix += fmt.Sprintf("%-*s", labelWidth, row.Label)
		indent += labelWidth
	}
	not := ""
	if row.Negated {
		not = "NOT "
	}
	if row.Text != "" {
		fmt.Fprintln(r.w, prefix+not+row.Text)
		return
	}
	tree := (r.expand || object) && slices.ContainsFunc(row.Items, func(it card.Item) bool { return len(it.Children) > 0 })
	if !tree {
		fmt.Fprintln(r.w, prefix+not+strings.Join(r.names(row.Items), ", "))
		return
	}
	lines := r.tree(row.Items, 1)
	fmt.Fprintln(r.w, prefix+not+lines[0])
	pad := strings.Repeat(" ", indent+len(not))
	for _, l := range lines[1:] {
		fmt.Fprintln(r.w, pad+l)
	}
}

// names renders items on one line, cut at five unless --full.
func (r renderer) names(items []card.Item) []string {
	shown, more := r.cut(items)
	var out []string
	for _, it := range shown {
		s := r.name(it)
		if !r.expand && it.Kind == "profile-group" && len(it.Children) > 0 {
			// K9: a profile group always shows what it holds.
			s += " (" + strings.Join(r.names(it.Children), ", ") + ")"
		}
		out = append(out, s)
	}
	if more > 0 {
		out = append(out, fmt.Sprintf("… (+%d more)", more))
	}
	return out
}

// tree renders items one per line, children two spaces deeper, cut at three levels.
func (r renderer) tree(items []card.Item, depth int) []string {
	shown, more := r.cut(items)
	var out []string
	for _, it := range shown {
		out = append(out, r.name(it))
		if len(it.Children) == 0 {
			continue
		}
		if depth == maxDepth {
			out = append(out, fmt.Sprintf("  … (+%d more)", len(it.Children)))
			continue
		}
		for _, l := range r.tree(it.Children, depth+1) {
			out = append(out, "  "+l)
		}
	}
	if more > 0 {
		out = append(out, fmt.Sprintf("… (+%d more)", more))
	}
	return out
}

// name is an item as --expand asks: bare, or with its value in parentheses.
func (r renderer) name(it card.Item) string {
	if !r.expand || it.Literal {
		return it.Name
	}
	switch {
	case it.Predefined:
		return it.Name + " (predefined)"
	case it.Value != "":
		return it.Name + " (" + it.Value + ")"
	case len(it.Children) > 0 && it.Kind != "profile-group":
		return it.Name + " (group, " + plural(len(it.Children), "member") + ")"
	}
	return it.Name
}

func (r renderer) cut(items []card.Item) ([]card.Item, int) {
	if r.full || len(items) <= maxItems {
		return items, 0
	}
	return items[:maxItems], len(items) - maxItems
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

func sorted[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
