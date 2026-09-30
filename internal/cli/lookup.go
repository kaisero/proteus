package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
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

// lookupOptions are lookup's flags.
type lookupOptions struct {
	sel          selection
	name         string
	kind         string
	expand, full bool
}

func (a *app) lookupCmd() *cobra.Command {
	var o lookupOptions
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
			o.name = argv[0]
			return a.emitRun(a.runLookup(c.Context(), o))
		},
	}
	o.sel.bind(cmd, selectOpts{file: true, at: true, fresh: true})
	f := cmd.Flags()
	f.StringVar(&o.kind, "kind", "", "the kind of element: security-rule or an object kind")
	f.BoolVar(&o.expand, "expand", false, "show each name's value and every group's members")
	f.BoolVar(&o.full, "full", false, "show every item of a list")
	return cmd
}

// lookupAnswer is the cards found per target, in target order.
type lookupAnswer struct {
	o        lookupOptions
	name     string
	found    int
	ts       []estate.Target
	byTarget [][]card.Card
	holes    []estate.Hole
	un       []unresolved
	notes    []note
}

func (a *app) runLookup(ctx context.Context, o lookupOptions) (answer, error) {
	s, err := a.settings(o.sel.file == "")
	if err != nil {
		return nil, err
	}
	ts, holes, err := a.targets(ctx, o.sel, s)
	if err != nil {
		return nil, err
	}
	ans, err := a.lookupTargets(ctx, o.name, o.kind, ts, holes)
	if err != nil {
		return nil, err
	}
	ans.o = o
	return ans, nil
}

func (l lookupAnswer) Command() string { return "lookup" }

func (l lookupAnswer) Input() any {
	return lookupInput{Name: l.name, Kind: l.o.kind, Expand: l.o.expand, Full: l.o.full, Selection: l.o.sel.input()}
}

func (l lookupAnswer) Results() any {
	results := []lookupResult{}
	for i, t := range l.ts {
		for _, cd := range l.byTarget[i] {
			results = append(results, lookupResult{target: targetOf(t), Scope: cd.Scope.String(), Card: cd})
		}
	}
	return results
}

func (l lookupAnswer) Qualifiers() qualifiers {
	return qualifiers{Holes: l.holes, Unresolved: l.un, Notes: l.notes}
}

func (l lookupAnswer) Text(t *textOut) error {
	r := renderer{w: t, expand: l.o.expand, full: l.o.full}
	with, without := 0, 0
	for i, tg := range l.ts {
		if len(l.byTarget[i]) == 0 {
			without++
			continue
		}
		with++
		fmt.Fprintln(t, t.pal.head(header(tg, t.now)))
		printNotes(t, tg)
		for _, cd := range l.byTarget[i] {
			r.card(cd)
			fmt.Fprintln(t)
		}
	}
	if l.found == 0 {
		fmt.Fprintf(t, "no element named %q in the selection\n\n", l.name)
	}
	printQualifiers(t, l.Qualifiers())
	fmt.Fprintf(t, "%d with it, %d without, %d holes\n", with, without, len(l.holes))
	return t.err
}

// lookupTargets finds the element on each target. A name that means different kinds
// on different targets is a usage error: the user has to pick one.
func (a *app) lookupTargets(ctx context.Context, name, kind string, ts []estate.Target, holes []estate.Hole) (lookupAnswer, error) {
	ans := lookupAnswer{name: name, ts: ts, byTarget: make([][]card.Card, len(ts)), holes: holes}
	kinds := map[string][]string{} // kind -> where it was found
	found := 0
	for i, t := range ts {
		if err := ctx.Err(); err != nil {
			return lookupAnswer{}, err
		}
		idx, err := index.For(t.Config, t.Scope)
		if err != nil {
			ans.holes = append(ans.holes, estate.Hole{Device: t.Device, Vsys: t.Vsys, Reason: err.Error()})
			continue
		}
		cs, err := card.Find(t.Config, idx, name, kind)
		if err != nil {
			return lookupAnswer{}, usageErr("--kind: %w", err)
		}
		ans.byTarget[i] = cs
		var here []string
		for _, cd := range cs {
			here = append(here, cd.Kind)
			kinds[cd.Kind] = append(kinds[cd.Kind], where(t.Device, t.Vsys))
		}
		found += len(cs)
		a.log.Infof(runlog.TagFind, "%s/%s: lookup %q found %v", t.Device, t.Vsys, name, here)
	}
	if len(kinds) > 1 {
		var lines []string
		for _, k := range sorted(kinds) {
			lines = append(lines, fmt.Sprintf("  %s on %s", k, strings.Join(kinds[k], ", ")))
		}
		return lookupAnswer{}, usageErr("%q names more than one kind; pick one with --kind:\n%s", name, strings.Join(lines, "\n"))
	}
	ans.un, ans.notes = targetQualifiers(ts)
	ans.found = found
	return ans, nil
}

// lookupResult is one card in the JSON envelope.
type lookupResult struct {
	target
	Scope string    `json:"scope"`
	Card  card.Card `json:"card"`
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
	slices.Sort(out)
	return out
}
