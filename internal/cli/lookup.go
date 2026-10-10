package cli

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/card"
	"github.com/okaiser/proteus/internal/query"
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
	limit        int
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
	bindLimit(cmd, &o.limit)
	a.bindDetail(cmd)
	return cmd
}

// lookupAnswer is the cards found per target, in target order.
type lookupAnswer struct {
	enveloped[query.LookupInput, query.LookupResult]
}

func (a *app) runLookup(ctx context.Context, o lookupOptions) (answer, error) {
	in := query.LookupInput{
		Name: o.name, Kind: o.kind, Expand: o.expand, Full: o.full, Selection: o.sel.input(),
		ResultLimit: query.ResultLimit{Limit: o.limit},
	}
	if u := in.Validate(); u != nil {
		return nil, u
	}
	env, err := a.selectionEnv(in.Selection)
	if err != nil {
		return nil, err
	}
	e, err := query.Lookup(ctx, env, in)
	if err != nil {
		return nil, err
	}
	return lookupAnswer{enveloped[query.LookupInput, query.LookupResult]{e}}, nil
}

func (l lookupAnswer) Summary() *query.Summary { return l.e.Summary }

func (l lookupAnswer) SummaryResults() any {
	return query.Summarize(l.e, query.LookupResult.Summary).Results
}

func (l lookupAnswer) Input() any {
	return l.e.Input.Echo()
}

func (l lookupAnswer) Text(t *textOut) error {
	in := l.e.Input
	r := renderer{w: t, expand: in.Expand, full: in.Full}
	byTarget := make([][]query.LookupResult, len(l.e.Targets))
	for _, res := range l.e.Results {
		byTarget[res.TargetIndex] = append(byTarget[res.TargetIndex], res)
	}
	for i, tg := range l.e.Targets {
		if len(byTarget[i]) == 0 {
			continue
		}
		fmt.Fprintln(t, t.pal.head(header(tg, t.now)))
		printNotes(t, tg)
		for _, res := range byTarget[i] {
			fmt.Fprintf(t, "  %s\n", res.Answer)
			r.card(res.Card)
			fmt.Fprintln(t)
		}
	}
	if l.e.Summary.Found == 0 {
		fmt.Fprintf(t, "no element named %q in the selection\n\n", in.Name)
	}
	printQualifiers(t, l.Qualifiers())
	fmt.Fprintln(t, l.e.Summary.Answer)
	return t.err
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
