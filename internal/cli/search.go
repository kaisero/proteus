package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/query"
)

// searchOptions are search's flags.
type searchOptions struct {
	sel                     selection
	term                    string
	exact, within, contains bool
	direct, why             bool
	kinds, fields, show     []string
	limit                   int
}

func (a *app) searchCmd() *cobra.Command {
	var o searchOptions
	cmd := &cobra.Command{
		Use:   "search <term>",
		Short: "Find every place a value or name appears",
		Long: "Search finds the objects whose value holds the term, the objects with that name,\n" +
			"the groups holding either, the references naming any of them, and the rules that\n" +
			"write the term directly into a field.\n\n" +
			"The term's type sets the match: an address is covered, a prefix or range overlaps,\n" +
			"a port is covered, a URL matches by PAN-OS tokens, anything else is exact.",
		Args: args(cobra.ExactArgs(1)),
		RunE: func(c *cobra.Command, argv []string) error {
			o.term = argv[0]
			return a.emitRun(a.runSearch(c.Context(), o))
		},
	}
	o.sel.bind(cmd, selectOpts{file: true, at: true, fresh: true})
	f := cmd.Flags()
	f.BoolVar(&o.exact, "exact", false, "the value equals the term")
	f.BoolVar(&o.within, "within", false, "the value lies inside the term (addresses, prefixes, ranges)")
	f.BoolVar(&o.contains, "contains", false, "the value or name holds the term as text; not a match")
	cmd.MarkFlagsMutuallyExclusive("exact", "within", "contains")
	f.StringSliceVar(&o.kinds, "kind", nil, "only objects and groups of these kinds")
	f.StringSliceVar(&o.fields, "field", nil, "only references and literals from these fields")
	f.StringSliceVar(&o.show, "show", nil, "only these stages: objects, groups, refs, literals")
	f.BoolVar(&o.direct, "direct", false, "groups one level up only")
	bindLimit(cmd, &o.limit)
	bindWhy(cmd, &o.why)
	a.bindDetail(cmd)
	return cmd
}

// input is the search the flags ask. The mode flags exclude each other; the
// root command checks that.
func (o searchOptions) input() query.SearchInput {
	in := query.SearchInput{
		Term: o.term, Kinds: o.kinds, Fields: o.fields, Show: o.show, Direct: o.direct, Selection: o.sel.input(),
		ResultLimit: query.ResultLimit{Limit: o.limit},
	}
	switch {
	case o.exact:
		in.Mode = "exact"
	case o.within:
		in.Mode = "within"
	case o.contains:
		in.Mode = "contains"
	}
	return in
}

// searchAnswer is a search over the selected targets: findings per target, in
// target order.
type searchAnswer struct {
	enveloped[query.SearchInput, query.Finding]
	why bool
}

func (a *app) runSearch(ctx context.Context, o searchOptions) (answer, error) {
	in := o.input()
	if u := in.Validate(); u != nil {
		return nil, u
	}
	env, err := a.selectionEnv(in.Selection)
	if err != nil {
		return nil, err
	}
	e, err := query.Search(ctx, env, in)
	if err != nil {
		return nil, err
	}
	return searchAnswer{enveloped: enveloped[query.SearchInput, query.Finding]{e}, why: o.why}, nil
}

func (s searchAnswer) Summary() *query.Summary { return s.e.Summary }

func (s searchAnswer) SummaryResults() any {
	return query.Summarize(s.e, query.Finding.Summary).Results
}

func (s searchAnswer) Input() any {
	return s.e.Input.Echo()
}

func (s searchAnswer) Text(t *textOut) error {
	fmt.Fprintf(t, "search %s (%s)\n\n", s.e.Input.Term, s.e.Input.Matching())
	byTarget := make([][]query.Finding, len(s.e.Targets))
	for _, r := range s.e.Results {
		byTarget[r.TargetIndex] = append(byTarget[r.TargetIndex], r)
	}
	for i, tg := range s.e.Targets {
		if len(byTarget[i]) == 0 {
			continue
		}
		fmt.Fprintln(t, t.pal.head(header(tg, t.now)))
		printNotes(t, tg)
		var tb table
		for _, f := range byTarget[i] {
			tb.row(plain(string(f.Stage)), plain(f.Kind), plain(f.Name), plain(query.Detail(f.Finding)))
			// The finding's answer duplicates its row, so only --why adds it.
			if s.why {
				tb.row(plain(""), plain(f.Answer))
			}
		}
		_ = tb.write(t, "  ", 1)
	}
	printQualifiers(t, s.Qualifiers(), leftNotes(s.e.Targets, func(i int) bool { return len(byTarget[i]) > 0 })...)
	fmt.Fprintln(t, s.e.Summary.Answer)
	return t.err
}

// userSnapshot reads PROTEUS_USERS, the user-to-group mapping a configuration does
// not hold. None set is no mapping.
func (a *app) userSnapshot() (index.UserDirectory, error) {
	path := a.getenv("PROTEUS_USERS")
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("PROTEUS_USERS: %w", err)
	}
	defer func() { _ = f.Close() }()
	snap, err := index.LoadUserSnapshot(f)
	if err != nil {
		return nil, fmt.Errorf("PROTEUS_USERS: %w", err)
	}
	return snap, nil
}

// header names a target: device, vsys, and where its configuration came from.
func header(t estate.Target, now time.Time) string {
	return t.Device + " / " + t.Vsys + "   " + source(t, now)
}

// source says where a target's configuration came from: a file, or a snapshot
// and its age.
func source(t estate.Target, now time.Time) string {
	if t.Snapshot == nil {
		return t.Config.Path()
	}
	return fmt.Sprintf("snapshot %s (%s)", t.Snapshot.ID, ago(now.Sub(t.Snapshot.Meta.TakenAt)))
}

func where(device, vsys string) string {
	if vsys == "" {
		return device
	}
	return device + "/" + vsys
}
