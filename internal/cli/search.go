package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/search"
)

// searchOptions are search's flags.
type searchOptions struct {
	sel                     selection
	term                    string
	exact, within, contains bool
	direct                  bool
	kinds, fields, show     []string
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
	o.sel.bind(cmd, true)
	f := cmd.Flags()
	f.BoolVar(&o.exact, "exact", false, "the value equals the term")
	f.BoolVar(&o.within, "within", false, "the value lies inside the term (addresses, prefixes, ranges)")
	f.BoolVar(&o.contains, "contains", false, "the value or name holds the term as text; not a match")
	cmd.MarkFlagsMutuallyExclusive("exact", "within", "contains")
	f.StringSliceVar(&o.kinds, "kind", nil, "only objects and groups of these kinds")
	f.StringSliceVar(&o.fields, "field", nil, "only references and literals from these fields")
	f.StringSliceVar(&o.show, "show", nil, "only these stages: objects, groups, refs, literals")
	f.BoolVar(&o.direct, "direct", false, "groups one level up only")
	return cmd
}

// query turns the flags and the term into a search query.
func (o searchOptions) query(term string) (search.Query, error) {
	q := search.Query{Term: term, Kinds: o.kinds, Fields: o.fields, Direct: o.direct}
	switch { // the flags exclude each other; the root command checks that
	case o.exact:
		q.Mode = search.Exact
	case o.within:
		q.Mode = search.Within
	case o.contains:
		q.Mode = search.Contains
	}
	for _, st := range o.show {
		stage, ok := showNames[st]
		if !ok {
			return q, usageErr("--show %q: want objects, groups, refs or literals", st)
		}
		q.Show = append(q.Show, stage)
	}
	return q, nil
}

// searchAnswer is a search over the selected targets: findings per target, in
// target order.
type searchAnswer struct {
	o        searchOptions
	q        search.Query
	ts       []estate.Target
	byTarget [][]search.Finding
	holes    []estate.Hole
	un       []unresolved
	notes    []note
}

func (a *app) runSearch(ctx context.Context, o searchOptions) (answer, error) {
	q, err := o.query(o.term)
	if err != nil {
		return nil, err
	}
	s, err := a.settings(o.sel.file == "")
	if err != nil {
		return nil, err
	}
	ts, holes, err := a.targets(ctx, o.sel, s, a.stderr)
	if err != nil {
		return nil, err
	}
	ans, err := a.searchTargets(ctx, q, ts, holes)
	if err != nil {
		return nil, err
	}
	ans.o = o
	return ans, nil
}

func (s searchAnswer) Command() string { return "search" }

func (s searchAnswer) Input() any {
	return searchInput{
		Term: s.q.Term, Mode: modeName(s.q), Kinds: s.o.kinds, Fields: s.o.fields, Show: s.o.show,
		Direct: s.o.direct, Selection: s.o.sel.input(),
	}
}

func (s searchAnswer) Results() any {
	results := []searchResult{}
	for i, t := range s.ts {
		for _, f := range s.byTarget[i] {
			results = append(results, searchResult{target: targetOf(t), Finding: f, Scope: f.Scope.String()})
		}
	}
	return results
}

func (s searchAnswer) Qualifiers() qualifiers {
	return qualifiers{Holes: s.holes, Unresolved: s.un, Notes: s.notes}
}

func (s searchAnswer) Text(t *textOut) error {
	fmt.Fprintf(t, "search %s (%s)\n\n", s.q.Term, modeName(s.q))
	with, without := 0, 0
	for i, tg := range s.ts {
		if len(s.byTarget[i]) == 0 {
			without++
			continue
		}
		with++
		fmt.Fprintln(t, header(tg, t.now))
		printNotes(t, tg)
		for _, f := range s.byTarget[i] {
			fmt.Fprintf(t, "  %-10s %-20s %-24s %s\n", f.Stage, f.Kind, f.Name, detail(f))
		}
	}
	printQualifiers(t, s.Qualifiers())
	fmt.Fprintf(t, "%d with results, %d without, %d holes\n", with, without, len(s.holes))
	return t.err
}

// searchTargets runs the query on each target. A target whose index cannot be built
// becomes a hole.
func (a *app) searchTargets(ctx context.Context, q search.Query, ts []estate.Target, holes []estate.Hole) (searchAnswer, error) {
	users, err := a.userSnapshot()
	if err != nil {
		return searchAnswer{}, err
	}
	ans := searchAnswer{q: q, ts: ts, byTarget: make([][]search.Finding, len(ts)), holes: holes}
	for i, t := range ts {
		if err := ctx.Err(); err != nil {
			return searchAnswer{}, err
		}
		q.Providers = index.Providers{Users: users}
		if t.Snapshot != nil {
			if z, err := t.Snapshot.Zones(); err == nil {
				q.Providers.Zones = z
			}
		}
		idx, err := index.For(t.Config, t.Scope)
		if err != nil {
			ans.holes = append(ans.holes, estate.Hole{Device: t.Device, Vsys: t.Vsys, Reason: err.Error()})
			continue
		}
		fs, err := search.Run(t.Config, idx, q)
		if err != nil {
			// Only a term --within cannot read is the user's to fix.
			if errors.Is(err, search.ErrWithinNeedsAddress) {
				err = usageErr("--within: %w", err)
			}
			return searchAnswer{}, err
		}
		ans.byTarget[i] = fs
		a.log.Infof(runlog.TagFind, "%s/%s: %d findings for %q (%s)", t.Device, t.Vsys, len(fs), q.Term, modeName(q))
		for _, f := range fs {
			a.log.Debugf(runlog.TagFind, "%s/%s: %s %s %s %s", t.Device, t.Vsys, f.Stage, f.Kind, f.Name, detail(f))
		}
	}
	ans.un, ans.notes = targetQualifiers(ts)
	return ans, nil
}

// searchResult is one finding in the JSON envelope.
type searchResult struct {
	target
	search.Finding
	Scope string `json:"scope"`
}

// portTerm is a port, bare or with its protocol: 443, tcp/443.
var portTerm = regexp.MustCompile(`^((tcp|udp|sctp)/)?[0-9]+$`)

// showNames are the --show values of spec §15 C6.
var showNames = map[string]search.Stage{
	"objects": search.StageObject, "groups": search.StageGroup,
	"refs": search.StageReference, "literals": search.StageLiteral,
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

// modeName says how the term was matched, for the header.
func modeName(q search.Query) string {
	switch q.Mode {
	case search.Exact:
		return "exact"
	case search.Within:
		return "within"
	case search.Contains:
		return "contains"
	}
	switch ps := index.PrefixesOf(q.Term); {
	case len(ps) == 1 && ps[0].IsSingleIP(), portTerm.MatchString(q.Term):
		return "covers"
	case len(ps) > 0:
		return "overlaps"
	}
	return "matches"
}

// detail is the last column of a finding's line.
func detail(f search.Finding) string {
	switch f.Stage {
	case search.StageReference:
		return f.Field + " -> " + f.Via
	case search.StageLiteral:
		return f.Field + " " + f.Via
	}
	return f.Via
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
