package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/drift"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/store"
)

// snapshotListOptions are snapshot list's flags.
type snapshotListOptions struct{ device string }

// snapshotShowOptions are snapshot show's flags.
type snapshotShowOptions struct{ sel selection }

// snapshotDiffOptions are snapshot diff's flags.
type snapshotDiffOptions struct {
	sel      selection
	from, to string
	limit    int
}

func (a *app) snapshotListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <device>",
		Short: "List a device's stored snapshots, newest first; * marks latest",
		Args:  args(cobra.ExactArgs(1)),

		ValidArgsFunction: a.completeOneDevice,
		RunE: func(c *cobra.Command, argv []string) error {
			return a.emitRun(a.runSnapshotList(c.Context(), snapshotListOptions{device: argv[0]}))
		},
	}
}

// snapshotRow is one stored snapshot of a device.
type snapshotRow struct {
	ID        string `json:"id"`
	Latest    bool   `json:"latest"`
	SWVersion string `json:"sw_version"`
	Documents int    `json:"documents"`
	Failed    int    `json:"failed"`
}

// snapshotListAnswer is the stored snapshots of one device, newest first.
type snapshotListAnswer struct {
	device string
	rows   []snapshotRow
	holes  []estate.Hole
}

func (a *app) runSnapshotList(_ context.Context, o snapshotListOptions) (answer, error) {
	s, err := a.settings(false)
	if err != nil {
		return nil, err
	}
	if s.inv != nil {
		if _, err := s.inv.Select([]string{o.device}, nil); err != nil {
			return nil, usageErr("%w", err)
		}
	}
	ans := snapshotListAnswer{device: o.device, rows: []snapshotRow{}}
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return nil, err
	}
	ids, err := st.List(o.device)
	if err != nil {
		ans.holes = []estate.Hole{estate.NewHole(o.device, "", reason.New(estate.GapOf(err), err.Error()))}
		return ans, nil
	}
	ans.rows, ans.holes = snapshotRows(st, o.device, ids)
	return ans, nil
}

// snapshotRows reads the listed snapshots of a device. A damaged snapshot becomes a
// hole and the list goes on; one pruned since it was listed no longer exists and is
// left out.
func snapshotRows(st *store.Store, device string, ids []string) ([]snapshotRow, []estate.Hole) {
	rows := []snapshotRow{}
	var holes []estate.Hole
	latest, _ := st.Latest(device)
	for _, id := range ids {
		sn, err := st.Get(device, id)
		switch {
		case errors.Is(err, store.ErrNoSnapshot):
			continue
		case err != nil:
			holes = append(holes, estate.NewHole(device, "", reason.New(estate.GapOf(err), err.Error())))
			continue
		}
		r := snapshotRow{ID: id, Latest: id == latest.ID, SWVersion: sn.Meta.SWVersion, Documents: len(sn.Meta.Documents)}
		for _, d := range sn.Meta.Documents {
			if d.Error != "" {
				r.Failed++
			}
		}
		rows = append(rows, r)
	}
	return rows, holes
}

func (l snapshotListAnswer) Command() string        { return "snapshot list" }
func (l snapshotListAnswer) Input() any             { return snapshotListInput{Device: l.device} }
func (l snapshotListAnswer) Results() any           { return l.rows }
func (l snapshotListAnswer) Qualifiers() qualifiers { return qualifiers{Holes: l.holes} }

func (l snapshotListAnswer) Text(t *textOut) error {
	var tb table
	for _, r := range l.rows {
		mark := plain(" ")
		if r.Latest {
			mark = cell{"*", t.pal.ok}
		}
		failed := plain(fmt.Sprintf("%d failed", r.Failed))
		if r.Failed > 0 {
			failed.style = t.pal.bad
		}
		tb.row(mark, plain(r.ID), plain("PAN-OS "+r.SWVersion), plain(fmt.Sprintf("%d documents,", r.Documents)), failed)
	}
	_ = tb.write(t, "", 1)
	printQualifiers(t, l.Qualifiers())
	return t.err
}

func (a *app) snapshotShowCmd() *cobra.Command {
	var o snapshotShowOptions
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the snapshots a question would read: version, vsys, rule counts, documents",
		Args:  args(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			return a.emitRun(a.runSnapshotShow(c.Context(), o))
		},
	}
	o.sel.bind(cmd, selectOpts{file: true, at: true, fresh: true})
	return cmd
}

// showRow is one device and vsys that a question would read.
type showRow struct {
	target
	Version  string               `json:"version"`
	Rules    int                  `json:"rules"`
	Host     string               `json:"host,omitempty"`
	Model    string               `json:"model,omitempty"`
	Serial   string               `json:"serial,omitempty"`
	From     string               `json:"fetched_from,omitempty"`
	Document []store.DocumentMeta `json:"documents,omitempty"`
}

// snapshotShowAnswer is the snapshots a question would read: one row per device and
// vsys.
type snapshotShowAnswer struct {
	o     snapshotShowOptions
	ts    []estate.Target
	rows  []showRow
	holes []estate.Hole
	un    []unresolved
	notes []note
}

func (a *app) runSnapshotShow(ctx context.Context, o snapshotShowOptions) (answer, error) {
	env, err := a.selectionEnv(o.sel.input())
	if err != nil {
		return nil, err
	}
	ts, holes, err := query.Targets(ctx, env, o.sel.input())
	if err != nil {
		return nil, err
	}
	ans := snapshotShowAnswer{o: o, ts: ts, rows: []showRow{}, holes: holes}
	for _, t := range ts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r := showRow{target: targetOf(t), Version: t.Config.DetailVersion()}
		if tg, err := resolve.TargetFor(t.Config, firstDevice(t.Config), t.Vsys); err == nil {
			r.Rules = len(tg.Rules(resolve.Security))
		}
		if t.Snapshot != nil {
			m := t.Snapshot.Meta
			r.Host, r.Model, r.Serial, r.From, r.Document = m.Host, m.Model, m.Serial, m.FetchedFrom, m.Documents
		}
		ans.rows = append(ans.rows, r)
	}
	ans.un, ans.notes = query.TargetQualifiers(ts)
	return ans, nil
}

func (s snapshotShowAnswer) Command() string { return "snapshot show" }
func (s snapshotShowAnswer) Input() any      { return s.o.sel.input() }
func (s snapshotShowAnswer) Results() any    { return s.rows }
func (s snapshotShowAnswer) Qualifiers() qualifiers {
	return qualifiers{Holes: s.holes, Unresolved: s.un, Notes: s.notes}
}

// Text prints one block per device and one line per vsys.
func (s snapshotShowAnswer) Text(t *textOut) error {
	last := ""
	var vsys table // one per device, written before the next device's header
	for i, r := range s.rows {
		if r.Device != last {
			_ = vsys.write(t, "  ", 4)
			vsys = table{}
			last = r.Device
			fmt.Fprintf(t, "%s   %s\n", t.pal.head(r.Device), source(s.ts[i], t.now))
			printNotes(t, s.ts[i])
			if r.Host != "" {
				fmt.Fprintf(t, "  %s, %s, serial %s\n", r.Host, r.Model, r.Serial)
			}
			if r.From != "" {
				fmt.Fprintf(t, "  fetched from the active HA peer %s\n", r.From)
			}
			var tb table
			for _, d := range r.Document {
				if d.Error != "" {
					tb.row(plain(d.Name), cell{"FAILED", t.pal.bad}, plain(d.Error))
				} else {
					tb.row(plain(d.Name), plain(fmt.Sprintf("%d bytes", d.Bytes)))
				}
			}
			_ = tb.write(t, "  ", 1)
		}
		vsys.row(plain(r.Vsys), plain(fmt.Sprintf("PAN-OS %s, security rules: %d", r.Version, r.Rules)))
	}
	_ = vsys.write(t, "  ", 4)
	printQualifiers(t, s.Qualifiers())
	return t.err
}

func (a *app) snapshotDiffCmd() *cobra.Command {
	var o snapshotDiffOptions
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show what changed between two snapshots of each selected device",
		Long: "Diff compares objects and rules per vsys and shared. By default it compares the\n" +
			"snapshot before latest with latest; --from and --to pick other points in time.",
		Args: args(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error {
			return a.emitRun(a.runSnapshotDiff(c.Context(), o))
		},
	}
	o.sel.bind(cmd, selectOpts{})
	cmd.Flags().StringVar(&o.from, "from", "", "compare from the newest snapshot at or before this time (default: the one before --to)")
	cmd.Flags().StringVar(&o.to, "to", "", "compare to the newest snapshot at or before this time (default: latest)")
	bindLimit(cmd, &o.limit)
	a.bindDetail(cmd)
	return cmd
}

// snapshotDiffAnswer is what changed between two snapshots of each selected device.
type snapshotDiffAnswer struct {
	enveloped[query.DiffInput, query.DiffResult]
}

func (a *app) runSnapshotDiff(ctx context.Context, o snapshotDiffOptions) (answer, error) {
	in := query.DiffInput{Selection: o.sel.input(), From: o.from, To: o.to, ResultLimit: query.ResultLimit{Limit: o.limit}}
	if u := in.Validate(); u != nil {
		return nil, u
	}
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	env, err := a.storeEnv(s)
	if err != nil {
		return nil, err
	}
	e, err := query.SnapshotDiff(ctx, env, in)
	if err != nil {
		return nil, err
	}
	return snapshotDiffAnswer{enveloped[query.DiffInput, query.DiffResult]{e}}, nil
}

func (d snapshotDiffAnswer) Summary() *query.Summary { return d.e.Summary }

func (d snapshotDiffAnswer) SummaryResults() any {
	return query.Summarize(d.e, query.DiffResult.Summary).Results
}

func (d snapshotDiffAnswer) Input() any {
	return d.e.Input.Echo()
}

// Text prints one block per device and one section per scope.
func (d snapshotDiffAnswer) Text(t *textOut) error {
	last := ""
	for _, r := range d.e.Results {
		if r.Device != last {
			last = r.Device
			fmt.Fprintf(t, "%s   %s -> %s\n", t.pal.head(r.Device), r.From, r.To)
			for _, n := range d.e.Notes {
				if n.Device == r.Device {
					fmt.Fprintf(t, "  %s\n", t.pal.dim("note: "+n.Note))
				}
			}
		}
		if len(r.Changes) == 0 {
			fmt.Fprintf(t, "  %-10s no changes\n", r.Scope)
			fmt.Fprintf(t, "    %s\n", r.Answer)
			continue
		}
		fmt.Fprintf(t, "  %s\n", r.Scope)
		fmt.Fprintf(t, "    %s\n", r.Answer)
		var tb table
		for _, c := range r.Changes {
			op := cell{text: string(c.Op)}
			switch c.Op {
			case drift.Added:
				op.style = t.pal.ok
			case drift.Removed:
				op.style = t.pal.bad
			case drift.Changed:
				op.style = t.pal.warn
			}
			if c.Op == drift.Changed {
				tb.row(op, plain(c.Kind), plain(c.Name))
				for _, f := range c.Fields {
					tb.row(plain("  " + fieldLine(f)))
				}
				continue
			}
			tb.row(op, plain(c.Kind), plain(c.Name), plain(changeDetail(c)))
		}
		_ = tb.write(t, "    ", 1)
	}
	// A device with no result left prints no header, so its notes go below.
	shown := map[string]bool{}
	for _, r := range d.e.Results {
		shown[r.Device] = true
	}
	var left []note
	for _, n := range d.e.Notes {
		if !shown[n.Device] {
			left = append(left, n)
		}
	}
	printQualifiers(t, qualifiers{Holes: d.e.Holes}, left...)
	fmt.Fprintln(t, d.e.Summary.Answer)
	return t.err
}

// changeDetail is an added or removed row's last column: the new entry's short
// line, or the old one's for a removal.
func changeDetail(c drift.Change) string {
	if c.Op == drift.Removed {
		return c.Old
	}
	return c.New
}

// fieldLine is one changed setting of a changed entry, on its own line below
// it: negate-destination: no -> yes. An absent side reads (unset). A secret
// changed on both sides reads "changed (secret, not shown)", and a setting
// the schema does not describe "changed (not described by the schema; values
// not shown)"; neither value is ever printed.
func fieldLine(f drift.FieldChange) string {
	if f.Undescribed {
		return f.Path + ": changed (not described by the schema; values not shown)"
	}
	if f.Secret && f.Old != "" && f.New != "" {
		return f.Path + ": changed (secret, not shown)"
	}
	side := func(v string) string {
		if v == "" {
			return "(unset)"
		}
		return v
	}
	return f.Path + ": " + side(f.Old) + " -> " + side(f.New)
}

// firstDevice is the device entry a firewall configuration's vsys sit under.
func firstDevice(cfg *config.Config) string {
	if devs := cfg.Root().Find("devices", "entry"); len(devs) > 0 {
		return devs[0].Attr("name")
	}
	return ""
}
