package cli

import (
	"context"
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/drift"
	"github.com/okaiser/proteus/internal/estate"
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
		ans.holes = []estate.Hole{{Device: o.device, Reason: err.Error()}}
		return ans, nil
	}
	latest, _ := st.Latest(o.device)
	for _, id := range ids {
		sn, err := st.Get(o.device, id)
		if err != nil {
			return nil, err
		}
		r := snapshotRow{ID: id, Latest: id == latest.ID, SWVersion: sn.Meta.SWVersion, Documents: len(sn.Meta.Documents)}
		for _, d := range sn.Meta.Documents {
			if d.Error != "" {
				r.Failed++
			}
		}
		ans.rows = append(ans.rows, r)
	}
	return ans, nil
}

func (l snapshotListAnswer) Command() string        { return "snapshot list" }
func (l snapshotListAnswer) Input() any             { return snapshotListInput{Device: l.device} }
func (l snapshotListAnswer) Results() any           { return l.rows }
func (l snapshotListAnswer) Qualifiers() qualifiers { return qualifiers{Holes: l.holes} }

func (l snapshotListAnswer) Text(t *textOut) error {
	for _, r := range l.rows {
		mark := " "
		if r.Latest {
			mark = "*"
		}
		fmt.Fprintf(t, "%s %s  PAN-OS %-8s %d documents, %d failed\n", mark, r.ID, r.SWVersion, r.Documents, r.Failed)
	}
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
	o.sel.bind(cmd, true)
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
	s, err := a.settings(o.sel.file == "")
	if err != nil {
		return nil, err
	}
	ts, holes, err := a.targets(ctx, o.sel, s)
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
	ans.un, ans.notes = targetQualifiers(ts)
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
	for i, r := range s.rows {
		if r.Device != last {
			last = r.Device
			fmt.Fprintf(t, "%s   %s\n", r.Device, source(s.ts[i], t.now))
			printNotes(t, s.ts[i])
			if r.Host != "" {
				fmt.Fprintf(t, "  %s, %s, serial %s\n", r.Host, r.Model, r.Serial)
			}
			if r.From != "" {
				fmt.Fprintf(t, "  fetched from the active HA peer %s\n", r.From)
			}
			for _, d := range r.Document {
				if d.Error != "" {
					fmt.Fprintf(t, "  %-12s FAILED  %s\n", d.Name, d.Error)
				} else {
					fmt.Fprintf(t, "  %-12s %8d bytes\n", d.Name, d.Bytes)
				}
			}
		}
		fmt.Fprintf(t, "  %-8s PAN-OS %s, security rules: %d\n", r.Vsys, r.Version, r.Rules)
	}
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
			if o.sel.file != "" || o.sel.at != "" {
				return usageErr("diff compares stored snapshots; use --from and --to, not --file or --at")
			}
			return a.emitRun(a.runSnapshotDiff(c.Context(), o))
		},
	}
	o.sel.bind(cmd, false)
	cmd.Flags().StringVar(&o.from, "from", "", "compare from the newest snapshot at or before this time (default: the one before --to)")
	cmd.Flags().StringVar(&o.to, "to", "", "compare to the newest snapshot at or before this time (default: latest)")
	return cmd
}

// diffResult is what changed in one scope of one device.
type diffResult struct {
	Device  string         `json:"device"`
	From    string         `json:"from"`
	To      string         `json:"to"`
	Scope   string         `json:"scope"`
	Changes []drift.Change `json:"changes"`
}

// snapshotDiffAnswer is what changed between two snapshots of each selected device.
type snapshotDiffAnswer struct {
	o       snapshotDiffOptions
	results []diffResult
	holes   []estate.Hole
	notes   []note
}

func (a *app) runSnapshotDiff(ctx context.Context, o snapshotDiffOptions) (answer, error) {
	s, err := a.settings(true)
	if err != nil {
		return nil, err
	}
	names, err := s.inv.Select(o.sel.devices, o.sel.labels)
	if err != nil {
		return nil, usageErr("%w", err)
	}
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return nil, err
	}
	ans := snapshotDiffAnswer{o: o, results: []diffResult{}}
	for _, d := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		older, newer, err := pair(st, d, o.from, o.to)
		if err != nil {
			ans.holes = append(ans.holes, estate.Hole{Device: d, Reason: err.Error()})
			continue
		}
		// After an HA failover the entry's snapshots come from the other member,
		// whose configuration is synced but not identical.
		if was, now := older.Meta.Serial, newer.Meta.Serial; was != "" && now != "" && was != now {
			ans.notes = append(ans.notes, note{Device: d, Note: fmt.Sprintf(
				"the snapshots come from different firewalls (serial %s, then %s), as after an HA failover; settings an HA pair does not sync show as changes", was, now)})
		}
		before, _, err1 := config.Load(older.Path(store.ConfigDoc))
		after, _, err2 := config.Load(newer.Path(store.ConfigDoc))
		if err1 != nil || err2 != nil {
			ans.holes = append(ans.holes, estate.Hole{Device: d, Reason: fmt.Sprintf("unreadable configuration: %v %v", err1, err2)})
			continue
		}
		for _, sc := range diffScopes(before, after, o.sel.vsys) {
			ch := drift.Compare(before, after, sc)
			if ch == nil {
				ch = []drift.Change{}
			}
			ans.results = append(ans.results, diffResult{Device: d, From: older.ID, To: newer.ID, Scope: sc.String(), Changes: ch})
		}
	}
	return ans, nil
}

func (d snapshotDiffAnswer) Command() string { return "snapshot diff" }
func (d snapshotDiffAnswer) Input() any {
	return snapshotDiffInput{Selection: d.o.sel.input(), From: d.o.from, To: d.o.to}
}
func (d snapshotDiffAnswer) Results() any { return d.results }
func (d snapshotDiffAnswer) Qualifiers() qualifiers {
	return qualifiers{Holes: d.holes, Notes: d.notes}
}

// Text prints one block per device and one section per scope.
func (d snapshotDiffAnswer) Text(t *textOut) error {
	last := ""
	for _, r := range d.results {
		if r.Device != last {
			last = r.Device
			fmt.Fprintf(t, "%s   %s -> %s\n", r.Device, r.From, r.To)
			for _, n := range d.notes {
				if n.Device == r.Device {
					fmt.Fprintf(t, "  note: %s\n", n.Note)
				}
			}
		}
		if len(r.Changes) == 0 {
			fmt.Fprintf(t, "  %-10s no changes\n", r.Scope)
			continue
		}
		fmt.Fprintf(t, "  %s\n", r.Scope)
		for _, c := range r.Changes {
			detail := c.New
			switch c.Op {
			case drift.Removed:
				detail = c.Old
			case drift.Changed:
				detail = c.Old + " -> " + c.New
			}
			fmt.Fprintf(t, "    %-8s %-20s %-24s %s\n", c.Op, c.Kind, c.Name, detail)
		}
	}
	printQualifiers(t, qualifiers{Holes: d.holes})
	return t.err
}

// pair picks the two snapshots of a device to compare.
func pair(st *store.Store, device, from, to string) (store.Snapshot, store.Snapshot, error) {
	var newer store.Snapshot
	var err error
	if to == "" {
		newer, err = st.Latest(device)
	} else {
		t, perr := estate.ParseAt(to)
		if perr != nil {
			return newer, newer, perr
		}
		newer, err = st.AtOrBefore(device, t)
	}
	if err != nil {
		return newer, newer, err
	}
	if from != "" {
		t, perr := estate.ParseAt(from)
		if perr != nil {
			return newer, newer, perr
		}
		older, err := st.AtOrBefore(device, t)
		return older, newer, err
	}
	older, err := st.AtOrBefore(device, newer.Meta.TakenAt.Add(-1))
	if err != nil {
		return older, newer, fmt.Errorf("only one snapshot with a configuration at or before %s; nothing to compare", newer.ID)
	}
	return older, newer, nil
}

// diffScopes is shared and every vsys either configuration has, or the asked vsys.
func diffScopes(before, after *config.Config, want []string) []config.Scope {
	seen := map[string]bool{}
	for _, cfg := range []*config.Config{before, after} {
		vs := resolve.Vsyses(cfg)
		for _, v := range vs {
			seen[v] = true
		}
	}
	var names []string
	for v := range seen {
		if len(want) == 0 || contains(want, v) {
			names = append(names, v)
		}
	}
	slices.Sort(names)
	out := []config.Scope{{Sort: config.ScopeShared}}
	for _, v := range names {
		out = append(out, config.Scope{Sort: config.ScopeVsys, Name: v})
	}
	return out
}

func contains(xs []string, x string) bool {
	return slices.Contains(xs, x)
}

// firstDevice is the device entry a firewall configuration's vsys sit under.
func firstDevice(cfg *config.Config) string {
	if devs := cfg.Root().Find("devices", "entry"); len(devs) > 0 {
		return devs[0].Attr("name")
	}
	return ""
}
