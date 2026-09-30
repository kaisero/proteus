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

func (a *app) snapshotListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <device>",
		Short: "List a device's stored snapshots, newest first; * marks latest",
		Args:  args(cobra.ExactArgs(1)),

		ValidArgsFunction: a.completeOneDevice,
		RunE:              func(_ *cobra.Command, argv []string) error { return a.runSnapshotList(argv[0]) },
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

func (a *app) runSnapshotList(device string) error {
	s, err := a.settings(false)
	if err != nil {
		return err
	}
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return err
	}
	ids, err := st.List(device)
	if err != nil {
		return err
	}
	latest, _ := st.Latest(device)
	var rows []snapshotRow
	for _, id := range ids {
		sn, err := st.Get(device, id)
		if err != nil {
			return err
		}
		r := snapshotRow{ID: id, Latest: id == latest.ID, SWVersion: sn.Meta.SWVersion, Documents: len(sn.Meta.Documents)}
		for _, d := range sn.Meta.Documents {
			if d.Error != "" {
				r.Failed++
			}
		}
		rows = append(rows, r)
	}
	if a.format == formatJSON {
		return writeJSON(a.stdout, envelope{Command: "snapshot list", Input: snapshotListInput{Device: device}, Results: rows})
	}
	for _, r := range rows {
		mark := " "
		if r.Latest {
			mark = "*"
		}
		fmt.Fprintf(a.stdout, "%s %s  PAN-OS %-8s %d documents, %d failed\n", mark, r.ID, r.SWVersion, r.Documents, r.Failed)
	}
	return nil
}

func (a *app) snapshotShowCmd() *cobra.Command {
	var sel selection
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the snapshots a question would read: version, vsys, rule counts, documents",
		Args:  args(cobra.NoArgs),
		RunE:  func(c *cobra.Command, _ []string) error { return a.runSnapshotShow(c.Context(), sel) },
	}
	sel.bind(cmd, true)
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

func (a *app) runSnapshotShow(ctx context.Context, sel selection) error {
	s, err := a.settings(sel.file == "")
	if err != nil {
		return err
	}
	ts, holes, err := a.targets(ctx, sel, s, a.stderr)
	if err != nil {
		return err
	}
	var rows []showRow
	for _, t := range ts {
		r := showRow{target: targetOf(t), Version: t.Config.DetailVersion()}
		if tg, err := resolve.TargetFor(t.Config, firstDevice(t.Config), t.Vsys); err == nil {
			r.Rules = len(tg.Rules(resolve.Security))
		}
		if t.Snapshot != nil {
			m := t.Snapshot.Meta
			r.Host, r.Model, r.Serial, r.From, r.Document = m.Host, m.Model, m.Serial, m.FetchedFrom, m.Documents
		}
		rows = append(rows, r)
	}
	un, notes := targetQualifiers(ts)
	if a.format == formatJSON {
		if err := writeJSON(a.stdout, envelope{
			Command: "snapshot show", Input: sel.input(), Results: rows, Holes: holes, Unresolved: un, Notes: notes,
		}); err != nil {
			return err
		}
	} else {
		a.printSnapshotShow(ts, rows)
		printQualifiers(a.stdout, qualifiers{Holes: holes, Unresolved: un, Notes: notes})
	}
	return finish(holes, un)
}

// printSnapshotShow prints one block per device and one line per vsys.
func (a *app) printSnapshotShow(ts []estate.Target, rows []showRow) {
	last := ""
	for i, r := range rows {
		if r.Device != last {
			last = r.Device
			fmt.Fprintf(a.stdout, "%s   %s\n", r.Device, source(ts[i], a.now()))
			printNotes(a.stdout, ts[i])
			if r.Host != "" {
				fmt.Fprintf(a.stdout, "  %s, %s, serial %s\n", r.Host, r.Model, r.Serial)
			}
			if r.From != "" {
				fmt.Fprintf(a.stdout, "  fetched from the active HA peer %s\n", r.From)
			}
			for _, d := range r.Document {
				if d.Error != "" {
					fmt.Fprintf(a.stdout, "  %-12s FAILED  %s\n", d.Name, d.Error)
				} else {
					fmt.Fprintf(a.stdout, "  %-12s %8d bytes\n", d.Name, d.Bytes)
				}
			}
		}
		fmt.Fprintf(a.stdout, "  %-8s PAN-OS %s, security rules: %d\n", r.Vsys, r.Version, r.Rules)
	}
}

func (a *app) snapshotDiffCmd() *cobra.Command {
	var sel selection
	var from, to string
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show what changed between two snapshots of each selected device",
		Long: "Diff compares objects and rules per vsys and shared. By default it compares the\n" +
			"snapshot before latest with latest; --from and --to pick other points in time.",
		Args: args(cobra.NoArgs),
		RunE: func(*cobra.Command, []string) error {
			if sel.file != "" || sel.at != "" {
				return usageErr("diff compares stored snapshots; use --from and --to, not --file or --at")
			}
			return a.runSnapshotDiff(sel, from, to)
		},
	}
	sel.bind(cmd, false)
	cmd.Flags().StringVar(&from, "from", "", "compare from the newest snapshot at or before this time (default: the one before --to)")
	cmd.Flags().StringVar(&to, "to", "", "compare to the newest snapshot at or before this time (default: latest)")
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

func (a *app) runSnapshotDiff(sel selection, from, to string) error {
	s, err := a.settings(true)
	if err != nil {
		return err
	}
	names, err := s.inv.Select(sel.devices, sel.labels)
	if err != nil {
		return usageErr("%w", err)
	}
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return err
	}
	var results []diffResult
	var holes []estate.Hole
	var notes []note
	for _, d := range names {
		older, newer, err := pair(st, d, from, to)
		if err != nil {
			holes = append(holes, estate.Hole{Device: d, Reason: err.Error()})
			continue
		}
		// After an HA failover the entry's snapshots come from the other member,
		// whose configuration is synced but not identical.
		if was, now := older.Meta.Serial, newer.Meta.Serial; was != "" && now != "" && was != now {
			notes = append(notes, note{Device: d, Note: fmt.Sprintf(
				"the snapshots come from different firewalls (serial %s, then %s), as after an HA failover; settings an HA pair does not sync show as changes", was, now)})
		}
		before, _, err1 := config.Load(older.Path(store.ConfigDoc))
		after, _, err2 := config.Load(newer.Path(store.ConfigDoc))
		if err1 != nil || err2 != nil {
			holes = append(holes, estate.Hole{Device: d, Reason: fmt.Sprintf("unreadable configuration: %v %v", err1, err2)})
			continue
		}
		for _, sc := range diffScopes(before, after, sel.vsys) {
			ch := drift.Compare(before, after, sc)
			if ch == nil {
				ch = []drift.Change{}
			}
			results = append(results, diffResult{Device: d, From: older.ID, To: newer.ID, Scope: sc.String(), Changes: ch})
		}
	}
	if a.format == formatJSON {
		in := snapshotDiffInput{Selection: sel.input(), From: from, To: to}
		if err := writeJSON(a.stdout, envelope{Command: "snapshot diff", Input: in, Results: results, Holes: holes, Notes: notes}); err != nil {
			return err
		}
	} else {
		a.printDiff(results, notes)
		printQualifiers(a.stdout, qualifiers{Holes: holes})
	}
	return finish(holes, nil)
}

// printDiff prints one block per device and one section per scope.
func (a *app) printDiff(results []diffResult, notes []note) {
	last := ""
	for _, r := range results {
		if r.Device != last {
			last = r.Device
			fmt.Fprintf(a.stdout, "%s   %s -> %s\n", r.Device, r.From, r.To)
			for _, n := range notes {
				if n.Device == r.Device {
					fmt.Fprintf(a.stdout, "  note: %s\n", n.Note)
				}
			}
		}
		if len(r.Changes) == 0 {
			fmt.Fprintf(a.stdout, "  %-10s no changes\n", r.Scope)
			continue
		}
		fmt.Fprintf(a.stdout, "  %s\n", r.Scope)
		for _, c := range r.Changes {
			detail := c.New
			switch c.Op {
			case drift.Removed:
				detail = c.Old
			case drift.Changed:
				detail = c.Old + " -> " + c.New
			}
			fmt.Fprintf(a.stdout, "    %-8s %-20s %-24s %s\n", c.Op, c.Kind, c.Name, detail)
		}
	}
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
