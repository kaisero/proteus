package main

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/panos-analyst/estate"
	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/runlog"
	"github.com/okaiser/panos-analyst/search"
)

func (a *app) searchCmd() *cobra.Command {
	var sel selection
	var exact, within, contains, direct bool
	var kinds, fields, show []string
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
			q := search.Query{Term: argv[0], Kinds: kinds, Fields: fields, Direct: direct}
			modes := 0
			for m, on := range map[search.Mode]bool{search.Exact: exact, search.Within: within, search.Contains: contains} {
				if on {
					q.Mode = m
					modes++
				}
			}
			if modes > 1 {
				return usageErr("--exact, --within and --contains exclude each other")
			}
			for _, st := range show {
				stage, ok := showNames[st]
				if !ok {
					return usageErr("--show %q: want objects, groups, refs or literals", st)
				}
				q.Show = append(q.Show, stage)
			}
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
				search.Finding
				Scope string `json:"scope"`
			}
			users, err := a.userSnapshot()
			if err != nil {
				return err
			}
			var results []result
			byTarget := make([][]search.Finding, len(ts))
			for i, t := range ts {
				q.Providers = index.Providers{Users: users}
				if t.Snapshot != nil {
					if z, err := t.Snapshot.Zones(); err == nil {
						q.Providers.Zones = z
					}
				}
				idx, err := index.For(t.Config, t.Scope)
				if err != nil {
					holes = append(holes, estate.Hole{Device: t.Device, Vsys: t.Vsys, Reason: err.Error()})
					continue
				}
				fs, err := search.Run(t.Config, idx, q)
				if err != nil {
					return usageErr("%v", err)
				}
				byTarget[i] = fs
				a.log.Infof(runlog.TagFind, "%s/%s: %d findings for %q (%s)", t.Device, t.Vsys, len(fs), q.Term, modeName(q))
				for _, f := range fs {
					a.log.Debugf(runlog.TagFind, "%s/%s: %s %s %s %s", t.Device, t.Vsys, f.Stage, f.Kind, f.Name, detail(f))
					results = append(results, result{target: targetOf(t), Finding: f, Scope: f.Scope.String()})
				}
			}
			un, notes := qualifiers(ts)
			if s.output == "json" {
				in := map[string]any{"term": q.Term, "mode": modeName(q), "kinds": kinds, "fields": fields, "show": show, "direct": direct, "selection": sel.input()}
				if results == nil {
					results = []result{}
				}
				if err := writeJSON(a.stdout, envelope{Command: "search", Input: in, Results: results, Holes: holes, Unresolved: un, Notes: notes}); err != nil {
					return err
				}
				return finish(holes, un)
			}
			fmt.Fprintf(a.stdout, "search %s (%s)\n\n", q.Term, modeName(q))
			with, without := 0, 0
			for i, t := range ts {
				if len(byTarget[i]) == 0 {
					without++
					continue
				}
				with++
				fmt.Fprintln(a.stdout, header(t, a.now()))
				printNotes(a, t)
				for _, f := range byTarget[i] {
					fmt.Fprintf(a.stdout, "  %-10s %-20s %-24s %s\n", f.Stage, f.Kind, f.Name, detail(f))
				}
			}
			printQualifiers(a, holes, un, notes)
			fmt.Fprintf(a.stdout, "%d with results, %d without, %d holes\n", with, without, len(holes))
			return finish(holes, un)
		},
	}
	sel.bind(cmd.Flags(), true)
	f := cmd.Flags()
	f.BoolVar(&exact, "exact", false, "the value equals the term")
	f.BoolVar(&within, "within", false, "the value lies inside the term (addresses, prefixes, ranges)")
	f.BoolVar(&contains, "contains", false, "the value or name holds the term as text; not a match")
	f.StringSliceVar(&kinds, "kind", nil, "only objects and groups of these kinds")
	f.StringSliceVar(&fields, "field", nil, "only references and literals from these fields")
	f.StringSliceVar(&show, "show", nil, "only these stages: objects, groups, refs, literals")
	f.BoolVar(&direct, "direct", false, "groups one level up only")
	return cmd
}

// portTerm is a port, bare or with its protocol: 443, tcp/443.
var portTerm = regexp.MustCompile(`^((tcp|udp|sctp)/)?[0-9]+$`)

// showNames are the --show values of spec §15 C6.
var showNames = map[string]search.Stage{
	"objects": search.StageObject, "groups": search.StageGroup,
	"refs": search.StageReference, "literals": search.StageLiteral,
}

// userSnapshot reads PANOS_USERS, the user-to-group mapping a configuration does
// not hold. None set is no mapping.
func (a *app) userSnapshot() (index.UserDirectory, error) {
	path := a.getenv("PANOS_USERS")
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("PANOS_USERS: %w", err)
	}
	defer func() { _ = f.Close() }()
	snap, err := index.LoadUserSnapshot(f)
	if err != nil {
		return nil, fmt.Errorf("PANOS_USERS: %w", err)
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

// printNotes prints a target's notes under its header. A version gap is left for
// printQualifiers, because it makes the answer incomplete rather than qualifying it.
func printNotes(a *app, t estate.Target) {
	for _, n := range t.Notes {
		if n != t.Report.VersionGap {
			fmt.Fprintf(a.stdout, "  note: %s\n", n)
		}
	}
}

// printQualifiers prints holes, unresolved entries and notes after an answer.
func printQualifiers(a *app, holes []estate.Hole, un []unresolved, notes []note) {
	for _, h := range holes {
		fmt.Fprintf(a.stdout, "hole: %s: %s\n", where(h.Device, h.Vsys), h.Reason)
	}
	for _, u := range un {
		fmt.Fprintf(a.stdout, "unresolved: %s: %s\n", where(u.Device, u.Vsys), u.Reason)
	}
	if len(holes)+len(un) > 0 {
		fmt.Fprintln(a.stdout)
	}
	_ = notes // notes print under each target's header
}

func where(device, vsys string) string {
	if vsys == "" {
		return device
	}
	return device + "/" + vsys
}

// input records the selection for a JSON envelope.
func (sel selection) input() map[string]any {
	in := map[string]any{}
	if len(sel.devices) > 0 {
		in["device"] = sel.devices
	}
	if len(sel.labels) > 0 {
		in["label"] = sel.labels
	}
	if len(sel.vsys) > 0 {
		in["vsys"] = sel.vsys
	}
	if sel.file != "" {
		in["file"] = sel.file
	}
	if sel.at != "" {
		in["at"] = sel.at
	}
	if sel.fresh {
		in["fresh"] = true
	}
	return in
}
