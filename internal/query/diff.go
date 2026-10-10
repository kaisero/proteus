package query

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/drift"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/store"
)

// DiffInput is snapshot diff: what changed between two snapshots of each
// selected device.
type DiffInput struct {
	// Selection names the devices and, optionally, the vsys. A diff reads the
	// store: a file, a time and a fresh fetch are refused.
	Selection Selection `json:"selection" jsonschema:"the devices and, optionally, the vsys to compare"`
	// From and To are points in time; "" compares the snapshot before To with
	// To, and To "" is the latest.
	From string `json:"from,omitempty" jsonschema:"the older point in time; empty for the snapshot before the newer one"`
	To   string `json:"to,omitempty" jsonschema:"the newer point in time; empty for the latest"`
	ResultLimit
}

// Validate holds the diff's input rules: the store's devices only, picked by
// From and To rather than one time, each read as at is, and no limit below
// zero.
func (in DiffInput) Validate() *UsageError {
	for _, f := range []struct {
		given bool
		flag  string
	}{{in.Selection.File != "", "file"}, {in.Selection.At != "", "at"}, {in.Selection.Fresh, "fresh"}} {
		if f.given {
			return usage(fmt.Sprintf("--%s: snapshot diff compares stored snapshots; pick them with --from and --to", f.flag),
				f.flag+": snapshot diff compares stored snapshots; pick them with from and to")
		}
	}
	if _, _, u := in.times(); u != nil {
		return u
	}
	return in.checkLimit()
}

// times reads From and To; the zero time is none.
func (in DiffInput) times() (from, to time.Time, u *UsageError) {
	if from, u = parseTime("from", in.From); u != nil {
		return from, to, u
	}
	to, u = parseTime("to", in.To)
	return from, to, u
}

// DiffResult is what changed in one scope of one device.
type DiffResult struct {
	Answer  string         `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Device  string         `json:"device" jsonschema:"the device name"`
	From    string         `json:"from" jsonschema:"the older snapshot ID"`
	To      string         `json:"to" jsonschema:"the newer snapshot ID"`
	Scope   string         `json:"scope" jsonschema:"the configuration scope the result came from"`
	Changes []drift.Change `json:"changes" jsonschema:"what was added, removed or changed"`
}

// SnapshotDiff compares two snapshots of each selected device, per scope. A
// device without two snapshots to compare, or whose configuration cannot be
// read, is a hole. The summary counts the scopes compared and the devices with
// and without a change. A limit keeps the first scopes over all devices.
func SnapshotDiff(ctx context.Context, env Env, in DiffInput) (Envelope[DiffInput, DiffResult], error) {
	var none Envelope[DiffInput, DiffResult]
	if u := in.Validate(); u != nil {
		return none, u
	}
	if env.Inventory == nil {
		return none, errNoInventory
	}
	names, err := env.Inventory.Select(in.Selection.Device, in.Selection.Label)
	if err != nil {
		return none, usageOf(err, err.Error(), "")
	}
	if env.Store == nil {
		return none, errNoStore
	}
	from, to, _ := in.times() // Validate has read them
	e := envelope[DiffInput, DiffResult]("snapshot diff", in)
	e.Results, e.Summary = []DiffResult{}, &Summary{}
	compared := 0
	for _, d := range names {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		older, newer, err := pair(env.Store, d, from, to)
		if err != nil {
			e.Holes = append(e.Holes, estate.NewHole(d, "", reason.New(estate.GapOf(err), err.Error())))
			continue
		}
		e.Read = append(e.Read, d+"@"+older.ID, d+"@"+newer.ID)
		// After an HA failover the entry's snapshots come from the other member,
		// whose configuration is synced but not identical.
		if was, now := older.Meta.Serial, newer.Meta.Serial; was != "" && now != "" && was != now {
			e.Notes = append(e.Notes, NoteOf(d, "", reason.New("note.serial-changed", fmt.Sprintf(
				"the snapshots come from different firewalls (serial %s, then %s), as after an HA failover; settings an HA pair does not sync show as changes", was, now))))
		}
		was, err1 := env.configs().Config(older)
		now, err2 := env.configs().Config(newer)
		if err1 != nil || err2 != nil {
			e.Holes = append(e.Holes, estate.NewHole(d, "", reason.New(configGap(older, newer), fmt.Sprintf("unreadable configuration: %v %v", err1, err2))))
			continue
		}
		before, after := was.Config, now.Config
		changed := false
		for _, sc := range diffScopes(before, after, in.Selection.Vsys) {
			ch := drift.Compare(before, after, sc)
			if ch == nil {
				ch = []drift.Change{}
			}
			changed = changed || len(ch) > 0
			e.Results = append(e.Results, DiffResult{Answer: DiffAnswer(d, sc.String(), ch), Device: d, From: older.ID, To: newer.ID, Scope: sc.String(), Changes: ch})
		}
		compared++
		if changed {
			e.Summary.With++
		}
	}
	slices.Sort(e.Read)
	e.Summary.Found, e.Summary.Without = len(e.Results), compared-e.Summary.With
	e.Summary.Answer = diffCount(e.Summary, len(e.Holes))
	cut(&e, in.ResultLimit, "device")
	return e, nil
}

// pair picks the two snapshots of a device to compare. A zero to is the
// latest; a zero from is the snapshot before the newer one.
func pair(st *store.Store, device string, from, to time.Time) (store.Snapshot, store.Snapshot, error) {
	var newer store.Snapshot
	var err error
	if to.IsZero() {
		newer, err = st.Latest(device)
	} else {
		newer, err = st.AtOrBefore(device, to)
	}
	if err != nil {
		return newer, newer, err
	}
	if !from.IsZero() {
		older, err := st.AtOrBefore(device, from)
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
		for _, v := range resolve.Vsyses(cfg) {
			seen[v] = true
		}
	}
	var names []string
	for v := range seen {
		if len(want) == 0 || slices.Contains(want, v) {
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

// configGap is the kind of a diff's unreadable configuration: missing when a
// snapshot has none, as the store reports it, else a failed read.
func configGap(sns ...store.Snapshot) reason.Code {
	for _, sn := range sns {
		if _, err := sn.ConfigPath(); err != nil {
			return estate.GapOf(err)
		}
	}
	return "gap.load-failed"
}
