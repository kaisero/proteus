package query

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/drift"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/identity"
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
	_, _, u := in.validate()
	return u
}

// validate holds Validate's rules and gives From and To as read.
func (in DiffInput) validate() (from, to time.Time, u *UsageError) {
	for _, f := range []struct {
		given bool
		flag  string
	}{{in.Selection.File != "", "file"}, {in.Selection.At != "", "at"}, {in.Selection.Fresh, "fresh"}} {
		if f.given {
			return from, to, usage(fmt.Sprintf("--%s: snapshot diff compares stored snapshots; pick them with --from and --to", f.flag),
				f.flag+": snapshot diff compares stored snapshots; pick them with from and to")
		}
	}
	if from, u = parseTime("from", in.From); u != nil {
		return from, to, u
	}
	if to, u = parseTime("to", in.To); u != nil {
		return from, to, u
	}
	return from, to, in.checkLimit()
}

// DiffResult is what changed in one scope of one device.
type DiffResult struct {
	Answer  string         `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Device  string         `json:"device" jsonschema:"the device name"`
	From    string         `json:"from" jsonschema:"the older snapshot ID"`
	To      string         `json:"to" jsonschema:"the newer snapshot ID"`
	Scope   string         `json:"scope" jsonschema:"the configuration scope the result came from"`
	Changes []drift.Change `json:"changes" jsonschema:"what was added, removed or changed; with a limit, the scope where the limit falls holds only its first changes"`

	// whole is every change of a scope the limit shortened; nil when Changes
	// is whole. The summary form counts it.
	whole []drift.Change
}

// SnapshotDiff compares two snapshots of each selected device, per scope, and
// their identity data in the scope identity (identityDiff). A device without
// two snapshots to compare, or whose configuration cannot be read, is a hole. The summary counts the changes and the devices with and
// without a change. A limit keeps the first changes over all devices.
func SnapshotDiff(ctx context.Context, env Env, in DiffInput) (Envelope[DiffInput, DiffResult], error) {
	var none Envelope[DiffInput, DiffResult]
	from, to, u := in.validate()
	if u != nil {
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
	e := envelope[DiffInput, DiffResult]("snapshot diff", in)
	e.Results, e.Summary = []DiffResult{}, &Summary{}
	compared := 0
	ids := env.identitySource()
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
		sides := []store.Snapshot{newer, older}
		if older.ID == newer.ID { // --from at or after the snapshot --to picks
			sides = sides[:1]
		}
		for _, sn := range sides {
			if n, ok := estate.SkipNote(sn); ok {
				e.Notes = append(e.Notes, NoteOf(d, "", n))
			}
		}
		// After an HA failover the entry's snapshots come from the other member,
		// whose configuration is synced but not identical.
		if was, now := older.Meta.Serial, newer.Meta.Serial; was != "" && now != "" && was != now {
			e.Notes = append(e.Notes, NoteOf(d, "", reason.New("note.serial-changed", fmt.Sprintf(
				"the snapshots come from different firewalls (serial %s, then %s), as after an HA failover; settings an HA pair does not sync show as changes", was, now))))
		}
		// The diff says only that the content version changed; it does not
		// compare applications (spec 2026-10-16 §5.3).
		if was, now := older.Meta.AppVersion, newer.Meta.AppVersion; was != "" && now != "" && was != now {
			e.Notes = append(e.Notes, NoteOf(d, "", reason.New("note.app-version-changed",
				fmt.Sprintf("content version %s → %s", was, now))))
		}
		// Across a change of the configuration source, template values show as
		// added and the uncommitted changes of an export as removed, once
		// (spec 2026-10-17 §2.4).
		if was, now := configSource(older.Meta), configSource(newer.Meta); was != now {
			e.Notes = append(e.Notes, NoteOf(d, "", reason.New("note.config-source-changed", fmt.Sprintf(
				"configuration source %s → %s: template values and uncommitted changes show as added or removed once", was, now))))
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
			e.Summary.Found += len(ch)
			e.Results = append(e.Results, DiffResult{Answer: DiffAnswer(d, sc.String(), ch), Device: d, From: older.ID, To: newer.ID, Scope: sc.String(), Changes: ch})
		}
		ch, notes, ok := identityDiff(ids, older, newer)
		for _, n := range notes {
			e.Notes = append(e.Notes, NoteOf(d, "", n))
		}
		if ok {
			changed = changed || len(ch) > 0
			e.Summary.Found += len(ch)
			e.Results = append(e.Results, DiffResult{Answer: DiffAnswer(d, identityScope, ch), Device: d, From: older.ID, To: newer.ID, Scope: identityScope, Changes: ch})
		}
		compared++
		if changed {
			e.Summary.With++
		}
	}
	slices.Sort(e.Read)
	e.Summary.Without = compared - e.Summary.With
	e.Summary.Answer = diffCount(e.Summary, len(e.Holes))
	cutChanges(&e, in.ResultLimit)
	return e, nil
}

// identityScope is the scope of the identity result of a diff (spec
// 2026-10-17 §6.3, PD15).
const identityScope = "identity"

// identityDiff compares the identity data of two snapshots (spec 2026-10-17
// §6.3, SG8). With data in both, ok holds and the changes come from
// identityChanges, and a part missing in either snapshot gives
// note.identity-not-compared, which names the part: identity.Diff does not
// compare what that part judges (PD19). With data in one snapshot only, ok
// does not hold, and the note says so: every user would show as added. With
// none, there is nothing. A file that does not load gives
// gap.no-user-directory with the cause, and counts as no data (PD11).
func identityDiff(src estate.IdentitySource, older, newer store.Snapshot) ([]drift.Change, []reason.Reason, bool) {
	var notes []reason.Reason
	load := func(sn store.Snapshot) *identity.Data {
		if sn.IdentityPath() == "" {
			return nil
		}
		d, err := src.Identity(sn.IdentityPath())
		if err != nil {
			notes = append(notes, reason.New("gap.no-user-directory", fmt.Sprintf("no identity data in snapshot %s: %v", sn.ID, err)))
			return nil
		}
		return d
	}
	before, after := load(older), load(newer)
	switch {
	case before == nil && after == nil:
		return nil, notes, false
	case before == nil || after == nil:
		without := older.ID
		if after == nil {
			without = newer.ID
		}
		return nil, append(notes, reason.New("note.identity-not-compared", fmt.Sprintf(
			"the snapshot %s has no identity data, so users and sources are not compared", without))), false
	}
	for _, p := range []struct{ part, what string }{
		{identity.PartUserGroups, "users"},
		{identity.PartUserNames, "users"},
		{identity.PartLDAP, "LDAP sources"},
		{identity.PartCIE, "CIE sources"},
	} {
		var in []string
		for _, side := range []struct {
			d  *identity.Data
			id string
		}{{before, older.ID}, {after, newer.ID}} {
			if !side.d.Complete(p.part) && !slices.Contains(in, side.id) {
				in = append(in, side.id)
			}
		}
		if len(in) > 0 {
			notes = append(notes, reason.New("note.identity-not-compared", fmt.Sprintf(
				"the part %s of the identity data is missing in snapshot %s, so %s are not compared", p.part, strings.Join(in, " and "), p.what)))
		}
	}
	ch := identityChanges(before, after)
	if ch == nil {
		ch = []drift.Change{}
	}
	return ch, notes, true
}

// identityChanges gives the identity changes from before to after as drift
// changes (spec 2026-10-17 §6.3, PD15): kind identity user, a user that came
// or went with its groups and DUGs, or a user whose groups changed, one field
// group per group gained or lost; kind identity source, a source that came or
// went with its line, or a source whose group count changed. identity.Diff
// never compares mappings (D9). A nil side gives nil.
func identityChanges(before, after *identity.Data) []drift.Change {
	var out []drift.Change
	for _, c := range identity.Diff(before, after) {
		dc := drift.Change{Op: drift.Op(c.Op), Kind: "identity " + c.Kind, Name: c.Name}
		switch {
		case c.Kind == "user" && dc.Op == drift.Changed:
			for _, g := range c.Added {
				dc.Fields = append(dc.Fields, drift.FieldChange{Path: "group", New: g})
			}
			for _, g := range c.Removed {
				dc.Fields = append(dc.Fields, drift.FieldChange{Path: "group", Old: g})
			}
		case c.Kind == "user":
			// A DN holds commas, so the groups of the line part with "; ".
			dc.New, dc.Old = strings.Join(c.Added, "; "), strings.Join(c.Removed, "; ")
		case dc.Op == drift.Changed:
			dc.Fields = []drift.FieldChange{{Path: "groups", Old: c.Old, New: c.New}}
		default:
			dc.Old, dc.New = c.Old, c.New
		}
		out = append(out, dc)
	}
	return out
}

// configSource is where a snapshot's configuration came from. A snapshot
// without the key exported it: every fetch before the switch did (spec
// 2026-10-17 §2.4).
func configSource(m store.Meta) string {
	if m.ConfigSource == "" {
		return "export"
	}
	return m.ConfigSource
}

// cutChanges keeps the first Limit changes of a complete answer, in its
// order, over all scopes and devices: a unit of snapshot diff is one change.
// The scope where the limit falls keeps its first changes, and its answer
// keeps its whole counts and adds how many it shows; the later scopes drop
// out. Holes and notes stay whole.
func cutChanges(e *Envelope[DiffInput, DiffResult], l ResultLimit) {
	all := e.Summary.Found
	if l.Limit == 0 || all <= l.Limit {
		return
	}
	kept := 0
	for i := range e.Results {
		r := &e.Results[i]
		if kept+len(r.Changes) < l.Limit {
			kept += len(r.Changes)
			continue
		}
		if n := l.Limit - kept; n < len(r.Changes) {
			r.whole, r.Changes = r.Changes, r.Changes[:n]
			r.Answer += fmt.Sprintf(" (%d of %d changes shown)", n, len(r.whole))
		}
		e.Results = e.Results[:i+1]
		break
	}
	leftOut(e.Summary, l.Limit, all, "device")
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
	// AtOrBefore passes over a damaged snapshot, so the one before the newer is
	// the next one that can be read.
	older, err := st.AtOrBefore(device, newer.Meta.TakenAt.Add(-1))
	switch {
	case errors.Is(err, store.ErrNoSnapshot):
		return older, newer, fmt.Errorf("only one snapshot with a configuration at or before %s; nothing to compare", newer.ID)
	case err != nil:
		return older, newer, err
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
