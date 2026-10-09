// Package estate turns a selection of devices, vsys and a point in time into the
// configurations a question runs against. Every target is keyed by device and vsys
// (spec S6), and a device that cannot be read becomes a hole rather than stopping
// the question (S10). Spec §15 C7 and C8.
package estate

import (
	"fmt"
	"slices"
	"time"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/store"
)

// FileDevice is the device name a target read with --file carries.
const FileDevice = "file"

// Target is one scope a question runs against.
type Target struct {
	Device   string
	Vsys     string
	Scope    config.Scope
	Snapshot *store.Snapshot // nil for a target read from a file
	Config   *config.Config
	Report   config.Report
	// Notes qualify every answer from this target: a stale snapshot, a version gap.
	Notes []string
}

// Hole is a device or vsys that was asked for and could not be answered.
type Hole struct {
	Device string `json:"device"`
	Vsys   string `json:"vsys,omitempty"`
	Reason string `json:"reason"`
}

// When says which snapshot of each device to read.
type When struct {
	At     time.Time     // zero: latest
	MaxAge time.Duration // zero: no age note
	Now    time.Time
	Log    *runlog.Logger // receives which snapshot each device resolved to
}

// Open reads each device's chosen snapshot and returns one target per vsys, in
// device order, and a hole for every device or vsys that could not be read.
func Open(st *store.Store, devices, vsys []string, w When) ([]Target, []Hole) {
	var targets []Target
	var holes []Hole
	for _, d := range devices {
		sn, err := pick(st, d, w.At)
		ts, hs := openSnapshot(d, sn, err, vsys, w)
		targets = append(targets, ts...)
		holes = append(holes, hs...)
	}
	return targets, holes
}

// OpenSnapshot reads one snapshot by its id, as Open reads a device's chosen
// one. A snapshot without a configuration is a hole: it never falls back to an
// older one, so a caller that pinned a snapshot reads exactly that one.
func OpenSnapshot(st *store.Store, device, id string, vsys []string, w When) ([]Target, []Hole) {
	sn, err := st.Get(device, id)
	if err == nil {
		_, err = sn.ConfigPath()
	}
	return openSnapshot(device, sn, err, vsys, w)
}

// openSnapshot loads a picked snapshot; err says why none could be picked.
func openSnapshot(d string, sn store.Snapshot, err error, vsys []string, w When) ([]Target, []Hole) {
	if err != nil {
		w.Log.Warnf(runlog.TagSnap, "%s: hole: %v", d, err)
		return nil, []Hole{{Device: d, Reason: err.Error()}}
	}
	cfg, rep, err := config.Load(sn.Path(store.ConfigDoc))
	if err != nil {
		w.Log.Warnf(runlog.TagSnap, "%s: hole: %v", d, err)
		return nil, []Hole{{Device: d, Reason: err.Error()}}
	}
	w.Log.Infof(runlog.TagSnap, "%s: snapshot %s taken %s, PAN-OS %s read with the %s schema",
		d, sn.ID, sn.Meta.TakenAt.Format(time.RFC3339), cfg.Version(), cfg.DigestVersion())
	var notes []string
	if age := w.Now.Sub(sn.Meta.TakenAt); w.MaxAge > 0 && age > w.MaxAge {
		notes = append(notes, StaleNote(sn.ID, age, w.MaxAge))
	}
	ts, hs := scopes(d, &sn, cfg, rep, vsys, notes)
	for _, h := range hs {
		w.Log.Warnf(runlog.TagSnap, "%s/%s: hole: %s", h.Device, h.Vsys, h.Reason)
	}
	return ts, hs
}

// OpenFile reads one configuration file with no inventory or store.
func OpenFile(path string, vsys []string, log *runlog.Logger) ([]Target, []Hole, error) {
	cfg, rep, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	log.Infof(runlog.TagSnap, "file %s: PAN-OS %s read with the %s schema", path, cfg.Version(), cfg.DigestVersion())
	ts, hs := scopes(FileDevice, nil, cfg, rep, vsys, nil)
	return ts, hs, nil
}

func pick(st *store.Store, device string, at time.Time) (store.Snapshot, error) {
	if at.IsZero() {
		return st.Latest(device)
	}
	return st.AtOrBefore(device, at)
}

// scopes returns a target per vsys the configuration defines, keeping only the
// asked ones when vsys is not empty. An asked vsys the configuration lacks is a hole.
func scopes(device string, sn *store.Snapshot, cfg *config.Config, rep config.Report,
	vsys, notes []string,
) ([]Target, []Hole) {
	have := resolve.Vsyses(cfg)
	if rep.VersionGap != "" {
		notes = append(notes, rep.VersionGap)
	}
	want := map[string]bool{}
	for _, v := range vsys {
		want[v] = true
	}
	missing := map[string]bool{}
	for v := range want {
		missing[v] = true
	}
	var out []Target
	for _, v := range have {
		if len(want) > 0 && !want[v] {
			continue
		}
		delete(missing, v)
		out = append(out, Target{
			Device: device, Vsys: v, Scope: config.Scope{Sort: config.ScopeVsys, Name: v},
			Snapshot: sn, Config: cfg, Report: rep, Notes: notes,
		})
	}
	var holes []Hole
	names := make([]string, 0, len(missing))
	for v := range missing {
		names = append(names, v)
	}
	slices.Sort(names)
	for _, v := range names {
		holes = append(holes, Hole{Device: device, Vsys: v, Reason: fmt.Sprintf("no vsys %s; it has %v", v, have)})
	}
	return out, holes
}

// StaleNote is the note on a target whose snapshot is older than the limit.
func StaleNote(id string, age, limit time.Duration) string {
	return fmt.Sprintf("snapshot %s is %s old, past the %s limit", id, age.Round(time.Minute), limit)
}

// ParseAt reads a --at time: a snapshot id (2026-09-28T07-15-37Z), an RFC 3339 time,
// or a date, which means the end of that day in UTC.
func ParseAt(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02T15-04-05Z", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.Add(24*time.Hour - time.Second), nil
	}
	return time.Time{}, fmt.Errorf("--at %q: want a snapshot id, an RFC 3339 time, or a date like 2026-09-23", s)
}
