// Package estate turns a selection of devices, vsys and a point in time into the
// configurations a question runs against. Every target is keyed by device and vsys
// (spec S6), and a device that cannot be read becomes a hole rather than stopping
// the question (S10). Spec §15 C7 and C8.
package estate

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/runlog"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/store"
)

// FileDevice is the device name a target read with --file carries.
const FileDevice = "file"

// AppsFile is the App-ID content file OpenFile reads in the directory of the
// configuration (spec 2026-10-16 §6).
const AppsFile = "apps.xml.gz"

// Target is one scope a question runs against.
type Target struct {
	Device   string
	Vsys     string
	Scope    config.Scope
	Snapshot *store.Snapshot // nil for a target read from a file
	Config   *config.Config
	Report   config.Report
	// Indexes builds the configuration's indexes when the source that loaded
	// it keeps them; nil leaves them to the caller. It is no data of the
	// answer, so JSON leaves it out.
	Indexes Indexes `json:"-"`
	// Apps loads the target's App-ID content data; nil when its snapshot
	// names no content version. AppsPath is the content file it reads, ""
	// for none. A question that needs no application data never calls Apps
	// (spec 2026-10-16 §4.1).
	Apps     func() (*appid.Data, error) `json:"-"`
	AppsPath string                      `json:"-"`
	// Notes qualify every answer from this target: a stale snapshot, a skipped document.
	Notes simulate.Reasons
}

// Hole is a device or vsys that was asked for and could not be answered.
type Hole struct {
	Device string      `json:"device"`
	Vsys   string      `json:"vsys,omitempty"`
	Code   reason.Code `json:"code"` // the kind of Reason
	Reason string      `json:"text"`
}

// NewHole returns a hole for a device and vsys with r's code and text.
func NewHole(device, vsys string, r reason.Reason) Hole {
	return Hole{Device: device, Vsys: vsys, Reason: r.Text, Code: r.Code}
}

// Why returns the hole's code and text as one reason.
func (h Hole) Why() reason.Reason { return reason.Reason{Code: h.Code, Text: h.Reason} }

// GapOf is the code of a failure to read a device's data: a missing
// configuration, a missing snapshot, or a load that failed (spec §12 C10). A
// device whose snapshots all lack a configuration is a missing configuration.
func GapOf(err error) reason.Code {
	var c *codedError
	switch {
	case errors.As(err, &c):
		return c.code
	case errors.Is(err, store.ErrNoConfig):
		return "gap.config-missing"
	case errors.Is(err, store.ErrNoSnapshot):
		return "gap.snapshot-missing"
	}
	return "gap.load-failed"
}

// codedError is a read failure that names its own code.
type codedError struct {
	code reason.Code
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

// coded marks err with code c, which GapOf returns.
func coded(c reason.Code, err error) error {
	return &codedError{code: reason.New(c, "").Code, err: err}
}

// When says which snapshot of each device to read.
type When struct {
	At     time.Time     // zero: latest
	MaxAge time.Duration // zero: no age note
	Now    time.Time
	Log    *runlog.Logger // receives which snapshot each device resolved to
	// Ops reads the devices' operational data; nil reads it from the store on
	// every ask. A server fills it with its cache.
	Ops OpSource
	// Configs loads the snapshots' configurations; nil loads each from the
	// store on every ask. A server fills it with its cache.
	Configs ConfigSource
	// Apps loads the snapshots' App-ID content files; nil loads each from
	// the store on every ask. A question fills it with its memo.
	Apps AppSource
}

// Indexes gives a configuration's indexes: each scope's index of a rulebase.
type Indexes interface {
	Index(sc config.Scope, rb resolve.Rulebase) (*index.Index, error)
}

// Loaded is a snapshot's configuration as a ConfigSource gives it.
type Loaded struct {
	Config *config.Config
	Report config.Report
	// Indexes builds the configuration's indexes; nil leaves them to the
	// caller.
	Indexes Indexes
	// Apps loads the snapshot's App-ID content data; nil loads it with
	// When.Apps from the snapshot's content path.
	Apps func() (*appid.Data, error)
}

// ConfigSource loads a snapshot's configuration. The answer depends only on
// the snapshot (its device and id), so an implementation may cache by them.
// The returned values are shared: a caller must not change them. A source a
// server shares between questions must be safe for concurrent use. Notes do
// not come from it: each question builds them (spec 2026-10-09 §4.8).
type ConfigSource interface {
	Config(sn store.Snapshot) (Loaded, error)
}

// DiskConfigs loads each configuration from the store on every ask.
type DiskConfigs struct{}

// Config implements ConfigSource.
func (DiskConfigs) Config(sn store.Snapshot) (Loaded, error) {
	cfg, rep, err := config.Load(sn.Path(store.ConfigDoc))
	return Loaded{Config: cfg, Report: rep}, err
}

// AppSource loads an App-ID content file. The answer depends only on the
// path, so an implementation may cache by it. The returned data is shared: a
// caller must not change it. A source a server shares between questions must
// be safe for concurrent use.
type AppSource interface {
	Apps(path string) (*appid.Data, error)
}

// DiskApps loads each content file from disk on every ask.
type DiskApps struct{}

// Apps implements AppSource.
func (DiskApps) Apps(path string) (*appid.Data, error) { return appid.Load(path) }

// apps is the source of content files.
func (w When) apps() AppSource {
	if w.Apps == nil {
		return DiskApps{}
	}
	return w.Apps
}

// configs is the source of configurations.
func (w When) configs() ConfigSource {
	if w.Configs == nil {
		return DiskConfigs{}
	}
	return w.Configs
}

// ops is the source of operational data.
func (w When) ops() OpSource {
	if w.Ops == nil {
		return DiskOps{}
	}
	return w.Ops
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
		return nil, []Hole{NewHole(d, "", reason.New(GapOf(err), err.Error()))}
	}
	l, err := w.configs().Config(sn)
	if err != nil {
		w.Log.Warnf(runlog.TagSnap, "%s: hole: %v", d, err)
		return nil, []Hole{NewHole(d, "", reason.New("gap.load-failed", err.Error()))}
	}
	cfg := l.Config
	w.Log.Infof(runlog.TagSnap, "%s: snapshot %s taken %s, PAN-OS %s",
		d, sn.ID, sn.Meta.TakenAt.Format(time.RFC3339), cfg.Version())
	var notes simulate.Reasons
	if n, ok := SkipNote(sn); ok {
		w.Log.Warnf(runlog.TagSnap, "%s: %s", d, n.Text)
		notes = append(notes, n)
	}
	if age := w.Now.Sub(sn.Meta.TakenAt); w.MaxAge > 0 && age > w.MaxAge {
		notes = append(notes, reason.New("note.snapshot-stale", StaleNote(sn.ID, age, w.MaxAge)))
	}
	ts, hs := scopes(d, &sn, cfg, l.Report, l.Indexes, vsys, notes)
	path, apps := sn.ContentPath(), l.Apps
	if apps == nil && path != "" {
		src := w.apps()
		apps = func() (*appid.Data, error) { return src.Apps(path) }
	}
	for i := range ts {
		ts[i].Apps, ts[i].AppsPath = apps, path
	}
	for _, h := range hs {
		w.Log.Warnf(runlog.TagSnap, "%s/%s: hole: %s", h.Device, h.Vsys, h.Reason)
	}
	return ts, hs
}

// OpenFile reads one configuration file with no inventory or store. Its
// targets read the App-ID content data from AppsFile in the directory of the
// file, when a question needs it (spec 2026-10-16 §6).
func OpenFile(path string, vsys []string, log *runlog.Logger) ([]Target, []Hole, error) {
	cfg, rep, err := config.Load(path)
	if err != nil {
		return nil, nil, err
	}
	log.Infof(runlog.TagSnap, "file %s: PAN-OS %s", path, cfg.Version())
	ts, hs := scopes(FileDevice, nil, cfg, rep, nil, vsys, nil)
	apps := filepath.Join(filepath.Dir(path), AppsFile)
	for i := range ts {
		ts[i].Apps = func() (*appid.Data, error) { return DiskApps{}.Apps(apps) }
		ts[i].AppsPath = apps
	}
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
	ix Indexes, vsys []string, notes simulate.Reasons,
) ([]Target, []Hole) {
	have := resolve.Vsyses(cfg)
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
			Snapshot: sn, Config: cfg, Report: rep, Indexes: ix, Notes: notes,
		})
	}
	var holes []Hole
	names := make([]string, 0, len(missing))
	for v := range missing {
		names = append(names, v)
	}
	slices.Sort(names)
	for _, v := range names {
		holes = append(holes, NewHole(device, v, reason.New("gap.vsys-missing", fmt.Sprintf("no vsys %s; it has %v", v, have))))
	}
	return out, holes
}

// SkipNote is the note on a snapshot picked by time past damaged newer ones, and
// false when none was passed over.
func SkipNote(sn store.Snapshot) (reason.Reason, bool) {
	if len(sn.Skipped) == 0 {
		return reason.Reason{}, false
	}
	text := fmt.Sprintf("snapshot %s skipped: its meta.json cannot be read; %s answers", sn.Skipped[0], sn.ID)
	if len(sn.Skipped) > 1 {
		text = fmt.Sprintf("snapshots %s skipped: their meta.json files cannot be read; %s answers",
			strings.Join(sn.Skipped, ", "), sn.ID)
	}
	return reason.New("note.snapshot-skipped", text), true
}

// StaleNote is the note on a target whose snapshot is older than the limit.
func StaleNote(id string, age, limit time.Duration) string {
	return fmt.Sprintf("snapshot %s is %s old, past the %s limit", id, age.Round(time.Minute), limit)
}

// ParseAt reads a point in time, as --at, --from and --to take it: a snapshot id
// (2026-09-28T07-15-37Z), an RFC 3339 time, or a date, which means the end of
// that day in UTC. Its error names the value; the caller names the input.
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
	return time.Time{}, fmt.Errorf("%q: want a snapshot id, an RFC 3339 time, or a date like 2026-09-23", s)
}
