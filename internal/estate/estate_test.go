package estate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/store"
)

var t0 = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/config/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// storeWith writes fw01 twice (lab at 10:00, multivsys at 11:00) and fw02 once.
func storeWith(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock := []time.Time{t0, t0.Add(time.Hour), t0}
	i := 0
	st = st.WithClock(func() time.Time { i++; return clock[i-1] })
	for _, w := range []struct{ dev, file string }{
		{"fw01", "firewall-lab.xml"}, {"fw01", "firewall-multivsys.xml"}, {"fw02", "firewall-zones.xml"},
	} {
		if _, err := st.Write(store.Meta{Device: w.dev}, map[string][]byte{store.ConfigDoc: fixture(t, w.file)}, 20); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func names(ts []Target) string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Device+"/"+t.Vsys)
	}
	return strings.Join(out, ",")
}

func TestOpenReadsLatest(t *testing.T) {
	t.Parallel()
	ts, holes := Open(storeWith(t), []string{"fw01", "fw02"}, nil, When{Now: t0.Add(2 * time.Hour)})
	if len(holes) != 0 {
		t.Errorf("holes = %v", holes)
	}
	if got := names(ts); got != "fw01/vsys1,fw01/vsys2,fw01/vsys3,fw02/vsys1" {
		t.Errorf("targets = %s", got)
	}
	if ts[0].Snapshot == nil || ts[0].Scope.String() != "vsys:vsys1" {
		t.Errorf("target = %+v", ts[0])
	}
}

// countingConfigs loads from disk, counts the loads and hands out indexes.
type countingConfigs struct{ loads int }

func (c *countingConfigs) Config(sn store.Snapshot) (Loaded, error) {
	c.loads++
	l, err := DiskConfigs{}.Config(sn)
	l.Indexes = index.NewSet(l.Config)
	return l, err
}

// A source of configurations replaces the store's: every target of a
// snapshot carries its indexes, and the notes stay the question's own.
func TestOpenTakesAConfigSource(t *testing.T) {
	t.Parallel()
	src := &countingConfigs{}
	ts, holes := Open(storeWith(t), []string{"fw01"}, nil, When{Now: t0.Add(2 * time.Hour), MaxAge: time.Minute, Configs: src})
	if len(holes) != 0 || len(ts) != 3 || src.loads != 1 {
		t.Fatalf("%v %v, %d loads", ts, holes, src.loads)
	}
	for _, tg := range ts {
		if tg.Indexes == nil || len(tg.Notes) != 1 || tg.Notes[0].Code != "note.snapshot-stale" {
			t.Errorf("target %+v", tg)
		}
	}
}

func TestOpenAtAnEarlierTime(t *testing.T) {
	t.Parallel()
	ts, _ := Open(storeWith(t), []string{"fw01"}, nil, When{At: t0.Add(30 * time.Minute), Now: t0.Add(2 * time.Hour)})
	if got := names(ts); got != "fw01/vsys1,fw01/vsys2" {
		t.Errorf("at 10:30 fw01 is the lab config with two vsys, got %s", got)
	}
}

// S10: a device that cannot be read is a hole, and the rest still open.
func TestOpenReportsHoles(t *testing.T) {
	t.Parallel()
	ts, holes := Open(storeWith(t), []string{"fw01", "nope"}, []string{"vsys2", "vsys9"}, When{Now: t0})
	if got := names(ts); got != "fw01/vsys2" {
		t.Errorf("targets = %s", got)
	}
	if len(holes) != 2 || holes[0].Vsys != "vsys9" || holes[1].Device != "nope" ||
		holes[0].Code != "gap.vsys-missing" || holes[1].Why().Code != "gap.snapshot-missing" {
		t.Errorf("holes = %+v", holes)
	}
}

func TestStaleSnapshotsCarryANote(t *testing.T) {
	t.Parallel()
	st := storeWith(t)
	ts, _ := Open(st, []string{"fw02"}, nil, When{MaxAge: time.Hour, Now: t0.Add(3 * time.Hour)})
	if len(ts) == 0 || len(ts[0].Notes) != 1 || !strings.Contains(ts[0].Notes[0].Text, "past the 1h0m0s limit") || ts[0].Notes[0].Code != "note.snapshot-stale" {
		t.Errorf("notes = %v", ts)
	}
	ts, _ = Open(st, []string{"fw02"}, nil, When{MaxAge: 24 * time.Hour, Now: t0.Add(3 * time.Hour)})
	if len(ts[0].Notes) != 0 {
		t.Errorf("a fresh snapshot has no note, got %v", ts[0].Notes)
	}
}

func TestOpenFile(t *testing.T) {
	t.Parallel()
	ts, holes, err := OpenFile("../../testdata/config/firewall-version-12.2.xml", nil, nil)
	if err != nil || len(holes) != 0 {
		t.Fatal(err, holes)
	}
	if names(ts) != "file/vsys1,file/vsys2" || ts[0].Snapshot != nil {
		t.Errorf("targets = %s", names(ts))
	}
	if len(ts[0].Notes) != 1 || !strings.Contains(ts[0].Notes[0].Text, "12.2.0") || ts[0].Notes[0].Code != "gap.version" {
		t.Errorf("the version gap must be a note, got %v", ts[0].Notes)
	}
	if _, _, err := OpenFile("../../testdata/config/nope.xml", nil, nil); err == nil {
		t.Error("a missing file must be an error")
	}
}

func TestOpenReportsAnUnreadableConfiguration(t *testing.T) {
	t.Parallel()
	st, _ := store.Open(t.TempDir())
	if _, err := st.Write(store.Meta{Device: "bad"}, map[string][]byte{store.ConfigDoc: []byte("<nope/>")}, 20); err != nil {
		t.Fatal(err)
	}
	_, holes := Open(st, []string{"bad"}, nil, When{Now: t0})
	if len(holes) != 1 || holes[0].Code != "gap.load-failed" {
		t.Errorf("holes = %v", holes)
	}
}

// A snapshot with predefined services loads with them; one stored before they
// were fetched loads as before; a predefined.xml that cannot be read is a hole
// that names the file.
func TestOpenReadsThePredefinedServices(t *testing.T) {
	t.Parallel()
	st, _ := store.Open(t.TempDir())
	cfg := fixture(t, "firewall-lab.xml")
	for dev, pre := range map[string]string{"with": fakePredefined, "bad": "<response><result><service>"} {
		if _, err := st.Write(store.Meta{Device: dev}, map[string][]byte{store.ConfigDoc: cfg, "predefined": []byte(pre)}, 20); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.Write(store.Meta{Device: "old"}, map[string][]byte{store.ConfigDoc: cfg}, 20); err != nil {
		t.Fatal(err)
	}
	ts, holes := Open(st, []string{"with", "old", "bad"}, nil, When{Now: t0})
	if names(ts) != "with/vsys1,with/vsys2,old/vsys1,old/vsys2" || len(holes) != 1 || holes[0].Code != "gap.load-failed" || !strings.Contains(holes[0].Reason, "predefined.xml") {
		t.Fatalf("targets %s, holes %v", names(ts), holes)
	}
	if ts[0].Config.Predefined() == nil || ts[2].Config.Predefined() != nil {
		t.Error("only the snapshot with predefined.xml has predefined services")
	}
}

const fakePredefined = `<response status="success"><result><service>` +
	`<entry name="service-https"><protocol><tcp><port>443</port></tcp></protocol></entry></service></result></response>`

func TestParseAt(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]time.Time{
		"2026-09-28T07-15-37Z":      time.Date(2026, 9, 28, 7, 15, 37, 0, time.UTC),
		"2026-09-28T07:15:37Z":      time.Date(2026, 9, 28, 7, 15, 37, 0, time.UTC),
		"2026-09-23":                time.Date(2026, 9, 23, 23, 59, 59, 0, time.UTC),
		"2026-09-28T09:15:37+02:00": time.Date(2026, 9, 28, 7, 15, 37, 0, time.UTC),
	} {
		got, err := ParseAt(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseAt(%s) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseAt("tuesday"); err == nil || !strings.HasPrefix(err.Error(), `"tuesday": want a snapshot id`) {
		t.Errorf("garbage must be an error that names the value: %v", err)
	}
}

// Asking for the first vsys must not let the later ones through.
func TestVsysFilterHoldsForEveryVsys(t *testing.T) {
	t.Parallel()
	ts, holes, err := OpenFile("../../testdata/config/firewall-multivsys.xml", []string{"vsys1"}, nil)
	if err != nil || len(holes) != 0 {
		t.Fatal(err, holes)
	}
	if got := names(ts); got != "file/vsys1" {
		t.Errorf("targets = %s, want only file/vsys1", got)
	}
}

// OpenSnapshot reads exactly the snapshot named: an older one, a missing id, or
// one without a configuration is never replaced by another.
func TestOpenSnapshot(t *testing.T) {
	t.Parallel()
	st := storeWith(t)
	ids, err := st.List("fw01")
	if err != nil || len(ids) != 2 {
		t.Fatalf("%v %v", ids, err)
	}
	ts, holes := OpenSnapshot(st, "fw01", ids[1], nil, When{Now: t0})
	if got := names(ts); got != "fw01/vsys1,fw01/vsys2" || len(holes) != 0 || ts[0].Snapshot.ID != ids[1] {
		t.Errorf("older snapshot: %s %v", got, holes)
	}
	if _, holes := OpenSnapshot(st, "fw01", "2020-01-01T00-00-00Z", nil, When{Now: t0}); len(holes) != 1 {
		t.Errorf("missing id: %v", holes)
	}
	st = st.WithClock(func() time.Time { return t0.Add(2 * time.Hour) })
	sn, err := st.Write(store.Meta{Device: "fw01"}, map[string][]byte{store.FIBDoc: []byte("<x/>")}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if ts, holes := OpenSnapshot(st, "fw01", sn.ID, nil, When{Now: t0}); len(ts) != 0 || len(holes) != 1 || !strings.Contains(holes[0].Reason, "has no configuration") || holes[0].Code != "gap.config-missing" {
		t.Errorf("no configuration: %v %v", ts, holes)
	}
}

// A store failure names its gap; a device whose snapshots all lack a
// configuration is a missing configuration, not a missing snapshot.
func TestGapOf(t *testing.T) {
	t.Parallel()
	st, _ := store.Open(t.TempDir())
	if _, err := st.Write(store.Meta{Device: "bare"}, map[string][]byte{store.FIBDoc: []byte("<x/>")}, 20); err != nil {
		t.Fatal(err)
	}
	_, noConfig := st.Latest("bare")
	_, noSnapshot := st.Latest("nope")
	inner := errors.New("inner")
	for _, c := range []struct {
		err  error
		want reason.Code
	}{
		{noConfig, "gap.config-missing"},
		{noSnapshot, "gap.snapshot-missing"},
		{errors.New("other"), "gap.load-failed"},
		{fmt.Errorf("wrapped: %w", coded("gap.fib-missing", inner)), "gap.fib-missing"},
	} {
		if got := GapOf(c.err); got != c.want {
			t.Errorf("GapOf(%v) = %s, want %s", c.err, got, c.want)
		}
	}
	if !errors.Is(coded("gap.fib-missing", inner), inner) {
		t.Error("a coded error must keep its cause")
	}
}

// damage removes the meta.json of fw01's newest snapshot in a storeWith store and
// returns its id.
func damage(t *testing.T, st *store.Store) string {
	t.Helper()
	sn, err := st.Latest("fw01")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(sn.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	return sn.ID
}

// --at passes over a damaged snapshot to the next one that can be read, with a
// note that names it. latest and a pinned id never fall back: they are holes.
func TestADamagedSnapshotIsSkippedOnlyByTime(t *testing.T) {
	t.Parallel()
	st := storeWith(t)
	id := damage(t, st)
	now := t0.Add(2 * time.Hour)
	ts, holes := Open(st, []string{"fw01"}, nil, When{At: now, Now: now})
	if got := names(ts); got != "fw01/vsys1,fw01/vsys2" || len(holes) != 0 {
		t.Fatalf("at %s: %s, holes %v", now, got, holes)
	}
	want := "snapshot " + id + " skipped: its meta.json cannot be read; " + ts[0].Snapshot.ID + " answers"
	for _, tg := range ts {
		if len(tg.Notes) != 1 || tg.Notes[0].Code != "note.snapshot-skipped" || tg.Notes[0].Text != want {
			t.Errorf("%s notes = %v", tg.Vsys, tg.Notes)
		}
	}
	for name, open := range map[string]func() ([]Target, []Hole){
		"latest": func() ([]Target, []Hole) { return Open(st, []string{"fw01"}, nil, When{Now: now}) },
		"@id":    func() ([]Target, []Hole) { return OpenSnapshot(st, "fw01", id, nil, When{Now: now}) },
	} {
		ts, holes := open()
		if len(ts) != 0 || len(holes) != 1 || holes[0].Code != "gap.load-failed" || !strings.Contains(holes[0].Reason, id) {
			t.Errorf("%s: %v, holes %+v", name, names(ts), holes)
		}
	}
}

// The routing data read at a time carries the same note.
func TestNetworkNotesASkippedSnapshot(t *testing.T) {
	t.Parallel()
	st := networkStore(t,
		snap{dev: "fw01", serial: "S1", at: t0, docs: routingDocs(t, "fw01", nil)},
		snap{dev: "fw01", serial: "S1", at: t0.Add(time.Hour), docs: routingDocs(t, "fw01", nil)},
	)
	id := damage(t, st)
	n := NewNetwork(st, []string{"fw01"}, When{At: t0.Add(2 * time.Hour), Now: t0.Add(2 * time.Hour)})
	d, err := n.Device("fw01")
	if err != nil || d.TakenAt != t0 {
		t.Fatalf("fw01 = %+v, %v", d, err)
	}
	if len(d.Notes) != 1 || d.Notes[0].Code != "note.snapshot-skipped" || !strings.Contains(d.Notes[0].Text, id) {
		t.Errorf("notes = %v", d.Notes)
	}
}
