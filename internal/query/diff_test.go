package query

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
)

// diffLab is fw01 fetched twice, the second time changed and from another
// serial, and fw02 fetched once.
func diffLab(t *testing.T) Env {
	t.Helper()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01", Serial: "000000000001"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01", Serial: "000000000002"}, pathlab.Read(t, fixture("firewall-lab-changed.xml")))
	l.fetch("fw02", pathlab.ConfigFile("fw02"))
	return l.env()
}

// A diff per device and scope: fw01's changes with the serial note, fw02's one
// snapshot a hole.
func TestSnapshotDiff(t *testing.T) {
	t.Parallel()
	e, err := SnapshotDiff(context.Background(), diffLab(t), DiffInput{})
	if err != nil || e.Command != "snapshot diff" || len(e.Results) < 2 {
		t.Fatalf("%+v %v", e, err)
	}
	if r := e.Results[0]; r.Device != "fw01" || r.Scope != "shared" || r.From == r.To || r.Changes == nil {
		t.Errorf("first: %+v", r)
	}
	changed := 0
	for _, r := range e.Results {
		changed += len(r.Changes)
	}
	if changed == 0 {
		t.Error("no changes")
	}
	if len(e.Notes) != 1 || e.Notes[0].Code != "note.serial-changed" || len(e.Holes) != 1 || e.Holes[0].Device != "fw02" ||
		!strings.Contains(e.Holes[0].Reason, "only one snapshot") {
		t.Errorf("notes %+v, holes %+v", e.Notes, e.Holes)
	}
	e, err = SnapshotDiff(context.Background(), diffLab(t), DiffInput{Selection: Selection{Device: []string{"fw01"}, Vsys: []string{"vsys1"}}})
	if err != nil || len(e.Results) != 2 || e.Results[1].Scope != "vsys:vsys1" {
		t.Errorf("vsys1: %+v %v", e.Results, err)
	}
}

// A setting of the scope is a change like any other: the limit counts it.
func TestSnapshotDiffLimitCountsSettings(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	vsys := func(body string) []byte {
		return []byte(`<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">` +
			body + `</entry></vsys></entry></devices></config>`)
	}
	l.write(store.Meta{Device: "fw01"}, vsys(`<display-name>one</display-name>`))
	l.write(store.Meta{Device: "fw01"}, vsys(`<display-name>two</display-name><import><network><interface><member>ethernet1/3</member></interface></network></import>`))
	fw01 := Selection{Device: []string{"fw01"}, Vsys: []string{"vsys1"}}
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: fw01, ResultLimit: ResultLimit{Limit: 1}})
	if err != nil || e.Summary.Found != 2 || e.Summary.Omitted != 1 || len(e.Results) != 2 || len(e.Results[1].Changes) != 1 ||
		e.Results[1].Changes[0].Kind != "setting" || e.Results[1].Changes[0].Name != "display-name" {
		t.Errorf("%v %+v %+v", err, e.Summary, e.Results)
	}
}

// From and To pick the snapshots; one before any snapshot is a hole.
func TestSnapshotDiffFromAndTo(t *testing.T) {
	t.Parallel()
	env := diffLab(t)
	fw01 := Selection{Device: []string{"fw01"}}
	e, err := SnapshotDiff(context.Background(), env, DiffInput{Selection: fw01, From: "2026-09-28T10:00:00Z", To: "2026-09-28T10:00:30Z"})
	if err != nil || len(e.Results) == 0 || e.Results[0].From != e.Results[0].To {
		t.Errorf("same snapshot: %+v %v", e.Results, err)
	}
	if e, err := SnapshotDiff(context.Background(), env, DiffInput{Selection: fw01, To: "2020-01-01"}); err != nil || len(e.Holes) != 1 || e.Holes[0].Code != "gap.snapshot-missing" {
		t.Errorf("before any: %+v %v", e.Holes, err)
	}
}

// A configuration that does not parse is a hole of a failed load.
func TestSnapshotDiffOfAnUnreadableConfiguration(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01"}, []byte("<config"))
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
	if err != nil || len(e.Holes) != 1 || e.Holes[0].Code != "gap.load-failed" || !strings.Contains(e.Holes[0].Reason, "unreadable configuration") {
		t.Errorf("%+v %v", e.Holes, err)
	}
}

// Without From, a damaged snapshot before the newer one is passed over: the
// diff compares the next older one that can be read, and a note names the
// skipped one.
func TestSnapshotDiffPassesOverADamagedSnapshot(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab-changed.xml")))
	ids, err := l.st.List("fw01")
	if err != nil || len(ids) != 3 {
		t.Fatalf("ids %v, %v", ids, err)
	}
	sn, _ := l.st.Get("fw01", ids[1])
	if err := os.Remove(filepath.Join(sn.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
	if err != nil || len(e.Holes) != 0 || len(e.Results) == 0 {
		t.Fatalf("%+v %v", e, err)
	}
	if r := e.Results[0]; r.From != ids[2] || r.To != ids[0] {
		t.Errorf("compared %s with %s, want %s with %s", r.From, r.To, ids[2], ids[0])
	}
	if len(e.Notes) != 1 || e.Notes[0].Code != "note.snapshot-skipped" || e.Notes[0].Device != "fw01" ||
		!strings.Contains(e.Notes[0].Note, ids[1]) {
		t.Errorf("notes %+v", e.Notes)
	}
}

// With --from and --to on one snapshot past a damaged one, the note shows once.
// With every older snapshot damaged, the hole is a failed load that names them,
// not "only one snapshot".
func TestSnapshotDiffNamesDamagedSnapshotsOnce(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	for range 3 {
		l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	}
	ids, _ := l.st.List("fw01")
	sn, _ := l.st.Get("fw01", ids[0])
	if err := os.Remove(filepath.Join(sn.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	fw01 := Selection{Device: []string{"fw01"}}
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: fw01, From: "2026-09-28T10:02:30Z", To: "2026-09-28T10:02:30Z"})
	if err != nil || len(e.Notes) != 1 || e.Notes[0].Code != "note.snapshot-skipped" {
		t.Errorf("one snapshot on both sides: notes %+v, %v", e.Notes, err)
	}
	sn, _ = l.st.Get("fw01", ids[2])
	if err := os.Remove(filepath.Join(sn.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	e, err = SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: fw01, To: "2026-09-28T10:01:30Z"})
	if err != nil || len(e.Holes) != 1 || e.Holes[0].Code != "gap.load-failed" ||
		!strings.Contains(e.Holes[0].Reason, "damaged: "+ids[2]) || strings.Contains(e.Holes[0].Reason, "only one") {
		t.Errorf("every older one damaged: holes %+v, %v", e.Holes, err)
	}
}

// An older configuration that is there but cannot be read is a failed load, not
// "only one snapshot".
func TestSnapshotDiffOfAnUnreadableOlderSnapshot(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	ids, _ := l.st.List("fw01")
	sn, _ := l.st.Get("fw01", ids[1])
	p := sn.Path(store.ConfigDoc)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(p), p); err != nil { // a link to itself cannot be read
		t.Fatal(err)
	}
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
	if err != nil || len(e.Holes) != 1 || e.Holes[0].Code != "gap.load-failed" || strings.Contains(e.Holes[0].Reason, "only one") {
		t.Errorf("%+v %v", e.Holes, err)
	}
}

// A diff reads the store: a file, a time or a fresh fetch is refused, as are an
// unknown device and an env without the estate.
func TestSnapshotDiffInputRules(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   DiffInput
		want string
	}{
		{DiffInput{Selection: Selection{File: "x.xml"}}, "--file: snapshot diff compares stored snapshots"},
		{DiffInput{Selection: Selection{At: "2026-01-01"}}, "--at: snapshot diff"},
		{DiffInput{Selection: Selection{Fresh: true}}, "--fresh: snapshot diff"},
		{DiffInput{Selection: Selection{Device: []string{"fw09"}}}, `no device named "fw09"`},
		// From and To read as at does; a bad one names its own input.
		{DiffInput{To: "tuesday"}, `--to "tuesday": want a snapshot id, an RFC 3339 time, or a date`},
		{DiffInput{From: "tuesday", To: "2026-09-28"}, `--from "tuesday": want a snapshot id`},
	} {
		_, err := SnapshotDiff(context.Background(), diffLab(t), tc.in)
		usageOK(t, err, tc.want)
	}
	// The tool's words name the input without the dashes.
	u := DiffInput{From: "tuesday"}.Validate()
	if u == nil || u.ToolText != `from "tuesday": want a snapshot id, an RFC 3339 time, or a date like 2026-09-23` {
		t.Errorf("tool text: %+v", u)
	}
	if u := (DiffInput{From: "2026-09-27", To: "2026-09-28T10-00-00Z"}).Validate(); u != nil {
		t.Errorf("good times refused: %v", u)
	}
	if _, err := SnapshotDiff(context.Background(), Env{}, DiffInput{}); !errors.Is(err, errNoInventory) {
		t.Errorf("no inventory: %v", err)
	}
	env := diffLab(t)
	env.Store = nil
	if _, err := SnapshotDiff(context.Background(), env, DiffInput{}); !errors.Is(err, errNoStore) {
		t.Errorf("no store: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SnapshotDiff(ctx, diffLab(t), DiffInput{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// A diff of a snapshot without a configuration says so; one that cannot be read
// is a failed load.
func TestConfigGap(t *testing.T) {
	t.Parallel()
	with := store.Snapshot{Device: "fw01", ID: "a", Dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(with.Dir, store.ConfigDoc+".xml"), []byte("<config"), 0o600); err != nil {
		t.Fatal(err)
	}
	without := store.Snapshot{Device: "fw01", ID: "b", Dir: t.TempDir()}
	if got := configGap(with, without); got != "gap.config-missing" {
		t.Errorf("without: %s", got)
	}
	if got := configGap(with, with); got != "gap.load-failed" {
		t.Errorf("with: %s", got)
	}
}

// Two snapshots of different content versions give a note; equal versions,
// or a snapshot without one, give none (spec 2026-10-16 §5.3). The newer
// version's file is built here: no binary fixture is committed (D15).
func TestDiffNotesTheContentVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		older, newer string
		want         bool
	}{{"8000-1000", "8001-1001", true}, {"8000-1000", "8000-1000", false}, {"", "8001-1001", false}} {
		l := newLab(t)
		for _, v := range []string{tc.older, tc.newer} {
			if v == "" {
				continue
			}
			if err := l.st.WriteContent(v, contentOf(t, v)); err != nil {
				t.Fatal(err)
			}
		}
		l.write(store.Meta{Device: "fw01", AppVersion: tc.older}, pathlab.Read(t, fixture("firewall-lab.xml")))
		l.write(store.Meta{Device: "fw01", AppVersion: tc.newer}, pathlab.Read(t, fixture("firewall-lab-changed.xml")))
		e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
		if err != nil {
			t.Fatal(err)
		}
		n, ok := noteWith(e.Notes, "note.app-version-changed")
		if ok != tc.want || ok && (n.Note != "content version 8000-1000 → 8001-1001" || n.Device != "fw01") {
			t.Errorf("%s → %s: notes %+v", tc.older, tc.newer, e.Notes)
		}
	}
}
