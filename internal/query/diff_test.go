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
