package estate

import (
	"os"
	"strings"
	"testing"
	"time"

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
	if len(holes) != 2 || holes[0].Vsys != "vsys9" || holes[1].Device != "nope" {
		t.Errorf("holes = %+v", holes)
	}
}

func TestStaleSnapshotsCarryANote(t *testing.T) {
	t.Parallel()
	st := storeWith(t)
	ts, _ := Open(st, []string{"fw02"}, nil, When{MaxAge: time.Hour, Now: t0.Add(3 * time.Hour)})
	if len(ts) == 0 || len(ts[0].Notes) != 1 || !strings.Contains(ts[0].Notes[0], "past the 1h0m0s limit") {
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
	if len(ts[0].Notes) != 1 || !strings.Contains(ts[0].Notes[0], "12.2.0") {
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
	if len(holes) != 1 {
		t.Errorf("holes = %v", holes)
	}
}

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
	if _, err := ParseAt("tuesday"); err == nil {
		t.Error("garbage must be an error")
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
