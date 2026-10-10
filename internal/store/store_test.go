package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func clock(start time.Time) func() time.Time {
	t := start
	return func() time.Time {
		now := t
		t = t.Add(time.Minute)
		return now
	}
}

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s.WithClock(clock(time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)))
}

func docs(t *testing.T, withZones bool) map[string][]byte {
	t.Helper()
	out := map[string][]byte{ConfigDoc: []byte(`<config version="11.2.0"/>`)}
	if withZones {
		for name, path := range map[string]string{
			InterfacesDoc: "../../testdata/opdata/fw01-interface-all.xml",
			FIBDoc:        "../../testdata/opdata/fw01-advanced-routing-fib.xml",
		} {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			out[name] = b
		}
	}
	return out
}

func TestWriteThenLatest(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn, err := s.Write(Meta{Device: "fw01", Host: "192.0.2.10", Serial: "0001"}, docs(t, false), 20)
	if err != nil {
		t.Fatal(err)
	}
	if sn.ID != "2026-09-28T10-00-00Z" {
		t.Errorf("ID = %s", sn.ID)
	}
	got, err := s.Latest("fw01")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != sn.ID || got.Meta.Serial != "0001" || !got.Meta.TakenAt.Equal(time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("Latest = %+v", got)
	}
	b, err := os.ReadFile(got.Path(ConfigDoc))
	if err != nil || !strings.HasPrefix(string(b), "<config") {
		t.Errorf("config.xml = %s, %v", b, err)
	}
	if len(got.Meta.Documents) != 1 || got.Meta.Documents[0].File != "config.xml" {
		t.Errorf("documents = %+v", got.Meta.Documents)
	}
	if !got.Has(ConfigDoc) || got.Has(FIBDoc) {
		t.Error("Has must reflect what arrived")
	}
}

// A document the caller already named, because it failed or succeeded, gets its
// file and size filled in rather than a second entry.
func TestWriteFillsANamedDocument(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn, err := s.Write(Meta{Device: "fw01", Documents: []DocumentMeta{{Name: ConfigDoc}, {Name: FIBDoc, Error: "refused"}}},
		docs(t, false), 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(sn.Meta.Documents) != 2 || sn.Meta.Documents[0].File != "config.xml" || sn.Meta.Documents[1].Error != "refused" {
		t.Errorf("documents = %+v", sn.Meta.Documents)
	}
}

// Nothing can be analysed without the configuration, so a fetch that lost it is
// kept for the record but never becomes latest.
func TestLatestMovesOnlyWithAConfiguration(t *testing.T) {
	t.Parallel()
	s := open(t)
	first, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	_, err := s.Write(Meta{Device: "fw01", Documents: []DocumentMeta{{Name: ConfigDoc, Error: "refused"}}},
		map[string][]byte{}, 20)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := s.Latest("fw01")
	if got.ID != first.ID {
		t.Errorf("latest = %s, want it left at %s", got.ID, first.ID)
	}
	ids, _ := s.List("fw01")
	if len(ids) != 2 {
		t.Errorf("both snapshots must be kept, got %v", ids)
	}
}

func TestRetentionKeepsTheNewest(t *testing.T) {
	t.Parallel()
	s := open(t)
	for range 5 {
		if _, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 3); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := s.List("fw01")
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-09-28T10-04-00Z,2026-09-28T10-03-00Z,2026-09-28T10-02-00Z"
	if got := strings.Join(ids, ","); got != want {
		t.Errorf("List = %s, want %s", got, want)
	}
}

// Retention never removes the snapshot latest names, even when newer ones lack a
// configuration.
func TestRetentionKeepsLatest(t *testing.T) {
	t.Parallel()
	s := open(t)
	first, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 1)
	if _, err := s.Write(Meta{Device: "fw01"}, map[string][]byte{}, 1); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Latest("fw01"); err != nil || got.ID != first.ID {
		t.Errorf("latest = %v, %v; want %s kept", got.ID, err, first.ID)
	}
}

// failed stores a fetch whose configuration export failed.
func failed(t *testing.T, s *Store, keep int) Snapshot {
	t.Helper()
	sn, err := s.Write(Meta{Device: "fw01", Documents: []DocumentMeta{{Name: ConfigDoc, Error: "export failed"}}},
		map[string][]byte{}, keep)
	if err != nil {
		t.Fatal(err)
	}
	return sn
}

// Retention counts the snapshots with a configuration and those without apart: a
// run of failed exports never removes the last snapshots that can be analysed.
func TestRetentionCountsFailedFetchesApart(t *testing.T) {
	t.Parallel()
	s := open(t)
	var good, bad []string
	for range 3 {
		sn, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 3)
		if err != nil {
			t.Fatal(err)
		}
		good = append(good, sn.ID)
	}
	for range 3 {
		bad = append(bad, failed(t, s, 3).ID)
	}
	ids, _ := s.List("fw01")
	if len(ids) != 6 {
		t.Fatalf("keep 3 of each must keep all six, got %v", ids)
	}
	bad = append(bad, failed(t, s, 3).ID)
	ids, _ = s.List("fw01")
	want := []string{bad[3], bad[2], bad[1], good[2], good[1], good[0]}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("after a fourth failed export: %v, want %v (the oldest failed one goes)", ids, want)
	}
	if got, err := s.Latest("fw01"); err != nil || got.ID != good[2] {
		t.Errorf("latest = %v, %v; want %s", got.ID, err, good[2])
	}
}

// A good snapshot beyond keep goes when newer good ones arrive, however many failed
// ones lie between them.
func TestRetentionKeepsTheNewestGoodOnes(t *testing.T) {
	t.Parallel()
	s := open(t)
	first, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 1)
	failed(t, s, 1)
	second, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 1)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := s.List("fw01")
	if len(ids) != 2 || ids[0] != second.ID || slices.Contains(ids, first.ID) {
		t.Errorf("List = %v; want %s and the failed one, without %s", ids, second.ID, first.ID)
	}
}

// A snapshot directory without a readable meta.json counts as one without a
// configuration, even when it holds config.xml.
func TestRetentionCountsAnUnreadableSnapshotAsFailed(t *testing.T) {
	t.Parallel()
	s := open(t)
	broken, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 1)
	if err := os.Remove(filepath.Join(broken.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	good, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 1)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := s.List("fw01")
	if strings.Join(ids, ",") != good.ID+","+broken.ID {
		t.Errorf("List = %v; the unreadable snapshot is the one kept without a configuration", ids)
	}
	failed(t, s, 1)
	if ids, _ = s.List("fw01"); slices.Contains(ids, broken.ID) || !slices.Contains(ids, good.ID) {
		t.Errorf("List = %v; a newer failed fetch replaces the unreadable one", ids)
	}
}

func TestWriteRefusesADuplicateID(t *testing.T) {
	t.Parallel()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s = s.WithClock(func() time.Time { return time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC) })
	if _, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20); err == nil {
		t.Error("two snapshots in one second must not overwrite each other")
	}
}

func TestResolveAndGet(t *testing.T) {
	t.Parallel()
	s := open(t)
	a, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	b, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	if got, err := s.Resolve("fw01"); err != nil || got.ID != b.ID {
		t.Errorf("Resolve(fw01) = %v, %v; want latest %s", got.ID, err, b.ID)
	}
	if got, err := s.Resolve("fw01@" + a.ID); err != nil || got.ID != a.ID {
		t.Errorf("Resolve(fw01@%s) = %v, %v", a.ID, got.ID, err)
	}
	for _, bad := range []string{"", "fw02", "fw01@nope", "../etc", "fw01@../x", "fw01@2026-01-01T00-00-00Z"} {
		if _, err := s.Resolve(bad); err == nil {
			t.Errorf("Resolve(%q) must fail", bad)
		}
	}
	if _, err := s.List("../x"); err == nil {
		t.Error("List must refuse an unsafe name")
	}
}

func TestGetRejectsACorruptMeta(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	if err := os.WriteFile(filepath.Join(sn.Dir, "meta.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("fw01", sn.ID); err == nil {
		t.Error("a corrupt meta.json must be an error")
	}
}

func TestZonesFromAStoredSnapshot(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn, err := s.Write(Meta{Device: "fw01", Host: "192.0.2.10"}, docs(t, true), 20)
	if err != nil {
		t.Fatal(err)
	}
	z, err := sn.Zones()
	if err != nil {
		t.Fatal(err)
	}
	if len(z.Routers()) == 0 {
		t.Error("the stored forwarding table names no router")
	}
	bare, _ := s.Write(Meta{Device: "fw02"}, docs(t, false), 20)
	if _, err := bare.Zones(); err == nil {
		t.Error("a snapshot without interfaces and fib cannot place zones")
	}
	noFIB := docs(t, true)
	delete(noFIB, FIBDoc)
	half, _ := s.Write(Meta{Device: "fw03"}, noFIB, 20)
	if _, err := half.Zones(); err == nil || !strings.Contains(err.Error(), "forwarding table") {
		t.Errorf("a snapshot without a fib must say so, got %v", err)
	}
}

// A reader never sees half a snapshot: nothing but finished snapshots and latest
// sits in a device's directory.
func TestNoPartialSnapshotIsLeft(t *testing.T) {
	t.Parallel()
	s := open(t)
	if _, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(s.root, "fw01"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a temporary entry was left behind: %s", e.Name())
		}
	}
}

func TestWriteRejectsAnUnsafeDeviceName(t *testing.T) {
	t.Parallel()
	if _, err := open(t).Write(Meta{Device: "../x"}, docs(t, false), 20); err == nil {
		t.Error("a device name must never leave the store")
	}
}

func TestDefaultRoot(t *testing.T) {
	t.Parallel()
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if got, _ := DefaultRoot(env(map[string]string{"PROTEUS_STORE": "/s"})); got != "/s" {
		t.Errorf("PROTEUS_STORE ignored: %s", got)
	}
	if got, _ := DefaultRoot(env(map[string]string{"XDG_DATA_HOME": "/d"})); got != "/d/proteus" {
		t.Errorf("XDG_DATA_HOME ignored: %s", got)
	}
	got, err := DefaultRoot(env(nil))
	if err != nil || !strings.HasSuffix(got, filepath.Join(".local", "share", "proteus")) {
		t.Errorf("home default = %s, %v", got, err)
	}
}

func TestAtOrBefore(t *testing.T) {
	t.Parallel()
	s := open(t)
	a, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)     // 10:00
	_, _ = s.Write(Meta{Device: "fw01"}, map[string][]byte{}, 20) // 10:01, no config
	c, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)     // 10:02
	at := func(h, m int) time.Time { return time.Date(2026, 9, 28, h, m, 30, 0, time.UTC) }
	if _, err := s.AtOrBefore("fw01", at(9, 59)); err == nil {
		t.Error("before the first snapshot there is none")
	}
	if got, err := s.AtOrBefore("fw01", at(10, 1)); err != nil || got.ID != a.ID {
		t.Errorf("at 10:01:30 = %v, %v; want %s, skipping the snapshot without a configuration", got.ID, err, a.ID)
	}
	if got, err := s.AtOrBefore("fw01", at(11, 0)); err != nil || got.ID != c.ID {
		t.Errorf("at 11:00 = %v, %v; want %s", got.ID, err, c.ID)
	}
	if _, err := s.AtOrBefore("fw02", at(11, 0)); err == nil {
		t.Error("a device never fetched has none")
	}
}

// At creates nothing: an absent root has no snapshot, and the first write
// creates it private to its owner.
func TestAtCreatesNothingUntilAWrite(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "store")
	s := At(root)
	if _, err := s.Latest("fw01"); !errors.Is(err, ErrNoSnapshot) {
		t.Errorf("latest of an absent root: %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("At created the root: %v", err)
	}
	if _, err := s.Write(Meta{Device: "fw01"}, map[string][]byte{ConfigDoc: []byte("<config/>")}, 0); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(root); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the write's root: %v %v", fi, err)
	}
}
