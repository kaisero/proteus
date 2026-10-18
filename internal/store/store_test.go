package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	if !onDisk(got, ConfigDoc) || onDisk(got, FIBDoc) {
		t.Error("the files must reflect what arrived")
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

// A second writer of an id whose temporary directory exists fails at once, and
// leaves the first writer's directory as it is.
func TestWriteRefusesASecondWriter(t *testing.T) {
	t.Parallel()
	s := open(t)
	tmp := filepath.Join(s.root, "fw01", ".2026-09-28T10-00-00Z.partial")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	half := filepath.Join(tmp, "config.xml")
	if err := os.WriteFile(half, []byte("<config"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	if err == nil || !strings.Contains(err.Error(), "fw01@2026-09-28T10-00-00Z is being written by another fetch") {
		t.Errorf("second writer: %v", err)
	}
	if _, err := os.Stat(half); err != nil {
		t.Errorf("the second writer removed the first writer's files: %v", err)
	}
	if ids, _ := s.List("fw01"); len(ids) != 0 {
		t.Errorf("the second writer stored %v", ids)
	}
}

// A directory Write cannot make is an error of its own, not a second writer.
func TestWriteCannotMakeItsDirectories(t *testing.T) {
	t.Parallel()
	s := open(t)
	if err := os.WriteFile(filepath.Join(s.root, "fw01"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20); err == nil || strings.Contains(err.Error(), "another fetch") {
		t.Errorf("a file in the device directory's place: %v", err)
	}
	dev := filepath.Join(s.root, "fw02")
	if err := os.Mkdir(dev, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(Meta{Device: "fw02"}, docs(t, false), 20); err == nil || strings.Contains(err.Error(), "another fetch") {
		t.Errorf("a device directory without write permission: %v", err)
	}
}

// Write syncs each file and the directories it renames into. A test cannot see
// what reached the disk; it checks that the path runs and stores the files whole,
// and that the helpers report what they cannot open.
func TestWriteSyncsWhatItStores(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn, err := s.Write(Meta{Device: "fw01"}, docs(t, true), 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range sn.Meta.Documents {
		b, err := os.ReadFile(sn.Path(d.Name))
		if err != nil || len(b) == 0 || len(b) != d.Bytes {
			t.Errorf("%s: %d bytes of %d, %v", d.Name, len(b), d.Bytes, err)
		}
	}
	if len(sn.Meta.Documents) != 3 {
		t.Errorf("documents = %+v", sn.Meta.Documents)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if err := syncDir(missing); err == nil {
		t.Error("syncDir of an absent directory must fail")
	}
	if err := writeFile(filepath.Join(missing, "x.xml"), nil); err == nil {
		t.Error("writeFile into an absent directory must fail")
	}
}

// A document that cannot be written fails the write, and nothing is left.
func TestWriteFailsOnADocumentItCannotWrite(t *testing.T) {
	t.Parallel()
	s := open(t)
	if _, err := s.Write(Meta{Device: "fw01"}, map[string][]byte{"no/such": []byte("<x/>")}, 20); err == nil {
		t.Error("a document name that is no file name must fail")
	}
	entries, _ := os.ReadDir(filepath.Join(s.root, "fw01"))
	if len(entries) != 0 {
		t.Errorf("a failed write left %v", entries)
	}
}

// Writers of one id that race each other: one stores the snapshot whole, every
// other fails, and no temporary directory is left.
func TestConcurrentWritersOfOneID(t *testing.T) {
	t.Parallel()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s = s.WithClock(func() time.Time { return time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC) })
	errs := make([]error, 8)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() { _, errs[i] = s.Write(Meta{Device: "fw01"}, docs(t, false), 20) })
	}
	wg.Wait()
	stored := 0
	for _, err := range errs {
		if err == nil {
			stored++
		}
	}
	if stored != 1 {
		t.Errorf("%d writers stored the snapshot, want 1: %v", stored, errs)
	}
	got, err := s.Latest("fw01")
	if err != nil || !onDisk(got, ConfigDoc) || len(got.Meta.Documents) != 1 {
		t.Errorf("the stored snapshot: %+v, %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Join(s.root, "fw01"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a temporary entry was left behind: %s", e.Name())
		}
	}
}

// fixed returns a store whose clock stands at one second, so every write takes
// one id.
func fixed(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s.WithClock(func() time.Time { return time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC) })
}

// A writer that passed the first check while another renamed the same id into
// place makes the temporary directory anew. It then finds the snapshot stored and
// fails with the clear error, and the first writer's snapshot stays whole.
func TestASecondWriterAfterTheRename(t *testing.T) {
	t.Parallel()
	a := fixed(t)
	var first Snapshot
	var firstErr error
	b := *a
	b.step = func(name string) {
		if name == "checked" {
			first, firstErr = a.Write(Meta{Device: "fw01"}, docs(t, false), 20)
		}
	}
	_, err := b.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	if err == nil || err.Error() != "store: snapshot fw01@2026-09-28T10-00-00Z already exists" {
		t.Errorf("second writer: %v", err)
	}
	got, err := a.Latest("fw01")
	if err != nil || got.ID != first.ID || !onDisk(got, ConfigDoc) || len(got.Meta.Documents) != 1 {
		t.Errorf("the first writer's snapshot: %+v, %v", got, err)
	}
	entries, _ := os.ReadDir(filepath.Join(a.root, "fw01"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("a temporary entry was left behind: %s", e.Name())
		}
	}
}

// After its rename the first writer no longer owns the path of its temporary
// directory: a second writer that makes it again keeps it.
func TestTheFirstWriterLeavesTheNextOnesDirectory(t *testing.T) {
	t.Parallel()
	s := fixed(t)
	next := filepath.Join(s.root, "fw01", ".2026-09-28T10-00-00Z.partial", "config.xml")
	s.step = func(name string) {
		if name != "renamed" {
			return
		}
		if err := os.Mkdir(filepath.Dir(next), 0o700); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(next, []byte("<config"), 0o600); err != nil {
			t.Error(err)
		}
	}
	if _, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(next); err != nil {
		t.Errorf("the first writer removed the next writer's files: %v", err)
	}
}

// A sync that fails after the rename names the snapshot that is in place.
func TestAFailedSyncNamesTheStoredSnapshot(t *testing.T) {
	t.Parallel()
	s := fixed(t)
	s.step = func(name string) {
		if name == "renamed" {
			_ = os.RemoveAll(filepath.Join(s.root, "fw01", "2026-09-28T10-00-00Z"))
		}
	}
	_, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	if err == nil || !strings.HasPrefix(err.Error(), "store: fw01@2026-09-28T10-00-00Z is stored but not synced: ") {
		t.Errorf("a failed sync: %v", err)
	}
}

// Prune removes what a crashed write left, once it is an hour old by the file
// system's clock, and never a fresh one: a live write may still own it.
func TestPruneRemovesOldLeftovers(t *testing.T) {
	t.Parallel()
	s := open(t)
	dev := filepath.Join(s.root, "fw01")
	oldPartial := filepath.Join(dev, ".2026-09-01T00-00-00Z.partial")
	oldLink := filepath.Join(dev, ".latest-2026-09-01T00-00-00Z")
	fresh := filepath.Join(dev, ".2026-09-28T09-59-59Z.partial")
	for _, d := range []string{oldPartial, fresh} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(oldLink, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dev, ".keep")
	notAnID := filepath.Join(dev, ".notes.partial")
	noDot := filepath.Join(dev, "2026-09-01T00-00-00Z.partial")
	for _, p := range []string{other, notAnID, noDot} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	long := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{oldPartial, oldLink, other, notAnID, noDot} {
		if err := os.Chtimes(p, long, long); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		oldPartial: false, oldLink: false, fresh: true, other: true, notAnID: true, noDot: true,
	} {
		if _, err := os.Stat(p); (err == nil) != want {
			t.Errorf("%s: kept %v, want %v", filepath.Base(p), err == nil, want)
		}
	}
}

// A latest that cannot be moved leaves the snapshot stored, and the error says
// so.
func TestAFailedLatestNamesTheStoredSnapshot(t *testing.T) {
	t.Parallel()
	s := fixed(t)
	if err := os.MkdirAll(filepath.Join(s.root, "fw01", "latest", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	if err == nil || !strings.HasPrefix(err.Error(), "store: fw01@2026-09-28T10-00-00Z is stored but latest does not name it: ") {
		t.Errorf("a latest that cannot move: %v", err)
	}
	if _, err := s.Get("fw01", "2026-09-28T10-00-00Z"); err != nil {
		t.Errorf("the snapshot: %v", err)
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

// A snapshot whose meta.json is gone is damaged, not missing: Write renames a
// snapshot into place whole. A snapshot that is gone altogether is missing.
func TestGetTellsADamagedSnapshotFromAMissingOne(t *testing.T) {
	t.Parallel()
	s := open(t)
	damaged, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	gone, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20)
	if err := os.Remove(filepath.Join(damaged.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(gone.Dir); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get("fw01", damaged.ID)
	if !errors.Is(err, ErrUnreadable) || errors.Is(err, ErrNoSnapshot) || errors.Is(err, fs.ErrNotExist) ||
		!strings.HasPrefix(err.Error(), "store: fw01@"+damaged.ID+": meta.json: ") {
		t.Errorf("Get of a snapshot without meta.json: %v", err)
	}
	if _, err := s.Get("fw01", gone.ID); !errors.Is(err, ErrNoSnapshot) || errors.Is(err, ErrUnreadable) {
		t.Errorf("Get of a removed snapshot: %v", err)
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

// AtOrBefore passes over damaged snapshots, as it passes over ones without a
// configuration, and names them in Skipped. With nothing readable left, its error
// names them.
func TestAtOrBeforeSkipsADamagedSnapshot(t *testing.T) {
	t.Parallel()
	s := open(t)
	a, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20) // 10:00
	b, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20) // 10:01
	c, _ := s.Write(Meta{Device: "fw01"}, docs(t, false), 20) // 10:02
	if err := os.Remove(filepath.Join(c.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b.Dir, "meta.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Date(2026, 9, 28, 11, 0, 0, 0, time.UTC)
	got, err := s.AtOrBefore("fw01", later)
	if err != nil || got.ID != a.ID || strings.Join(got.Skipped, ",") != c.ID+","+b.ID {
		t.Errorf("AtOrBefore = %s skipping %v, %v; want %s skipping %s and %s", got.ID, got.Skipped, err, a.ID, c.ID, b.ID)
	}
	if sn, _ := s.Get("fw01", a.ID); len(sn.Skipped) != 0 {
		t.Errorf("Get names skipped snapshots: %v", sn.Skipped)
	}
	if err := os.Remove(filepath.Join(a.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	_, err = s.AtOrBefore("fw01", later)
	if !errors.Is(err, ErrUnreadable) || errors.Is(err, ErrNoSnapshot) || errors.Is(err, ErrNoConfig) ||
		!strings.HasSuffix(err.Error(), "; damaged: "+c.ID+", "+b.ID+", "+a.ID) {
		t.Errorf("all damaged: %v", err)
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

// onDisk reports whether a document of a snapshot is on disk.
func onDisk(sn Snapshot, doc string) bool {
	_, err := os.Stat(sn.Path(doc))
	return err == nil
}
