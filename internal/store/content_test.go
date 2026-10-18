package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/inventory"
)

const fixtureVersion = "8000-1000"

// age sets the modification time of a path to d in the past.
func age(t *testing.T, path string, d time.Duration) {
	t.Helper()
	old := time.Now().Add(-d)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

// exists reports whether a path is there.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func TestWriteContentThenHave(t *testing.T) {
	t.Parallel()
	s := open(t)
	if s.HaveContent(fixtureVersion) {
		t.Fatal("HaveContent before any write")
	}
	if err := s.WriteContent(fixtureVersion, []byte("gzip data")); err != nil {
		t.Fatal(err)
	}
	if !s.HaveContent(fixtureVersion) {
		t.Error("HaveContent after the write is false")
	}
	want := filepath.Join(s.root, ".content", "8000-1000.v1.xml.gz")
	if got := s.ContentPath(fixtureVersion); got != want {
		t.Errorf("ContentPath = %s, want %s", got, want)
	}
	fi, err := os.Stat(want)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("the content file: %v, %v", fi, err)
	}
	if b, _ := os.ReadFile(want); string(b) != "gzip data" {
		t.Errorf("the content file holds %q", b)
	}
	if fi, err := os.Stat(filepath.Dir(want)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the content directory: %v, %v", fi, err)
	}
	if s.HaveContent("8000-1001") {
		t.Error("HaveContent of another version")
	}
}

// A hit refreshes the file's modification time, so a prune in another process
// cannot remove a file a live fetch reuses (spec 2026-10-16 §2.2, §3.4).
func TestHaveContentTouchesTheFile(t *testing.T) {
	t.Parallel()
	s := open(t)
	if err := s.WriteContent(fixtureVersion, []byte("x")); err != nil {
		t.Fatal(err)
	}
	p := s.ContentPath(fixtureVersion)
	age(t, p, 3*time.Hour)
	before := time.Now()
	if !s.HaveContent(fixtureVersion) {
		t.Fatal("HaveContent is false")
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Before(before.Add(-time.Second)) || fi.ModTime().After(time.Now().Add(time.Second)) {
		t.Errorf("modification time %v, want about %v", fi.ModTime(), before)
	}
}

// A file whose time cannot be refreshed counts as a miss: a prune could remove
// it while the fetch relies on it (spec 2026-10-16 §2.2).
func TestHaveContentChtimesErrorIsAMiss(t *testing.T) {
	t.Parallel()
	s := open(t)
	if err := s.WriteContent(fixtureVersion, []byte("x")); err != nil {
		t.Fatal(err)
	}
	s.chtimes = func(string, time.Time, time.Time) error { return errors.New("read-only file system") }
	if s.HaveContent(fixtureVersion) {
		t.Error("a failed Chtimes must be a miss")
	}
}

// Devices with one content version write its file at once: the renames replace
// each other whole, and no temporary file stays (spec 2026-10-16 §2.1, §3.4).
func TestConcurrentWritersOfOneVersion(t *testing.T) {
	t.Parallel()
	s := open(t)
	bodies := make([][]byte, 8)
	for i := range bodies {
		bodies[i] = bytes.Repeat([]byte{byte('a' + i)}, 64<<10)
	}
	errs := make([]error, len(bodies))
	var wg sync.WaitGroup
	for i := range bodies {
		wg.Go(func() { errs[i] = s.WriteContent(fixtureVersion, bodies[i]) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", i, err)
		}
	}
	got, err := os.ReadFile(s.ContentPath(fixtureVersion))
	if err != nil {
		t.Fatal(err)
	}
	whole := false
	for _, b := range bodies {
		whole = whole || bytes.Equal(got, b)
	}
	if !whole {
		t.Errorf("the content file is no writer's whole file: %d bytes", len(got))
	}
	entries, _ := os.ReadDir(filepath.Join(s.root, ContentDir))
	if len(entries) != 1 || entries[0].Name() != appid.FileName(fixtureVersion) {
		t.Errorf("the content directory holds %v", entries)
	}
}

// A version that is not a content version never becomes a path (spec
// 2026-10-16 §2.2).
func TestWriteContentRefusesABadVersion(t *testing.T) {
	t.Parallel()
	s := open(t)
	for _, bad := range []string{"../x", "", "8000-1000/../../x", "8000"} {
		if err := s.WriteContent(bad, []byte("x")); err == nil {
			t.Errorf("WriteContent(%q) must fail", bad)
		}
		if s.ContentPath(bad) != "" || s.HaveContent(bad) {
			t.Errorf("%q gives a content path", bad)
		}
	}
	if entries, _ := os.ReadDir(s.root); len(entries) != 0 {
		t.Errorf("a refused write left %v", entries)
	}
}

// WriteContent reports what it cannot write, and leaves no temporary file.
func TestWriteContentFailures(t *testing.T) {
	t.Parallel()
	s := open(t)
	if err := os.WriteFile(filepath.Join(s.root, ContentDir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteContent(fixtureVersion, []byte("x")); err == nil {
		t.Error("a file in the content directory's place must fail the write")
	}

	s = open(t)
	dir := filepath.Join(s.root, ContentDir)
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteContent(fixtureVersion, []byte("x")); err == nil {
		t.Error("a content directory without write permission must fail the write")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	// A directory in the file's place: the rename fails.
	if err := os.MkdirAll(filepath.Join(s.ContentPath(fixtureVersion), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteContent(fixtureVersion, []byte("x")); err == nil {
		t.Error("a directory in the file's place must fail the write")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("a failed write left %v", entries)
	}
}

// snapshotWith stores a snapshot of a device that names a content version.
func snapshotWith(t *testing.T, s *Store, device, version string) Snapshot {
	t.Helper()
	sn, err := s.Write(Meta{Device: device, AppVersion: version}, docs(t, false), 20)
	if err != nil {
		t.Fatal(err)
	}
	return sn
}

// The prune keeps a file a meta.json names and a young file; it removes an old
// file no meta.json names and an old temporary file (spec 2026-10-16 §3.4).
func TestPruneContentKeepsNamedAndYoung(t *testing.T) {
	t.Parallel()
	s := open(t)
	snapshotWith(t, s, "fw01", "8000-1000")
	snapshotWith(t, s, "fw02", "8000-1001")
	snapshotWith(t, s, "fw03", "")
	for _, v := range []string{"8000-1000", "8000-1001", "8000-0998", "8000-0999"} {
		if err := s.WriteContent(v, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(s.root, ContentDir)
	tmpOld := filepath.Join(dir, ".8000-0997.v1.xml.gz.123.tmp")
	tmpYoung := filepath.Join(dir, ".8000-0997.v1.xml.gz.456.tmp")
	oldTrim := filepath.Join(dir, "8000-1000.v0.xml.gz")
	sub := filepath.Join(dir, "sub")
	for _, p := range []string{tmpOld, tmpYoung, oldTrim} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	named, unnamedOld, unnamedYoung := s.ContentPath("8000-1000"), s.ContentPath("8000-0998"), s.ContentPath("8000-0999")
	for _, p := range []string{named, s.ContentPath("8000-1001"), unnamedOld, tmpOld, oldTrim, sub} {
		age(t, p, 2*time.Hour)
	}
	if err := s.PruneContent(); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		named: true, s.ContentPath("8000-1001"): true, unnamedYoung: true, tmpYoung: true, sub: true,
		unnamedOld: false, tmpOld: false, oldTrim: false,
	} {
		if exists(p) != want {
			t.Errorf("%s: kept %v, want %v", filepath.Base(p), !want, want)
		}
	}
}

// The prune reads only device directories: .proteus and .content are no
// devices, and neither is a file in the root (spec 2026-10-16 §3.1).
func TestPruneContentSkipsDotDirectories(t *testing.T) {
	t.Parallel()
	s := open(t)
	snapshotWith(t, s, "fw01", fixtureVersion)
	if err := s.WriteContent(fixtureVersion, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(s.root, ".proteus", "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.root, "inventory.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	age(t, s.ContentPath(fixtureVersion), 2*time.Hour)
	if err := s.PruneContent(); err != nil {
		t.Fatal(err)
	}
	if !s.HaveContent(fixtureVersion) {
		t.Error("the prune removed a named file")
	}
}

// A store without content files, or without a root, has nothing to prune.
func TestPruneContentOfAnEmptyStore(t *testing.T) {
	t.Parallel()
	if err := At(filepath.Join(t.TempDir(), "absent")).PruneContent(); err != nil {
		t.Errorf("a store without a root: %v", err)
	}
	s := open(t)
	snapshotWith(t, s, "fw01", fixtureVersion)
	if err := s.PruneContent(); err != nil {
		t.Errorf("a store without content files: %v", err)
	}
}

// A device directory the prune cannot read could name any file: the prune
// fails and removes nothing.
func TestPruneContentFailsOnAnUnreadableDevice(t *testing.T) {
	t.Parallel()
	s := open(t)
	snapshotWith(t, s, "fw01", fixtureVersion)
	if err := s.WriteContent(fixtureVersion, []byte("x")); err != nil {
		t.Fatal(err)
	}
	p := s.ContentPath(fixtureVersion)
	age(t, p, 2*time.Hour)
	dev := filepath.Join(s.root, "fw01")
	if err := os.Chmod(dev, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dev, 0o700) })
	if err := s.PruneContent(); err == nil {
		t.Error("an unreadable device directory must fail the prune")
	}
	if !exists(p) {
		t.Error("a failed prune removed a file")
	}
}

// A damaged snapshot names no file anyone can read: the prune passes over it.
func TestPruneContentPassesOverADamagedSnapshot(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn := snapshotWith(t, s, "fw01", fixtureVersion)
	if err := os.WriteFile(filepath.Join(sn.Dir, "meta.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteContent(fixtureVersion, []byte("x")); err != nil {
		t.Fatal(err)
	}
	age(t, s.ContentPath(fixtureVersion), 2*time.Hour)
	if err := s.PruneContent(); err != nil {
		t.Fatal(err)
	}
	if exists(s.ContentPath(fixtureVersion)) {
		t.Error("a file only a damaged snapshot names stays")
	}
}

// A content directory the prune cannot read or clean is an error.
func TestPruneContentReportsWhatItCannotRemove(t *testing.T) {
	t.Parallel()
	s := open(t)
	if err := s.WriteContent(fixtureVersion, []byte("x")); err != nil {
		t.Fatal(err)
	}
	age(t, s.ContentPath(fixtureVersion), 2*time.Hour)
	dir := filepath.Join(s.root, ContentDir)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := s.PruneContent(); err == nil {
		t.Error("a file the prune cannot remove must be an error")
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	if err := s.PruneContent(); err == nil {
		t.Error("an unreadable content directory must be an error")
	}

	// A root it can pass through but not list: the content directory is
	// readable, the device directories are not.
	root := open(t)
	if err := root.WriteContent(fixtureVersion, []byte("x")); err != nil {
		t.Fatal(err)
	}
	age(t, root.ContentPath(fixtureVersion), 2*time.Hour)
	if err := os.Chmod(root.root, 0o100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root.root, 0o700) })
	if err := root.PruneContent(); err == nil {
		t.Error("a root it cannot list must be an error")
	}
	if !exists(root.ContentPath(fixtureVersion)) {
		t.Error("a failed prune removed a file")
	}
}

// .content can never be a device: a device name cannot start with a dot (spec
// 2026-10-16 §3.1).
func TestContentDirIsNoDevice(t *testing.T) {
	t.Parallel()
	if inventory.ValidName(ContentDir) {
		t.Errorf("%s is a valid device name", ContentDir)
	}
	s := open(t)
	if err := s.WriteContent(fixtureVersion, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(ContentDir); err == nil {
		t.Errorf("List(%s) must fail", ContentDir)
	}
}

func TestMetaAppVersionRoundTrip(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn := snapshotWith(t, s, "fw01", fixtureVersion)
	got, err := s.Get("fw01", sn.ID)
	if err != nil || got.Meta.AppVersion != fixtureVersion {
		t.Errorf("AppVersion = %q, %v", got.Meta.AppVersion, err)
	}
	bare := snapshotWith(t, s, "fw02", "")
	b, err := os.ReadFile(filepath.Join(bare.Dir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(b, &keys); err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["app_version"]; ok {
		t.Errorf("an empty AppVersion is in meta.json: %s", b)
	}
	if !strings.Contains(string(mustRead(t, filepath.Join(sn.Dir, "meta.json"))), `"app_version": "8000-1000"`) {
		t.Error(`meta.json lacks "app_version"`)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A snapshot's content path follows from its AppVersion and the trim version;
// there is no second reference (spec 2026-10-16 §3.1).
func TestSnapshotContentPath(t *testing.T) {
	t.Parallel()
	s := open(t)
	sn := snapshotWith(t, s, "fw01", fixtureVersion)
	want := filepath.Join(s.root, ContentDir, fixtureVersion+".v1.xml.gz")
	if got := sn.ContentPath(); got != want || got != s.ContentPath(fixtureVersion) {
		t.Errorf("ContentPath = %s, want %s", got, want)
	}
	if got := snapshotWith(t, s, "fw02", "").ContentPath(); got != "" {
		t.Errorf("ContentPath without a version = %s", got)
	}
	bad := Snapshot{Dir: sn.Dir, Meta: Meta{AppVersion: "../x"}}
	if got := bad.ContentPath(); got != "" {
		t.Errorf("ContentPath of an invalid version = %s", got)
	}
	if got := (Snapshot{Meta: Meta{AppVersion: fixtureVersion}}).ContentPath(); got != "" {
		t.Errorf("ContentPath of a snapshot without a directory = %s", got)
	}
}
