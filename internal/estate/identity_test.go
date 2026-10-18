package estate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/store"
	"github.com/okaiser/proteus/internal/testconfig"
)

// identityTakenAt is the taken_at of the identity fixture.
var identityTakenAt = time.Date(2026, 10, 17, 20, 0, 0, 0, time.UTC)

// identityBytes is the identity fixture as a fetch stores it: gzip JSON.
func identityBytes(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), identity.FileName)
	testconfig.Identity(t, p)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// identityStore holds one fw01 snapshot with an identity file and one fw02
// snapshot without one (spec 2026-10-17 §4.1).
func identityStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st = st.WithClock(func() time.Time { return t0 })
	docs := map[string][]byte{store.ConfigDoc: fixture(t, "firewall-identity.xml")}
	if _, err := st.Write(store.Meta{Device: "fw01"}, docs, identityBytes(t), 20); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write(store.Meta{Device: "fw02"}, docs, nil, 20); err != nil {
		t.Fatal(err)
	}
	return st
}

// countingIdentity loads from disk and records each path it was asked for.
type countingIdentity struct {
	mu    sync.Mutex
	paths []string
}

func (c *countingIdentity) Identity(path string) (*identity.Data, error) {
	c.mu.Lock()
	c.paths = append(c.paths, path)
	c.mu.Unlock()
	return DiskIdentity{}.Identity(path)
}

// A file reads identity.json.gz in its own directory and names it: absent,
// the loader says the file does not exist; present, it loads it (spec
// 2026-10-17 §7).
func TestOpenFileReadsTheIdentityFileBeside(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, fixture(t, "firewall-identity.xml"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, _, err := OpenFile(path, nil, nil)
	if err != nil || len(ts) != 1 {
		t.Fatalf("%v %v", ts, err)
	}
	want := filepath.Join(dir, IdentityFile)
	if ts[0].IdentityPath != want || ts[0].Identity == nil {
		t.Fatalf("path %q, loader %v; want %q", ts[0].IdentityPath, ts[0].Identity != nil, want)
	}
	if _, err := ts[0].Identity(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent file: %v", err)
	}
	testconfig.Identity(t, want)
	if d, err := ts[0].Identity(); err != nil || !d.TakenAt().Equal(identityTakenAt) {
		t.Errorf("present file: %v %v", d, err)
	}
}

// A snapshot that holds an identity file gives its targets the file's path
// and a loader that reads it through When.Identity, and only when called. A
// snapshot without one gives no loader (spec 2026-10-17 §4.2).
func TestOpenSnapshotReadsItsIdentityFile(t *testing.T) {
	t.Parallel()
	st := identityStore(t)
	src := &countingIdentity{}
	ts, holes := Open(st, []string{"fw01", "fw02"}, nil, When{Now: t0, Identity: src})
	if len(holes) != 0 || len(ts) != 2 {
		t.Fatalf("targets %s, holes %v", names(ts), holes)
	}
	if len(src.paths) != 0 {
		t.Errorf("Open loaded the identity file: %v", src.paths)
	}
	if ts[0].IdentityPath != ts[0].Snapshot.IdentityPath() || ts[0].IdentityPath == "" || ts[0].Identity == nil {
		t.Fatalf("fw01: path %q, loader %v", ts[0].IdentityPath, ts[0].Identity != nil)
	}
	d, err := ts[0].Identity()
	if err != nil || !d.TakenAt().Equal(identityTakenAt) || len(src.paths) != 1 || src.paths[0] != ts[0].IdentityPath {
		t.Errorf("fw01: %v %v, asked %v", d, err, src.paths)
	}
	if ts[1].Identity != nil || ts[1].IdentityPath != "" {
		t.Errorf("fw02: path %q, loader %v", ts[1].IdentityPath, ts[1].Identity != nil)
	}
	// One snapshot by its id, read from disk without When.Identity.
	ts, _ = OpenSnapshot(st, "fw01", ts[0].Snapshot.ID, nil, When{Now: t0})
	if d, err := ts[0].Identity(); err != nil || !d.TakenAt().Equal(identityTakenAt) {
		t.Errorf("OpenSnapshot: %v %v", d, err)
	}
}

// identityConfigs is a configuration source that gives its own identity
// loader, as a server's cache does.
type identityConfigs struct{ data *identity.Data }

func (c identityConfigs) Config(sn store.Snapshot) (Loaded, error) {
	l, err := DiskConfigs{}.Config(sn)
	l.Identity = func() (*identity.Data, error) { return c.data, nil }
	return l, err
}

// A configuration source's identity loader wins over When.Identity.
func TestOpenTakesTheSourcesIdentity(t *testing.T) {
	t.Parallel()
	data := identity.New(identity.File{Format: identity.Format})
	src := &countingIdentity{}
	ts, _ := Open(identityStore(t), []string{"fw01"}, nil, When{Now: t0, Identity: src, Configs: identityConfigs{data}})
	if d, err := ts[0].Identity(); d != data || err != nil || len(src.paths) != 0 {
		t.Errorf("%p %v, asked %v", d, err, src.paths)
	}
}
