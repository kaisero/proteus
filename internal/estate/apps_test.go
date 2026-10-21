package estate

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/store"
	"github.com/kaisero/proteus/internal/testconfig"
)

// appStore holds one fw01 snapshot whose meta names content version 8000-1000,
// with the content file stored, and one fw02 snapshot that names none.
func appStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st = st.WithClock(func() time.Time { return t0 })
	for _, m := range []store.Meta{{Device: "fw01", AppVersion: "8000-1000"}, {Device: "fw02"}} {
		if _, err := st.Write(m, map[string][]byte{store.ConfigDoc: fixture(t, "firewall-zones.xml")}, nil, 20); err != nil {
			t.Fatal(err)
		}
	}
	p := st.ContentPath("8000-1000")
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	testconfig.Content(t, p)
	return st
}

// countingApps loads from disk and records each path it was asked for.
type countingApps struct{ paths []string }

func (c *countingApps) Apps(path string) (*appid.Data, error) {
	c.paths = append(c.paths, path)
	return DiskApps{}.Apps(path)
}

// A snapshot that names a content version gives its targets the file's path
// and a loader that reads it through When.Apps, and only when called. A
// snapshot that names none gives no loader.
func TestOpenGivesTheSnapshotsContent(t *testing.T) {
	t.Parallel()
	st := appStore(t)
	src := &countingApps{}
	ts, holes := Open(st, []string{"fw01", "fw02"}, nil, When{Now: t0, Apps: src})
	if len(holes) != 0 || len(ts) != 2 {
		t.Fatalf("targets %s, holes %v", names(ts), holes)
	}
	if len(src.paths) != 0 {
		t.Errorf("Open loaded the content: %v", src.paths)
	}
	if ts[0].AppsPath != st.ContentPath("8000-1000") || ts[0].Apps == nil {
		t.Fatalf("fw01: path %q, loader %v", ts[0].AppsPath, ts[0].Apps != nil)
	}
	d, err := ts[0].Apps()
	if err != nil || d.Version() != "8000-1000" || len(src.paths) != 1 || src.paths[0] != ts[0].AppsPath {
		t.Errorf("fw01: %v %v, asked %v", d, err, src.paths)
	}
	if ts[1].Apps != nil || ts[1].AppsPath != "" {
		t.Errorf("fw02: path %q, loader %v", ts[1].AppsPath, ts[1].Apps != nil)
	}
}

// Without When.Apps, the content is read from disk.
func TestOpenReadsTheContentFromDisk(t *testing.T) {
	t.Parallel()
	ts, _ := Open(appStore(t), []string{"fw01"}, nil, When{Now: t0})
	if d, err := ts[0].Apps(); err != nil || d.Version() != "8000-1000" {
		t.Errorf("%v %v", d, err)
	}
}

// appsConfigs is a configuration source that gives its own content loader.
type appsConfigs struct{ data *appid.Data }

func (c appsConfigs) Config(sn store.Snapshot) (Loaded, error) {
	l, err := DiskConfigs{}.Config(sn)
	l.Apps = func() (*appid.Data, error) { return c.data, nil }
	return l, err
}

// A configuration source's content loader wins over When.Apps.
func TestOpenTakesTheSourcesContent(t *testing.T) {
	t.Parallel()
	data := &appid.Data{}
	src := &countingApps{}
	ts, _ := Open(appStore(t), []string{"fw01"}, nil, When{Now: t0, Apps: src, Configs: appsConfigs{data}})
	if d, err := ts[0].Apps(); d != data || err != nil || len(src.paths) != 0 {
		t.Errorf("%p %v, asked %v", d, err, src.paths)
	}
}

// A file reads apps.xml.gz in its own directory: absent, the loader says the
// file does not exist; present, it loads it (spec 2026-10-16 §6).
func TestOpenFileGivesTheContentBeside(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, fixture(t, "firewall-zones.xml"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, _, err := OpenFile(path, nil, nil)
	if err != nil || len(ts) != 1 {
		t.Fatalf("%v %v", ts, err)
	}
	want := filepath.Join(dir, AppsFile)
	if ts[0].AppsPath != want {
		t.Errorf("path %q, want %q", ts[0].AppsPath, want)
	}
	if _, err := ts[0].Apps(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent file: %v", err)
	}
	testconfig.Content(t, want)
	if d, err := ts[0].Apps(); err != nil || d.Version() != "8000-1000" {
		t.Errorf("present file: %v %v", d, err)
	}
}
