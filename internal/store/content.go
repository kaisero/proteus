package store

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/inventory"
)

// ContentDir holds the App-ID content files, one per content version, for all
// devices. A device name cannot start with a dot, so it is no device (spec
// 2026-10-16 §3.1).
const ContentDir = ".content"

// ContentPath returns where the content file of a version is stored, or ""
// when version is not a content version and so cannot name a file.
func (s *Store) ContentPath(version string) string {
	return contentPath(s.root, version)
}

func contentPath(root, version string) string {
	if !appid.ValidVersion(version) {
		return ""
	}
	return filepath.Join(root, ContentDir, appid.FileName(version))
}

// HaveContent reports whether the content file of a version is stored. A hit
// sets the file's modification time to now, so a prune in another process
// leaves the file this fetch reuses. A file whose time cannot be set is a miss
// (spec 2026-10-16 §2.2, §3.4). The time is the wall clock's, as the prune
// compares it with the wall clock.
func (s *Store) HaveContent(version string) bool {
	p := s.ContentPath(version)
	if p == "" {
		return false
	}
	chtimes := os.Chtimes
	if s.chtimes != nil {
		chtimes = s.chtimes
	}
	now := time.Now()
	return chtimes(p, now, now) == nil
}

// WriteContent stores the content file of a version. It writes a temporary
// file in ContentDir, syncs it and renames it into place, so a reader never
// sees half a file. Writers of one version replace each other whole (spec
// 2026-10-16 §3.4).
func (s *Store) WriteContent(version string, b []byte) error {
	p := s.ContentPath(version)
	if p == "" {
		return fmt.Errorf("store: %q is not a content version like 9159-10287", version)
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	// CreateTemp makes the file 0600, under a name no other writer takes.
	f, err := os.CreateTemp(dir, "."+filepath.Base(p)+".*.tmp")
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err = cmp.Or(err, f.Sync(), f.Close(), os.Rename(tmp, p)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("store: content %s: %w", version, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("store: content %s is stored but not synced: %w", version, err)
	}
	return nil
}

// PruneContent removes the content files that no snapshot's meta.json names
// and whose modification time is older than leftoverAge, with the temporary
// files of crashed writes. The store has no lock: the age keeps a file that a
// fetch in another process writes or reuses now (spec 2026-10-16 §3.4). A
// device directory it cannot read could name any file, so it then removes
// nothing. A damaged snapshot names no file a reader can use.
func (s *Store) PruneContent() error {
	dir := filepath.Join(s.root, ContentDir)
	files, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	named, err := s.namedContent()
	if err != nil {
		return err
	}
	now := time.Now()
	var errs []error
	for _, e := range files {
		if !e.Type().IsRegular() || named[e.Name()] {
			continue
		}
		fi, err := e.Info()
		if err != nil || now.Sub(fi.ModTime()) <= leftoverAge {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// namedContent returns the names of the content files that a snapshot of any
// device names. It reads only the directories with a device name, so it
// passes over ContentDir and the other dot directories.
func (s *Store) namedContent() (map[string]bool, error) {
	devices, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	named := map[string]bool{}
	for _, d := range devices {
		if !d.IsDir() || !inventory.ValidName(d.Name()) {
			continue
		}
		ids, err := s.List(d.Name())
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			sn, err := s.Get(d.Name(), id)
			if err == nil && appid.ValidVersion(sn.Meta.AppVersion) {
				named[appid.FileName(sn.Meta.AppVersion)] = true
			}
		}
	}
	return named, nil
}
