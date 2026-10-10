// Package store keeps fetched snapshots on disk, one timestamped directory per
// fetch, so any analysis can be repeated later against exactly what the device said.
//
//	<root>/<device>/<timestamp>/<document>.xml
//	<root>/<device>/<timestamp>/meta.json
//	<root>/<device>/latest -> <timestamp>
//
// Spec: docs/specs/2026-09-27-panos-analyst-scope.md §8.
package store

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/inventory"
)

// The document names the store reads itself. They must equal the names fetch gives
// them; store cannot import fetch (R12), so a test in internal/cli checks.
const (
	ConfigDoc     = "config"
	InterfacesDoc = "interfaces"
	FIBDoc        = "fib"
	RIBDoc        = "rib"
	HADoc         = "ha"
)

const idLayout = "2006-01-02T15-04-05Z"

// Store is a directory of snapshots.
type Store struct {
	root string
	now  func() time.Time
}

// Open returns the store at root, creating it private to its owner.
func Open(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	return &Store{root: root, now: time.Now}, nil
}

// At returns the store at root without creating it, for a reader that must not
// leave a directory behind. An absent root holds no snapshot; Write creates it,
// private to its owner, as Open does.
func At(root string) *Store { return &Store{root: root, now: time.Now} }

// WithClock returns the store using another clock. Tests use it.
func (s *Store) WithClock(now func() time.Time) *Store {
	c := *s
	c.now = now
	return &c
}

// DefaultRoot returns where snapshots are kept: PROTEUS_STORE, else
// $XDG_DATA_HOME/proteus, else ~/.local/share/proteus.
func DefaultRoot(getenv func(string) string) (string, error) {
	if p := getenv("PROTEUS_STORE"); p != "" {
		return p, nil
	}
	if x := getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "proteus"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("store: no home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "proteus"), nil
}

// Meta is a snapshot's meta.json.
type Meta struct {
	Device    string         `json:"device"`
	Host      string         `json:"host"`
	TakenAt   time.Time      `json:"taken_at"`
	Hostname  string         `json:"hostname,omitempty"`
	Model     string         `json:"model,omitempty"`
	Serial    string         `json:"serial,omitempty"`
	SWVersion string         `json:"sw_version,omitempty"`
	Documents []DocumentMeta `json:"documents"`
	// FetchedFrom is the host that answered when it is not the device's own: the
	// active peer of a device found passive.
	FetchedFrom string   `json:"fetched_from,omitempty"`
	Notes       []string `json:"notes,omitempty"`
}

// DocumentMeta is what happened to one document.
type DocumentMeta struct {
	Name  string `json:"name"`
	File  string `json:"file,omitempty"`
	Bytes int    `json:"bytes,omitempty"`
	Error string `json:"error,omitempty"`
}

// Write stores one fetch as a new snapshot.
//
// It writes into a hidden directory and renames it into place, so a reader never
// sees half a snapshot. It moves latest only when the configuration arrived, because
// nothing can be analysed without it, and then prunes the device's oldest snapshots
// down to keep with a configuration and keep without. meta.Documents may list
// documents that failed; Write adds an entry for every document in docs that meta
// does not already name.
func (s *Store) Write(meta Meta, docs map[string][]byte, keep int) (Snapshot, error) {
	if !inventory.ValidName(meta.Device) {
		return Snapshot{}, fmt.Errorf("store: device name %q is not safe as a directory name", meta.Device)
	}
	meta.TakenAt = s.now().UTC().Truncate(time.Second)
	id := meta.TakenAt.Format(idLayout)
	devDir := filepath.Join(s.root, meta.Device)
	final := filepath.Join(devDir, id)
	if _, err := os.Stat(final); err == nil {
		return Snapshot{}, fmt.Errorf("store: snapshot %s@%s already exists", meta.Device, id)
	}
	if err := os.MkdirAll(devDir, 0o700); err != nil {
		return Snapshot{}, fmt.Errorf("store: %w", err)
	}
	// Mkdir, not MkdirAll: a second writer of the same id fails here at once, and
	// only the writer that created the temporary directory removes it.
	tmp := filepath.Join(devDir, "."+id+".partial")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return Snapshot{}, fmt.Errorf("store: snapshot %s@%s is being written by another fetch", meta.Device, id)
		}
		return Snapshot{}, fmt.Errorf("store: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		file := n + ".xml"
		if err := writeFile(filepath.Join(tmp, file), docs[n]); err != nil {
			return Snapshot{}, fmt.Errorf("store: %w", err)
		}
		meta.Documents = recordFile(meta.Documents, n, file, len(docs[n]))
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return Snapshot{}, fmt.Errorf("store: %w", err)
	}
	if err := writeFile(filepath.Join(tmp, "meta.json"), mb); err != nil {
		return Snapshot{}, fmt.Errorf("store: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return Snapshot{}, fmt.Errorf("store: %w", err)
	}
	if _, ok := docs[ConfigDoc]; ok {
		if err := pointLatest(devDir, id); err != nil {
			return Snapshot{}, err
		}
	}
	// The renames live in the directories: sync them, so a crash cannot lose a
	// snapshot that Write reported stored.
	if err := cmp.Or(syncDir(final), syncDir(devDir)); err != nil {
		return Snapshot{}, fmt.Errorf("store: %w", err)
	}
	if err := s.prune(meta.Device, keep); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Device: meta.Device, ID: id, Dir: final, Meta: meta}, nil
}

// writeFile writes a file and syncs it, so its data reaches the disk before the
// snapshot is renamed into place.
func writeFile(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return cmp.Or(err, f.Sync(), f.Close())
}

// syncDir flushes a directory's entries to disk. It is the same as the one in
// internal/inventory; one small function does not earn a package of its own,
// and inventory's API is the inventory file.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return cmp.Or(d.Sync(), d.Close())
}

// recordFile fills in a document's file and size, adding an entry when the caller
// did not name the document.
func recordFile(docs []DocumentMeta, name, file string, size int) []DocumentMeta {
	for i := range docs {
		if docs[i].Name == name {
			docs[i].File, docs[i].Bytes = file, size
			return docs
		}
	}
	return append(docs, DocumentMeta{Name: name, File: file, Bytes: size})
}

// pointLatest replaces the latest link in one rename, so it always names a whole
// snapshot.
func pointLatest(devDir, id string) error {
	tmp := filepath.Join(devDir, ".latest-"+id)
	_ = os.Remove(tmp)
	if err := os.Symlink(id, tmp); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(devDir, "latest")); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("store: %w", err)
	}
	return nil
}

// prune removes a device's oldest snapshots beyond keep, never the one latest names.
// It counts the snapshots with a configuration and those without apart and keeps the
// newest keep of each, so a run of failed fetches cannot remove the last snapshots
// that can be analysed. A snapshot whose meta.json cannot be read counts as one
// without a configuration.
func (s *Store) prune(device string, keep int) error {
	keep = max(keep, 1)
	ids, err := s.List(device)
	if err != nil {
		return err
	}
	latest, _ := os.Readlink(filepath.Join(s.root, device, "latest"))
	kept := map[bool]int{}   // by whether the snapshot holds a configuration
	for _, id := range ids { // newest first
		withConfig := s.holdsConfig(device, id)
		kept[withConfig]++
		if kept[withConfig] <= keep || id == latest {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.root, device, id)); err != nil {
			return fmt.Errorf("store: %w", err)
		}
	}
	return nil
}

// holdsConfig reports whether a snapshot can be read and holds a configuration.
func (s *Store) holdsConfig(device, id string) bool {
	sn, err := s.Get(device, id)
	return err == nil && sn.Has(ConfigDoc)
}

// List returns a device's snapshot ids, newest first.
func (s *Store) List(device string) ([]string, error) {
	if !inventory.ValidName(device) {
		return nil, fmt.Errorf("store: device name %q is not valid", device)
	}
	entries, err := os.ReadDir(filepath.Join(s.root, device))
	if err != nil {
		return nil, missingOr(ErrNoSnapshot, fmt.Errorf("store: no snapshots of %s: %w", device, err), err)
	}
	var ids []string
	for _, e := range entries {
		if _, err := time.Parse(idLayout, e.Name()); err == nil && e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	slices.Sort(ids)
	slices.Reverse(ids)
	return ids, nil
}

// Latest returns the snapshot latest names.
func (s *Store) Latest(device string) (Snapshot, error) {
	if !inventory.ValidName(device) {
		return Snapshot{}, fmt.Errorf("store: device name %q is not valid", device)
	}
	id, err := os.Readlink(filepath.Join(s.root, device, "latest"))
	if err != nil {
		msg := fmt.Errorf("store: %s has no snapshot with a configuration; run proteus fetch %s", device, device)
		// latest moves only when a configuration arrived: snapshots without one
		// leave it absent, and that is a missing configuration.
		if ids, lerr := s.List(device); errors.Is(err, fs.ErrNotExist) && lerr == nil && len(ids) > 0 {
			return Snapshot{}, mark(ErrNoConfig, mark(ErrNoSnapshot, msg))
		}
		return Snapshot{}, missingOr(ErrNoSnapshot, msg, err)
	}
	return s.Get(device, id)
}

// Get returns one snapshot by id.
func (s *Store) Get(device, id string) (Snapshot, error) {
	if !inventory.ValidName(device) {
		return Snapshot{}, fmt.Errorf("store: device name %q is not valid", device)
	}
	if _, err := time.Parse(idLayout, id); err != nil {
		return Snapshot{}, fmt.Errorf("store: %q is not a snapshot id like 2026-09-28T10-00-00Z", id)
	}
	dir := filepath.Join(s.root, device, id)
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		if _, serr := os.Stat(dir); serr == nil {
			// The snapshot is there but its meta.json is not readable: Write renames a
			// snapshot into place whole, so it is damaged, not missing.
			return Snapshot{}, mark(ErrUnreadable, fmt.Errorf("store: %s@%s: meta.json: %w", device, id, err))
		}
		return Snapshot{}, missingOr(ErrNoSnapshot, fmt.Errorf("store: no snapshot %s@%s", device, id), err)
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Snapshot{}, mark(ErrUnreadable, fmt.Errorf("store: %s@%s: meta.json: %w", device, id, err))
	}
	return Snapshot{Device: device, ID: id, Dir: dir, Meta: m}, nil
}

// AtOrBefore returns the newest snapshot of a device that holds a configuration and
// was taken at or before t. Devices are fetched at different moments, so one time
// picks a different snapshot on each. Spec §15 C8.
func (s *Store) AtOrBefore(device string, t time.Time) (Snapshot, error) {
	ids, err := s.List(device)
	if err != nil {
		return Snapshot{}, err
	}
	early := false           // a snapshot at or before t exists, without a configuration
	for _, id := range ids { // newest first
		taken, _ := time.Parse(idLayout, id)
		if taken.After(t) {
			continue
		}
		sn, err := s.Get(device, id)
		if err != nil {
			return Snapshot{}, err
		}
		_, err = sn.ConfigPath()
		if err == nil {
			return sn, nil
		}
		if errors.Is(err, ErrUnreadable) {
			return Snapshot{}, err
		}
		early = true
	}
	err = mark(ErrNoSnapshot, fmt.Errorf("store: %s has no snapshot with a configuration at or before %s",
		device, t.UTC().Format(time.RFC3339)))
	if early {
		err = mark(ErrNoConfig, err)
	}
	return Snapshot{}, err
}

// Resolve reads a snapshot reference: a device name for its latest snapshot, or
// device@id for one in particular.
func (s *Store) Resolve(ref string) (Snapshot, error) {
	device, id, pinned := strings.Cut(ref, "@")
	if device == "" {
		return Snapshot{}, errors.New("store: an empty snapshot reference")
	}
	if pinned {
		return s.Get(device, id)
	}
	return s.Latest(device)
}
