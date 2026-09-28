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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/okaiser/panos-analyst/inventory"
)

// The document names the store reads itself. They must equal the names fetch gives
// them; store cannot import fetch (R12), so a test in cmd/panos-analyst checks.
const (
	ConfigDoc     = "config"
	InterfacesDoc = "interfaces"
	FIBDoc        = "fib"
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

// WithClock returns the store using another clock. Tests use it.
func (s *Store) WithClock(now func() time.Time) *Store {
	c := *s
	c.now = now
	return &c
}

// DefaultRoot returns where snapshots are kept: PANOS_STORE, else
// $XDG_DATA_HOME/panos-analyst, else ~/.local/share/panos-analyst.
func DefaultRoot(getenv func(string) string) (string, error) {
	if p := getenv("PANOS_STORE"); p != "" {
		return p, nil
	}
	if x := getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "panos-analyst"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("store: no home directory: %w", err)
	}
	return filepath.Join(home, ".local", "share", "panos-analyst"), nil
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
// down to keep. meta.Documents may list documents that failed; Write adds an entry
// for every document in docs that meta does not already name.
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
	tmp := filepath.Join(devDir, "."+id+".partial")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return Snapshot{}, fmt.Errorf("store: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		file := n + ".xml"
		if err := os.WriteFile(filepath.Join(tmp, file), docs[n], 0o600); err != nil {
			return Snapshot{}, fmt.Errorf("store: %w", err)
		}
		meta.Documents = recordFile(meta.Documents, n, file, len(docs[n]))
	}
	mb, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return Snapshot{}, fmt.Errorf("store: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "meta.json"), mb, 0o600); err != nil {
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
	if err := s.prune(meta.Device, keep); err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Device: meta.Device, ID: id, Dir: final, Meta: meta}, nil
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
func (s *Store) prune(device string, keep int) error {
	keep = max(keep, 1)
	ids, err := s.List(device)
	if err != nil {
		return err
	}
	latest, _ := os.Readlink(filepath.Join(s.root, device, "latest"))
	for _, id := range ids[min(keep, len(ids)):] {
		if id == latest {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.root, device, id)); err != nil {
			return fmt.Errorf("store: %w", err)
		}
	}
	return nil
}

// List returns a device's snapshot ids, newest first.
func (s *Store) List(device string) ([]string, error) {
	if !inventory.ValidName(device) {
		return nil, fmt.Errorf("store: device name %q is not valid", device)
	}
	entries, err := os.ReadDir(filepath.Join(s.root, device))
	if err != nil {
		return nil, fmt.Errorf("store: no snapshots of %s: %w", device, err)
	}
	var ids []string
	for _, e := range entries {
		if _, err := time.Parse(idLayout, e.Name()); err == nil && e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids, nil
}

// Latest returns the snapshot latest names.
func (s *Store) Latest(device string) (Snapshot, error) {
	if !inventory.ValidName(device) {
		return Snapshot{}, fmt.Errorf("store: device name %q is not valid", device)
	}
	id, err := os.Readlink(filepath.Join(s.root, device, "latest"))
	if err != nil {
		return Snapshot{}, fmt.Errorf("store: %s has no snapshot with a configuration; run panos-analyst fetch %s", device, device)
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
		return Snapshot{}, fmt.Errorf("store: no snapshot %s@%s", device, id)
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Snapshot{}, fmt.Errorf("store: %s@%s: meta.json: %w", device, id, err)
	}
	return Snapshot{Device: device, ID: id, Dir: dir, Meta: m}, nil
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
