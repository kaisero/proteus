package store

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/okaiser/proteus/internal/index"
)

// Snapshot is one stored fetch.
type Snapshot struct {
	Device string
	ID     string
	Dir    string
	Meta   Meta
	// Skipped names the damaged snapshots, newest first, that AtOrBefore passed
	// over to pick this one. Every other lookup leaves it empty.
	Skipped []string
}

// Path returns where a document of this snapshot is stored.
func (sn Snapshot) Path(doc string) string { return filepath.Join(sn.Dir, doc+".xml") }

// ConfigPath returns where this snapshot's configuration is stored, or an error
// that matches ErrNoConfig when the configuration did not arrive.
// A configuration that is there but cannot be read gives one that matches
// ErrUnreadable.
func (sn Snapshot) ConfigPath() (string, error) {
	p := sn.Path(ConfigDoc)
	if _, err := os.Stat(p); err != nil {
		return "", missingOr(ErrNoConfig, fmt.Errorf("store: %s@%s has no configuration", sn.Device, sn.ID), err)
	}
	return p, nil
}

// Zones builds the zone snapshot the index reads, from this snapshot's interface
// list and forwarding table. A zone answer then comes from what the device was
// doing, not from an inference from its configuration. A document that is absent
// gives an error that matches fs.ErrNotExist; one that cannot be read or parsed
// gives one that matches ErrUnreadable.
func (sn Snapshot) Zones() (*index.ZoneSnapshot, error) {
	i, err := os.Open(sn.Path(InterfacesDoc))
	if err != nil {
		return nil, unreadable(fmt.Errorf("store: %s@%s has no interface list: %w", sn.Device, sn.ID, err), err)
	}
	defer func() { _ = i.Close() }()
	f, err := os.Open(sn.Path(FIBDoc))
	if err != nil {
		return nil, unreadable(fmt.Errorf("store: %s@%s has no forwarding table: %w", sn.Device, sn.ID, err), err)
	}
	defer func() { _ = f.Close() }()
	zs, err := index.NewZoneSnapshot(sn.Meta.TakenAt, sn.Meta.Host, i, f)
	if err != nil {
		return nil, mark(ErrUnreadable, err)
	}
	return zs, nil
}
