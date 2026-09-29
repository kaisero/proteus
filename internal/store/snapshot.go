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
}

// Path returns where a document of this snapshot is stored.
func (sn Snapshot) Path(doc string) string { return filepath.Join(sn.Dir, doc+".xml") }

// Has reports whether a document arrived in this snapshot.
func (sn Snapshot) Has(doc string) bool {
	_, err := os.Stat(sn.Path(doc))
	return err == nil
}

// Zones builds the zone snapshot the index reads, from this snapshot's interface
// list and forwarding table. A zone answer then comes from what the device was
// doing, not from an inference from its configuration.
func (sn Snapshot) Zones() (*index.ZoneSnapshot, error) {
	i, err := os.Open(sn.Path(InterfacesDoc))
	if err != nil {
		return nil, fmt.Errorf("store: %s@%s has no interface list: %w", sn.Device, sn.ID, err)
	}
	defer func() { _ = i.Close() }()
	f, err := os.Open(sn.Path(FIBDoc))
	if err != nil {
		return nil, fmt.Errorf("store: %s@%s has no forwarding table: %w", sn.Device, sn.ID, err)
	}
	defer func() { _ = f.Close() }()
	return index.NewZoneSnapshot(sn.Meta.TakenAt, sn.Meta.Host, i, f)
}
