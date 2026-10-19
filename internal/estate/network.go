package estate

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/runlog"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/store"
)

// Network is simulate.Network over the store: each inventory device's chosen
// snapshot, read once per run and only when asked for.
//
// The two members of an HA pair are one node (spec §17 R18). Both answer with the
// same interface addresses, so as two nodes every address in the pair would have
// two owners and every path through it would be unresolved. Members are paired by
// serial: the HA state names the peer's serial, and a passive entry fetched from
// its active peer carries that peer's serial itself.
type Network struct {
	st    *store.Store
	w     When
	nodes []string
	node  map[string]string   // device -> its node
	pair  map[string][]string // node -> its members, when more than one
	pick  map[string]string   // node -> the member whose snapshot answers
	data  map[string]simulate.DeviceData
	errs  map[string]error
	// haNotes holds, per device, why its HA state could not be read. Such a device
	// is not paired, so the note travels with its answers.
	haNotes map[string]reason.Reason
}

// OpTables is the operational data of one snapshot as read: the interface
// state, the forwarding table and the routing table. It holds no note and
// nothing that depends on when a question is asked, so a cache can share it
// between questions per (member, snapshot id). The notes are built per question
// from the snapshot meta and When (spec 2026-10-09 §12 C13).
type OpTables struct {
	Interfaces []resolve.InterfaceState
	FIB        []resolve.FIBRoute
	RIB        []resolve.RIBRoute // nil when the snapshot has none
	// RIBErr says why a routing table the snapshot holds cannot be read.
	RIBErr error
}

// OpSource reads a snapshot's operational data. Every answer depends only on
// the snapshot (its device and id), so an implementation may cache by them.
// The returned values are shared: a caller must not change them. A source a
// server shares between questions must be safe for concurrent use.
type OpSource interface {
	// HA reads the snapshot's HA state: the zero state when the snapshot has
	// none, an error when it has one that cannot be read.
	HA(sn store.Snapshot) (resolve.HAState, error)
	// Tables reads the snapshot's interfaces, FIB and RIB. A missing interface
	// state or FIB is an error with its gap code (GapOf).
	Tables(sn store.Snapshot) (OpTables, error)
}

// DiskOps reads the operational data from the store on every ask.
type DiskOps struct{}

// HA implements OpSource.
func (DiskOps) HA(sn store.Snapshot) (resolve.HAState, error) { return readHA(sn) }

// Tables implements OpSource.
func (DiskOps) Tables(sn store.Snapshot) (OpTables, error) {
	var t OpTables
	b, err := os.ReadFile(sn.Path(store.InterfacesDoc))
	if err != nil {
		return t, coded("gap.interfaces-missing", fmt.Errorf("%s@%s has no interface state; fetch it again", sn.Device, sn.ID))
	}
	if t.Interfaces, err = resolve.ReadInterfaceStates(b); err != nil {
		return t, fmt.Errorf("%s@%s: %w", sn.Device, sn.ID, err)
	}
	b, err = os.ReadFile(sn.Path(store.FIBDoc))
	if err != nil {
		return t, coded("gap.fib-missing", fmt.Errorf("%s@%s has no forwarding table; fetch it again", sn.Device, sn.ID))
	}
	if t.FIB, err = resolve.ReadFIBRoutes(b); err != nil {
		return t, fmt.Errorf("%s@%s: %w", sn.Device, sn.ID, err)
	}
	if b, err := os.ReadFile(sn.Path(store.RIBDoc)); err == nil {
		t.RIB, t.RIBErr = resolve.ReadRIBRoutes(b)
	}
	return t, nil
}

// NewNetwork groups the devices into nodes. It reads each device's snapshot
// metadata and HA state, not its configuration. The operational data comes
// from w.Ops, or from the store when it is nil.
func NewNetwork(st *store.Store, devices []string, w When) *Network {
	n := &Network{
		st: st, w: w, node: map[string]string{}, pair: map[string][]string{}, pick: map[string]string{},
		data: map[string]simulate.DeviceData{}, errs: map[string]error{}, haNotes: map[string]reason.Reason{},
	}
	groups := map[string][]string{}
	var order []string
	active := map[string]bool{}
	for _, d := range devices {
		key := "device:" + d
		if sn, err := pick(st, d, w.At); err == nil {
			ha, err := w.ops().HA(sn)
			if err != nil {
				n.haNotes[d] = reason.New("note.ha-unreadable", fmt.Sprintf("%s: HA state unreadable, so it is not paired with its peer: %v", d, err))
				w.Log.Warnf(runlog.TagSnap, "%s", n.haNotes[d].Text)
			}
			switch {
			case ha.Enabled && ha.LocalSerial != "" && ha.PeerSerial != "":
				key = "serial:" + min(ha.LocalSerial, ha.PeerSerial) + "+" + max(ha.LocalSerial, ha.PeerSerial)
				active[d] = ha.LocalState == "active" || sn.Meta.FetchedFrom != ""
			case sn.Meta.Serial != "":
				key = "serial:" + sn.Meta.Serial
			}
		}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], d)
	}
	// A member keyed by its serial alone, such as one fetched before HA state was
	// stored, joins the pair that names that serial.
	pairOf := map[string]string{}
	for _, key := range order {
		if a, b, ok := strings.Cut(strings.TrimPrefix(key, "serial:"), "+"); ok && strings.HasPrefix(key, "serial:") {
			pairOf["serial:"+a], pairOf["serial:"+b] = key, key
		}
	}
	var merged []string
	for _, key := range order {
		if p, ok := pairOf[key]; ok {
			groups[p] = append(groups[p], groups[key]...)
			continue
		}
		merged = append(merged, key)
	}
	for _, key := range merged {
		members := groups[key]
		name := members[0]
		n.nodes = append(n.nodes, name)
		n.pick[name] = members[0]
		for _, m := range members {
			n.node[m] = name
			if active[m] {
				n.pick[name] = m
			}
		}
		if len(members) > 1 {
			n.pair[name] = members
		}
	}
	return n
}

// Devices names one node per firewall, in inventory order.
func (n *Network) Devices() []string { return n.nodes }

// Device reads a node's data on first use.
func (n *Network) Device(name string) (simulate.DeviceData, error) {
	node, ok := n.node[name]
	if !ok {
		return simulate.DeviceData{}, fmt.Errorf("no device %q in the inventory", name)
	}
	if d, ok := n.data[node]; ok {
		return d, nil
	}
	if err, ok := n.errs[node]; ok {
		return simulate.DeviceData{}, err
	}
	d, err := n.read(node)
	if err != nil {
		err = &simulate.UnavailableError{Missing: []simulate.Missing{simulate.NewMissing(node, reason.New(GapOf(err), err.Error()))}}
		n.errs[node] = err
		n.w.Log.Warnf(runlog.TagSnap, "%s: hole: %v", node, err)
		return simulate.DeviceData{}, err
	}
	n.data[node] = d
	return d, nil
}

// Read names each snapshot the run read, as member@snapshot-id, sorted: for an
// HA pair the member whose snapshot answered, for a single device the device.
func (n *Network) Read() []string {
	var out []string
	for _, d := range n.data {
		out = append(out, d.Member+"@"+d.SnapshotID)
	}
	slices.Sort(out)
	return out
}

func (n *Network) read(node string) (simulate.DeviceData, error) {
	member := n.pick[node]
	sn, err := pick(n.st, member, n.w.At)
	if err != nil {
		return simulate.DeviceData{}, err
	}
	d := simulate.DeviceData{Name: node, Member: member, SnapshotID: sn.ID, TakenAt: sn.Meta.TakenAt}
	t, err := n.w.ops().Tables(sn)
	if err != nil {
		return d, err
	}
	d.Interfaces, d.FIB, d.RIB = t.Interfaces, t.FIB, t.RIB
	if t.RIBErr != nil {
		d.Notes = append(d.Notes, reason.New("note.rib-unreadable",
			fmt.Sprintf("%s@%s: routing table unreadable, so route protocols and alternates are missing: %v", member, sn.ID, t.RIBErr)))
	}
	for _, m := range n.pairOrSelf(node) {
		if note, ok := n.haNotes[m]; ok {
			d.Notes = append(d.Notes, note)
		}
	}
	if members := n.pair[node]; len(members) > 1 {
		d.Notes = append(d.Notes, reason.New("note.ha-peer", fmt.Sprintf("%v are one HA pair; %s answers for it", sorted(members), member)))
	}
	if sn.Meta.FetchedFrom != "" {
		d.Notes = append(d.Notes, reason.New("note.ha-from-peer",
			fmt.Sprintf("%s was passive; its snapshot comes from the active peer %s", member, sn.Meta.FetchedFrom)))
	}
	if note, ok := SkipNote(sn); ok {
		d.Notes = append(d.Notes, note)
	}
	if age := n.w.Now.Sub(sn.Meta.TakenAt); n.w.MaxAge > 0 && age > n.w.MaxAge {
		d.Notes = append(d.Notes, reason.New("note.snapshot-stale", StaleNote(sn.ID, age, n.w.MaxAge)))
	}
	n.w.Log.Infof(runlog.TagSnap, "%s: routing data from %s@%s", node, member, sn.ID)
	return d, nil
}

// readHA reads a snapshot's HA state: the zero state when the snapshot has none,
// and an error when it has one that cannot be read.
func readHA(sn store.Snapshot) (resolve.HAState, error) {
	b, err := os.ReadFile(sn.Path(store.HADoc))
	if err != nil {
		return resolve.HAState{}, nil
	}
	return resolve.ReadHAState(b)
}

// pairOrSelf returns the members of a node: its HA pair, or the node alone.
func (n *Network) pairOrSelf(node string) []string {
	if members := n.pair[node]; len(members) > 0 {
		return members
	}
	return []string{node}
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	slices.Sort(out)
	return out
}
