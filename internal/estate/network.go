package estate

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/store"
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
}

// NewNetwork groups the devices into nodes. It reads each device's snapshot
// metadata and HA state, not its configuration.
func NewNetwork(st *store.Store, devices []string, w When) *Network {
	n := &Network{
		st: st, w: w, node: map[string]string{}, pair: map[string][]string{}, pick: map[string]string{},
		data: map[string]simulate.DeviceData{}, errs: map[string]error{},
	}
	groups := map[string][]string{}
	var order []string
	active := map[string]bool{}
	for _, d := range devices {
		key := "device:" + d
		if sn, err := pick(st, d, w.At); err == nil {
			ha := readHA(sn)
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
		n.errs[node] = err
		n.w.Log.Warnf(runlog.TagSnap, "%s: hole: %v", node, err)
		return simulate.DeviceData{}, err
	}
	n.data[node] = d
	return d, nil
}

func (n *Network) read(node string) (simulate.DeviceData, error) {
	member := n.pick[node]
	sn, err := pick(n.st, member, n.w.At)
	if err != nil {
		return simulate.DeviceData{}, err
	}
	d := simulate.DeviceData{Name: node, SnapshotID: sn.ID, TakenAt: sn.Meta.TakenAt}
	b, err := os.ReadFile(sn.Path(store.InterfacesDoc))
	if err != nil {
		return d, fmt.Errorf("%s@%s has no interface state; fetch it again", member, sn.ID)
	}
	if d.Interfaces, err = resolve.ReadInterfaceStates(b); err != nil {
		return d, fmt.Errorf("%s@%s: %w", member, sn.ID, err)
	}
	b, err = os.ReadFile(sn.Path(store.FIBDoc))
	if err != nil {
		return d, fmt.Errorf("%s@%s has no forwarding table; fetch it again", member, sn.ID)
	}
	if d.FIB, err = resolve.ReadFIBRoutes(b); err != nil {
		return d, fmt.Errorf("%s@%s: %w", member, sn.ID, err)
	}
	if b, err := os.ReadFile(sn.Path(store.RIBDoc)); err == nil {
		d.RIB, _ = resolve.ReadRIBRoutes(b)
	}
	if members := n.pair[node]; len(members) > 1 {
		d.Notes = append(d.Notes, fmt.Sprintf("%v are one HA pair; %s answers for it", sorted(members), member))
	}
	if sn.Meta.FetchedFrom != "" {
		d.Notes = append(d.Notes, fmt.Sprintf("%s was passive; its snapshot comes from the active peer %s", member, sn.Meta.FetchedFrom))
	}
	if age := n.w.Now.Sub(sn.Meta.TakenAt); n.w.MaxAge > 0 && age > n.w.MaxAge {
		d.Notes = append(d.Notes, fmt.Sprintf("snapshot %s is %s old, past the %s limit", sn.ID, age.Round(time.Minute), n.w.MaxAge))
	}
	n.w.Log.Infof(runlog.TagSnap, "%s: routing data from %s@%s", node, member, sn.ID)
	return d, nil
}

// readHA reads a snapshot's HA state; the zero state when it has none.
func readHA(sn store.Snapshot) resolve.HAState {
	b, err := os.ReadFile(sn.Path(store.HADoc))
	if err != nil {
		return resolve.HAState{}
	}
	st, _ := resolve.ReadHAState(b)
	return st
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	slices.Sort(out)
	return out
}
