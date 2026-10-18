package estate

import (
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/store"
)

func opdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/opdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// haDoc is a synthetic HA state: no lab device runs HA.
func haDoc(local, localSerial, peerSerial string) []byte {
	return []byte(`<response status="success"><result><enabled>yes</enabled><group><mode>active-passive</mode>` +
		`<local-info><state>` + local + `</state><serial-num>` + localSerial + `</serial-num></local-info>` +
		`<peer-info><state>x</state><serial-num>` + peerSerial + `</serial-num></peer-info></group></result></response>`)
}

type snap struct {
	dev, serial, from string
	at                time.Time
	docs              map[string][]byte
}

func networkStore(t *testing.T, snaps ...snap) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	i := 0
	st = st.WithClock(func() time.Time { i++; return snaps[i-1].at })
	for _, s := range snaps {
		docs := map[string][]byte{store.ConfigDoc: fixture(t, "firewall-lab.xml")}
		maps.Copy(docs, s.docs)
		if _, err := st.Write(store.Meta{Device: s.dev, Serial: s.serial, FetchedFrom: s.from}, docs, nil, 20); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

func routingDocs(t *testing.T, dev string, extra map[string][]byte) map[string][]byte {
	out := map[string][]byte{
		store.InterfacesDoc: opdata(t, dev+"-interface-all.xml"),
		store.FIBDoc:        opdata(t, dev+"-advanced-routing-fib.xml"),
	}
	maps.Copy(out, extra)
	return out
}

func TestNetworkReadsEachDeviceOnce(t *testing.T) {
	t.Parallel()
	st := networkStore(t,
		snap{dev: "fw01", serial: "S1", at: t0, docs: routingDocs(t, "fw01", nil)},
		snap{dev: "fw02", serial: "S2", at: t0, docs: routingDocs(t, "fw02", map[string][]byte{store.RIBDoc: opdata(t, "fw02-advanced-routing-route.xml")})},
		snap{dev: "fw01", serial: "S1", at: t0.Add(time.Hour), docs: routingDocs(t, "fw02", nil)},
	)
	n := NewNetwork(st, []string{"fw01", "fw02", "fw03"}, When{Now: t0.Add(3 * time.Hour), MaxAge: 2 * time.Hour})
	if strings.Join(n.Devices(), ",") != "fw01,fw02,fw03" {
		t.Errorf("devices = %v", n.Devices())
	}
	d, err := n.Device("fw02")
	if err != nil || len(d.Interfaces) == 0 || len(d.FIB) == 0 || len(d.RIB) != 15 || d.TakenAt != t0 {
		t.Fatalf("fw02 = %+v, %v", d, err)
	}
	if again, _ := n.Device("fw02"); again.SnapshotID != d.SnapshotID {
		t.Error("a second ask returns the same data")
	}
	if len(d.Notes) != 1 || !strings.Contains(d.Notes[0].Text, "past the 2h0m0s limit") || d.Notes[0].Code != "note.snapshot-stale" {
		t.Errorf("fw02 notes = %v", d.Notes)
	}
	// Latest by default; --at picks the older fw01 snapshot.
	if d, _ := n.Device("fw01"); d.TakenAt != t0.Add(time.Hour) || d.RIB != nil {
		t.Errorf("fw01 latest = %+v", d)
	}
	old := NewNetwork(st, []string{"fw01"}, When{At: t0.Add(time.Minute)})
	if d, _ := old.Device("fw01"); d.TakenAt != t0 {
		t.Errorf("fw01 at = %v", d.TakenAt)
	}
	if _, err := n.Device("fw03"); err == nil {
		t.Error("a device without a snapshot is an error")
	}
	if _, err := n.Device("fw03"); err == nil {
		t.Error("the error is remembered")
	}
	if _, err := n.Device("nope"); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Errorf("unknown device: %v", err)
	}
}

func TestNetworkNeedsInterfacesAndTables(t *testing.T) {
	t.Parallel()
	st := networkStore(t,
		snap{dev: "a", at: t0},
		snap{dev: "b", at: t0, docs: map[string][]byte{store.InterfacesDoc: opdata(t, "fw02-interface-all.xml")}},
		snap{dev: "c", at: t0, docs: map[string][]byte{store.InterfacesDoc: []byte("<x/>"), store.FIBDoc: opdata(t, "fw02-advanced-routing-fib.xml")}},
		snap{dev: "d", at: t0, docs: map[string][]byte{store.InterfacesDoc: opdata(t, "fw02-interface-all.xml"), store.FIBDoc: []byte("<x/>")}},
	)
	n := NewNetwork(st, []string{"a", "b", "c", "d"}, When{})
	for dev, want := range map[string]struct {
		text string
		code reason.Code
	}{
		"a": {"no interface state", "gap.interfaces-missing"}, "b": {"no forwarding table", "gap.fib-missing"},
		"c": {"op data", "gap.load-failed"}, "d": {"op data", "gap.load-failed"},
	} {
		_, err := n.Device(dev)
		u, ok := errors.AsType[*simulate.UnavailableError](err)
		if !ok || !strings.Contains(err.Error(), want.text) || u.Missing[0].Code != want.code {
			t.Errorf("%s: %v", dev, err)
		}
	}
}

// Both members of an HA pair in the inventory are one node: the active one answers.
func TestNetworkCollapsesAnHAPair(t *testing.T) {
	t.Parallel()
	st := networkStore(t,
		snap{dev: "fw-a", serial: "A", at: t0, docs: routingDocs(t, "fw01", map[string][]byte{store.HADoc: haDoc("passive", "A", "B")})},
		snap{dev: "fw-b", serial: "B", at: t0.Add(time.Minute), docs: routingDocs(t, "fw02", map[string][]byte{store.HADoc: haDoc("active", "B", "A")})},
		snap{dev: "other", serial: "C", at: t0, docs: routingDocs(t, "fw01", nil)},
	)
	n := NewNetwork(st, []string{"fw-a", "fw-b", "other"}, When{})
	if strings.Join(n.Devices(), ",") != "fw-a,other" {
		t.Fatalf("nodes = %v", n.Devices())
	}
	d, err := n.Device("fw-b") // a member name returns its pair's node
	if err != nil || d.Name != "fw-a" || d.TakenAt != t0.Add(time.Minute) {
		t.Fatalf("pair = %+v, %v", d, err)
	}
	// The active member's name and snapshot, not the node's first member.
	if active, err := st.Latest("fw-b"); err != nil || d.Member != "fw-b" || d.SnapshotID != active.ID {
		t.Errorf("member = %s@%s, want fw-b@%s (%v)", d.Member, d.SnapshotID, active.ID, err)
	}
	o, _ := n.Device("other")
	if o.Member != "other" {
		t.Errorf("single device member = %q", o.Member)
	}
	// Read names the member that answered, once per node read.
	if want := []string{"fw-b@" + d.SnapshotID, "other@" + o.SnapshotID}; !slices.Equal(n.Read(), want) {
		t.Errorf("read = %v, want %v", n.Read(), want)
	}
	if len(d.Notes) != 1 || !strings.Contains(d.Notes[0].Text, "[fw-a fw-b] are one HA pair; fw-b answers") || d.Notes[0].Code != "note.ha-peer" {
		t.Errorf("notes = %v", d.Notes)
	}
}

// A passive entry fetched from its peer, next to a peer entry fetched before HA
// state was stored: one node, and the note says where the data came from.
func TestNetworkJoinsAMemberWithoutHAState(t *testing.T) {
	t.Parallel()
	st := networkStore(t,
		snap{dev: "fw-a", serial: "B", from: "192.0.2.2", at: t0, docs: routingDocs(t, "fw02", map[string][]byte{store.HADoc: haDoc("active", "B", "A")})},
		snap{dev: "fw-b", serial: "B", at: t0, docs: routingDocs(t, "fw02", nil)},
	)
	n := NewNetwork(st, []string{"fw-a", "fw-b"}, When{})
	if strings.Join(n.Devices(), ",") != "fw-a" {
		t.Fatalf("nodes = %v", n.Devices())
	}
	d, _ := n.Device("fw-a")
	if len(d.Notes) != 2 || !strings.Contains(d.Notes[1].Text, "from the active peer 192.0.2.2") || d.Notes[1].Code != "note.ha-from-peer" {
		t.Errorf("notes = %v", d.Notes)
	}
}

// A routing table or HA state that is present but unreadable must not look like
// one that is absent: the device's answers carry a note that says why.
func TestNetworkNotesUnreadableOptionalDocuments(t *testing.T) {
	t.Parallel()
	garbage := []byte("<response status=\"success\"><result>")
	st := networkStore(t,
		snap{dev: "fw01", serial: "S1", at: t0, docs: routingDocs(t, "fw01", map[string][]byte{
			store.RIBDoc: garbage,
			store.HADoc:  garbage,
		})},
	)
	d, err := NewNetwork(st, []string{"fw01"}, When{Now: t0}).Device("fw01")
	if err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(d.Notes.Texts(), "\n")
	if !strings.Contains(notes, "routing table unreadable") || !strings.Contains(notes, "HA state unreadable") {
		t.Errorf("notes = %v", d.Notes)
	}
	if d.RIB != nil {
		t.Errorf("an unreadable routing table holds no routes, got %d", len(d.RIB))
	}
}

// A device in the inventory with no snapshot is missing data, not the user's
// mistake; a name the inventory does not have is the user's mistake, not missing
// data.
func TestAnUnreadableDeviceIsUnavailable(t *testing.T) {
	t.Parallel()
	st := networkStore(t)
	n := NewNetwork(st, []string{"fw1"}, When{Now: time.Now()})
	_, err := n.Device("fw1")
	u, ok := errors.AsType[*simulate.UnavailableError](err)
	if !ok || len(u.Missing) != 1 || u.Missing[0].Device != "fw1" {
		t.Errorf("err = %v, want an UnavailableError for fw1", err)
	}
	if _, err := n.Device("fw9"); err == nil {
		t.Fatal("fw9 is not in the inventory")
	} else if _, ok := errors.AsType[*simulate.UnavailableError](err); ok {
		t.Error("a name not in the inventory is the user's mistake, not missing data")
	}
}

// countingOps caches DiskOps by snapshot, as a server cache would, and counts
// the reads that reach the store.
type countingOps struct {
	mu     sync.Mutex
	tables map[string]OpTables
	ha     map[string]resolve.HAState
	reads  int
}

func (c *countingOps) HA(sn store.Snapshot) (resolve.HAState, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h, ok := c.ha[sn.Device+"@"+sn.ID]; ok {
		return h, nil
	}
	h, err := DiskOps{}.HA(sn)
	if err == nil {
		c.ha[sn.Device+"@"+sn.ID] = h
	}
	return h, err
}

func (c *countingOps) Tables(sn store.Snapshot) (OpTables, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tables[sn.Device+"@"+sn.ID]; ok {
		return t, nil
	}
	c.reads++
	t, err := DiskOps{}.Tables(sn)
	if err == nil {
		c.tables[sn.Device+"@"+sn.ID] = t
	}
	return t, err
}

// A shared source holds the tables; every network builds its notes from its own
// clock, so a cached snapshot turns stale when the clock passes the limit.
func TestNetworkBuildsNotesPerQuestionOverSharedTables(t *testing.T) {
	t.Parallel()
	garbage := []byte("<response status=\"success\"><result>")
	st := networkStore(t,
		snap{dev: "fw-a", serial: "A", at: t0, docs: routingDocs(t, "fw01", map[string][]byte{
			store.HADoc: haDoc("active", "A", "B"), store.RIBDoc: garbage,
		})},
		snap{dev: "fw-b", serial: "B", at: t0, docs: routingDocs(t, "fw02", map[string][]byte{store.HADoc: haDoc("passive", "B", "A")})},
	)
	ops := &countingOps{tables: map[string]OpTables{}, ha: map[string]resolve.HAState{}}
	codes := func(now time.Time) []reason.Code {
		t.Helper()
		d, err := NewNetwork(st, []string{"fw-a", "fw-b"}, When{Now: now, MaxAge: time.Hour, Ops: ops}).Device("fw-a")
		if err != nil {
			t.Fatal(err)
		}
		var out []reason.Code
		for _, n := range d.Notes {
			out = append(out, n.Code)
		}
		return out
	}
	fresh, stale := codes(t0), codes(t0.Add(2*time.Hour))
	if want := []reason.Code{"note.rib-unreadable", "note.ha-peer"}; !slices.Equal(fresh, want) {
		t.Errorf("fresh notes = %v, want %v", fresh, want)
	}
	if want := []reason.Code{"note.rib-unreadable", "note.ha-peer", "note.snapshot-stale"}; !slices.Equal(stale, want) {
		t.Errorf("stale notes = %v, want %v", stale, want)
	}
	if ops.reads != 1 {
		t.Errorf("tables read %d times, want once", ops.reads)
	}
}
