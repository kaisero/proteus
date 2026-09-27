package index

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func zoneSnap(t *testing.T) *ZoneSnapshot {
	t.Helper()
	f, err := os.Open("../testdata/opdata/fw01-zone-snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s, err := LoadZoneSnapshot(f)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The device's own forwarding table places the addresses the configuration cannot,
// and names the interface and route that did it.
func TestZoneSnapshotPlacesAnAddress(t *testing.T) {
	s := zoneSnap(t)

	for _, c := range []struct{ addr, zone, iface, route string }{
		{"198.18.0.5", "transport", "ethernet1/1", "0.0.0.0/0"},
		{"198.18.10.100", "server", "ethernet1/2", "198.18.10.0/24"},
		{"100.64.0.5", "link-int-a", "ethernet1/6", "100.64.0.0/15"},
		{"198.19.255.1", "transport", "loopback.1", "198.19.255.1/32"},
	} {
		got := s.ZonesOf(netip.MustParseAddr(c.addr))
		var found bool
		for _, p := range got {
			if p.Zone == c.zone && p.Interface == c.iface && p.Route == c.route {
				found = true
			}
		}
		if !found {
			t.Errorf("%s = %+v, want zone %s via %s on %s", c.addr, got, c.zone, c.iface, c.route)
		}
	}
}

// Longest prefix wins inside a router: a host route beats the network holding it.
func TestZoneSnapshotPrefersTheMoreSpecificRoute(t *testing.T) {
	s := zoneSnap(t)

	got := s.ZonesOf(netip.MustParseAddr("198.18.10.1"))
	for _, p := range got {
		if p.Router == "default" && p.Route != "198.18.10.1/32" {
			t.Errorf("the host route should win, got %+v", p)
		}
	}
}

// Two routers can cover one address, and neither is the answer. This is the reason
// ZonesOf returns a set.
func TestZoneSnapshotReportsEveryRouter(t *testing.T) {
	s := zoneSnap(t)

	got := s.ZonesOf(netip.MustParseAddr("198.19.11.5"))
	zones := map[string]string{}
	for _, p := range got {
		zones[p.Zone] = p.Router
	}
	if zones["int-link-b"] != "lte" {
		t.Errorf("the specific route in lte is missing: %+v", got)
	}
	if zones["transport"] != "default" {
		t.Errorf("the default route in default is missing: %+v", got)
	}
	if len(got) != 2 {
		t.Errorf("got %d placements, want one per router: %+v", len(got), got)
	}
}

// An address no route covers places nothing, rather than falling back to a guess.
func TestZoneSnapshotPlacesNothingWithoutARoute(t *testing.T) {
	s := zoneSnap(t)

	// Every IPv4 address is covered by the default route here, so use IPv6: the
	// device has a v6 table and it is empty.
	if got := s.ZonesOf(netip.MustParseAddr("2001:db8::1")); len(got) != 0 {
		t.Errorf("an address with no route was placed: %+v", got)
	}
}

// A snapshot can be built from two responses without assembling JSON.
func TestNewZoneSnapshotFromTwoDocuments(t *testing.T) {
	fi, err := os.Open("../testdata/opdata/fw01-interface-all.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fi.Close() }()
	ff, err := os.Open("../testdata/opdata/fw01-advanced-routing-fib.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ff.Close() }()

	s, err := NewZoneSnapshot(time.Now(), "fw01", fi, ff)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Routers(); len(got) != 2 || got[0] != "default" || got[1] != "lte" {
		t.Errorf("routers = %v, want [default lte]", got)
	}
	if !strings.Contains(s.Describe(), "fw01") {
		t.Errorf("Describe = %q", s.Describe())
	}
}

// Two documents from different devices, or the wrong document entirely, are refused
// rather than silently producing an empty table.
func TestLoadZoneSnapshotRejectsBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"malformed json": `{`,
		"no interfaces":  `{"interfaces_xml":"<result/>","fib_xml":"<result/>"}`,
		"swapped fields": `{"interfaces_xml":"<result><fibs/></result>","fib_xml":"<result><ifnet/></result>"}`,
	} {
		if _, err := LoadZoneSnapshot(strings.NewReader(body)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A snapshot records where it came from, but its age is not enforced: an upstream
// tool supplies data fresh enough for the question, so the library does not
// second-guess it.
func TestZoneSnapshotDoesNotEnforceAge(t *testing.T) {
	s := zoneSnap(t)
	s.TakenAt = time.Now().Add(-365 * 24 * time.Hour)

	if _, ok := any(s).(StaleReporter); ok {
		t.Error("a zone snapshot should not report staleness; see the plan's D3")
	}
	if got := s.ZonesOf(netip.MustParseAddr("198.18.0.5")); len(got) == 0 {
		t.Error("an old snapshot still answers")
	}
}

// A route leaving by an interface in no zone places nothing, and is reported so the
// reason is visible. A lab firewall's configured default route pointed at a tunnel
// with no zone, which is how this case was found.
func TestZoneSnapshotReportsUnroutedInterfaces(t *testing.T) {
	s := zoneSnap(t)
	// Put the default route on tunnel.99, which the device reports as zoneless.
	s.FIBXML = strings.Replace(s.FIBXML,
		"<interface>ethernet1/1</interface>", "<interface>tunnel.99</interface>", 1)
	if err := s.index(); err != nil {
		t.Fatal(err)
	}

	got := s.UnroutedInterfaces()
	if len(got) != 1 || got[0] != "tunnel.99" {
		t.Errorf("unrouted = %v, want [tunnel.99]", got)
	}
	// And an address only that route covers is now unplaceable.
	if p := s.ZonesOf(netip.MustParseAddr("8.8.8.8")); len(p) != 0 {
		t.Errorf("an address behind a zoneless interface was placed: %+v", p)
	}
}

// Describe names whatever provenance the snapshot carries, and says so when it
// carries none.
func TestZoneSnapshotDescribe(t *testing.T) {
	s := zoneSnap(t)
	for _, want := range []string{"fw01", "serial", "taken"} {
		if !strings.Contains(s.Describe(), want) {
			t.Errorf("Describe = %q, want it to mention %s", s.Describe(), want)
		}
	}
	bare := &ZoneSnapshot{}
	if got := bare.Describe(); !strings.Contains(got, "unlabelled") {
		t.Errorf("an unlabelled snapshot describes itself as %q", got)
	}
}

// A reader that fails is reported rather than producing an empty snapshot.
func TestNewZoneSnapshotReportsAReadFailure(t *testing.T) {
	good, err := os.Open("../testdata/opdata/fw01-interface-all.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = good.Close() }()

	if _, err := NewZoneSnapshot(time.Time{}, "x", failingReader{}, good); err == nil {
		t.Error("a failing interface reader was accepted")
	}
	if _, err := NewZoneSnapshot(time.Time{}, "x", strings.NewReader("<result><ifnet/></result>"), failingReader{}); err == nil {
		t.Error("a failing fib reader was accepted")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errRead }

var errRead = os.ErrClosed

// Two documents that parse but describe nothing usable are refused, because an empty
// table would answer "no zone" for every address and look like a finding.
func TestLoadZoneSnapshotRefusesWhenNothingIsZoned(t *testing.T) {
	body := `{"interfaces_xml":"<result><ifnet><entry><name>tunnel.99</name><vsys>1</vsys></entry></ifnet></result>",` +
		`"fib_xml":"<result><fibs><entry><vr>default</vr><type>0</type><entries>` +
		`<entry><dst>0.0.0.0/0</dst><interface>tunnel.99</interface></entry></entries></entry></fibs></result>"}`
	_, err := LoadZoneSnapshot(strings.NewReader(body))
	if err == nil {
		t.Fatal("a snapshot with no zoned route was accepted")
	}
	if !strings.Contains(err.Error(), "different devices") {
		t.Errorf("the error does not suggest the likely cause: %v", err)
	}
}

// Two routes to the same destination in one router both survive, so an ECMP pair or a
// duplicated entry does not silently lose a path.
func TestZoneSnapshotKeepsBothRoutesToOneDestination(t *testing.T) {
	body := `{"interfaces_xml":"<result><ifnet>` +
		`<entry><name>ethernet1/1</name><vsys>1</vsys><zone>a</zone><fwd>lr:default</fwd></entry>` +
		`<entry><name>ethernet1/2</name><vsys>1</vsys><zone>b</zone><fwd>lr:default</fwd></entry>` +
		`</ifnet></result>",` +
		`"fib_xml":"<result><fibs><entry><vr>default</vr><type>0</type><entries>` +
		`<entry><dst>10.0.0.0/8</dst><interface>ethernet1/1</interface></entry>` +
		`<entry><dst>10.0.0.0/8</dst><interface>ethernet1/2</interface></entry>` +
		`</entries></entry></fibs></result>"}`
	s, err := LoadZoneSnapshot(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	got := s.ZonesOf(netip.MustParseAddr("10.1.2.3"))
	if len(got) != 2 {
		t.Fatalf("got %d placements, want both paths: %+v", len(got), got)
	}
}

// NewZoneSnapshot reports a document that reads but does not parse.
func TestNewZoneSnapshotReportsUnparsableDocuments(t *testing.T) {
	if _, err := NewZoneSnapshot(time.Time{}, "x",
		strings.NewReader("<result/>"), strings.NewReader("<result/>")); err == nil {
		t.Error("empty documents were accepted")
	}
}
