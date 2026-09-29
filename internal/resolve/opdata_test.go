package resolve

import (
	"os"
	"testing"
)

func opFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/opdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The ifnet section carries interface, zone, vsys, router and address together. It is
// what the configuration-derived reader has to infer from three separate places.
func TestReadInterfaceStates(t *testing.T) {
	got, err := ReadInterfaceStates(opFixture(t, "fw01-interface-all.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 19 {
		t.Fatalf("got %d interfaces, want 19", len(got))
	}
	by := map[string]InterfaceState{}
	for _, i := range got {
		by[i.Name] = i
	}

	eth1 := by["ethernet1/1"]
	if eth1.Zone != "transport" || eth1.Router != "default" || eth1.Vsys != "1" {
		t.Errorf("ethernet1/1 = %+v", eth1)
	}
	if eth1.Prefix.String() != "198.19.0.254/24" {
		t.Errorf("ethernet1/1 prefix = %s", eth1.Prefix)
	}

	// A subinterface stands on its own, with its own zone.
	if sub := by["ethernet1/9.20"]; sub.Zone != "dmz-ext" || sub.Prefix.String() != "198.18.20.1/24" {
		t.Errorf("ethernet1/9.20 = %+v", sub)
	}
	// A loopback carries a host address.
	if lo := by["loopback.1"]; lo.Zone != "transport" || lo.Prefix.String() != "198.19.255.1/32" {
		t.Errorf("loopback.1 = %+v", lo)
	}
	// A zone can span routers.
	if by["ethernet1/8"].Router != "lte" || by["ethernet1/8"].Zone != "transport" {
		t.Errorf("ethernet1/8 = %+v, want zone transport in router lte", by["ethernet1/8"])
	}
	// A tunnel in a zone with no address is still an interface.
	if tun := by["tunnel.1"]; tun.Zone != "prisma" || tun.Prefix.IsValid() {
		t.Errorf("tunnel.1 = %+v, want zone prisma and no address", tun)
	}
	// An unrouted parent interface has no router and no zone, and "N/A" is not an
	// address.
	for _, n := range []string{"ethernet1/9", "loopback", "tunnel", "tunnel.99"} {
		if e := by[n]; e.Router != "" || e.Zone != "" || e.Prefix.IsValid() {
			t.Errorf("%s = %+v, want unrouted and zoneless", n, e)
		}
	}
}

// One table per router per address family. The lab firewall has two routers whose
// space overlaps, which is the case that makes a single answer impossible.
func TestReadFIBRoutes(t *testing.T) {
	got, err := ReadFIBRoutes(opFixture(t, "fw01-advanced-routing-fib.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 25 {
		t.Fatalf("got %d routes, want 25", len(got))
	}
	routers := map[string]int{}
	for _, r := range got {
		routers[r.Router]++
		if r.IPv6 {
			t.Errorf("no IPv6 routes are configured, got %+v", r)
		}
	}
	if routers["default"] != 23 || routers["lte"] != 2 {
		t.Errorf("routes per router = %v, want default 23 and lte 2", routers)
	}

	var def, host *FIBRoute
	for i := range got {
		if got[i].Destination.String() == "0.0.0.0/0" {
			def = &got[i]
		}
		if got[i].Flags == "uh" && host == nil {
			host = &got[i]
		}
	}
	if def == nil || def.Interface != "ethernet1/1" || def.NextHop != "198.19.0.1" {
		t.Errorf("default route = %+v", def)
	}
	// Host routes for the device's own addresses are kept; longest prefix handles them.
	if host == nil {
		t.Error("no host route found; the fixture should contain several")
	}
}

// A destination is masked, so a route written as an address keeps a usable prefix.
func TestReadFIBRoutesMasksDestinations(t *testing.T) {
	got, err := ReadFIBRoutes(opFixture(t, "fw01-advanced-routing-fib.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Destination != r.Destination.Masked() {
			t.Errorf("%s is not masked", r.Destination)
		}
	}
}

// The CLI prints a bare result with op-command-xml-output on, while the API wraps it.
// Both have to load.
func TestReadOpDataAcceptsBothEnvelopes(t *testing.T) {
	wrapped := opFixture(t, "fw01-interface-all.xml")
	if _, err := ReadInterfaceStates(wrapped); err != nil {
		t.Fatalf("wrapped: %v", err)
	}
	bare := []byte(`<result><ifnet><entry><name>ethernet1/1</name><zone>z</zone>` +
		`<vsys>1</vsys><fwd>lr:default</fwd><ip>10.0.0.1/24</ip></entry></ifnet></result>`)
	got, err := ReadInterfaceStates(bare)
	if err != nil {
		t.Fatalf("bare: %v", err)
	}
	if len(got) != 1 || got[0].Zone != "z" {
		t.Errorf("bare result = %+v", got)
	}
}

// The wrong document, or a failed command, is reported rather than read as empty.
func TestReadOpDataRejectsWrongInput(t *testing.T) {
	fib := opFixture(t, "fw01-advanced-routing-fib.xml")
	if _, err := ReadInterfaceStates(fib); err == nil {
		t.Error("a fib was accepted as an interface list")
	}
	ifaces := opFixture(t, "fw01-interface-all.xml")
	if _, err := ReadFIBRoutes(ifaces); err == nil {
		t.Error("an interface list was accepted as a fib")
	}
	if _, err := ReadInterfaceStates([]byte(`<response status="error"><msg>no</msg></response>`)); err == nil {
		t.Error("a failed command was accepted")
	}
	if _, err := ReadFIBRoutes([]byte("not xml")); err == nil {
		t.Error("malformed input was accepted")
	}
}

// An older release names a virtual router rather than a logical one.
func TestRouterOfBothSpellings(t *testing.T) {
	for in, want := range map[string]string{
		"lr:default": "default", "vr:trust": "trust", "N/A": "", "": "",
	} {
		if got := routerOf(in); got != want {
			t.Errorf("routerOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// A route whose destination cannot be read is skipped rather than failing the whole
// document: one malformed entry must not lose the other twenty-four.
func TestReadFIBRoutesSkipsUnreadableEntries(t *testing.T) {
	body := []byte(`<result><fibs>
	  <entry><vr>default</vr><type>0</type><entries>
	    <entry><dst>not-a-prefix</dst><interface>ethernet1/1</interface></entry>
	    <entry><dst>10.0.0.0/8</dst><interface>ethernet1/1</interface></entry>
	  </entries></entry>
	</fibs></result>`)
	got, err := ReadFIBRoutes(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Destination.String() != "10.0.0.0/8" {
		t.Errorf("routes = %+v, want only the readable one", got)
	}
}

// An entry with no name is not an interface.
func TestReadInterfaceStatesSkipsNamelessEntries(t *testing.T) {
	body := []byte(`<result><ifnet>
	  <entry><zone>z</zone></entry>
	  <entry><name>ethernet1/1</name><zone>z</zone></entry>
	</ifnet></result>`)
	got, err := ReadInterfaceStates(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "ethernet1/1" {
		t.Errorf("interfaces = %+v", got)
	}
}

// An IPv6 table is read as one, so a device with v6 routes is not silently mixed in
// with v4.
func TestReadFIBRoutesMarksIPv6(t *testing.T) {
	body := []byte(`<result><fibs>
	  <entry><vr>default</vr><type>1</type><entries>
	    <entry><dst>2001:db8::/32</dst><interface>ethernet1/1</interface></entry>
	  </entries></entry>
	</fibs></result>`)
	got, err := ReadFIBRoutes(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].IPv6 {
		t.Errorf("routes = %+v, want one marked IPv6", got)
	}
}
