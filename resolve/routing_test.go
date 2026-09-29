package resolve

import (
	"net/netip"
	"strings"
	"testing"
)

// Verified on fw02: FRR JSON inside <result><json>, one entry per route.
func TestReadRIBRoutes(t *testing.T) {
	got, err := ReadRIBRoutes(opFixture(t, "fw02-advanced-routing-route.xml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 15 {
		t.Fatalf("got %d routes, want 15", len(got))
	}
	by := map[string]RIBRoute{}
	for _, r := range got {
		by[r.Destination.String()] = r
	}
	def := by["0.0.0.0/0"]
	if def.Router != "default" || def.Protocol != "static" || def.Distance != 10 || def.Metric != 10 ||
		!def.Selected || !def.Installed || len(def.NextHops) != 1 ||
		def.NextHops[0].IP != netip.MustParseAddr("192.168.0.1") || def.NextHops[0].Interface != "ethernet1/1" {
		t.Errorf("default route = %+v", def)
	}
	// A directly connected next hop has no address.
	tun := by["10.10.0.0/16"]
	if tun.NextHops[0].IP.IsValid() || tun.NextHops[0].Interface != "tunnel.100" {
		t.Errorf("tunnel route = %+v", tun)
	}
	if by["198.19.0.1/32"].Protocol != "local" {
		t.Errorf("an own address is protocol local: %+v", by["198.19.0.1/32"])
	}
	if got[0].Destination.String() != "0.0.0.0/0" {
		t.Errorf("routes are sorted by router and destination: %v", got[0])
	}
}

// On an Advanced Routing device, the legacy command reports success with a text.
func TestReadRIBRoutesRefusesTheLegacyAnswer(t *testing.T) {
	_, err := ReadRIBRoutes(opFixture(t, "fw02-routing-route-deprecated.xml"))
	if err == nil || !strings.Contains(err.Error(), "deprecated") {
		t.Errorf("err = %v", err)
	}
	for _, in := range []string{
		`<response status="success"><result></result></response>`,
		`<response status="success"><result><json>{not json</json></result></response>`,
		`<response status="error"><result/></response>`,
	} {
		if _, err := ReadRIBRoutes([]byte(in)); err == nil {
			t.Errorf("%s: no error", in)
		}
	}
	// A prefix only in the key, and an unreadable one, as FRR could send them.
	got, err := ReadRIBRoutes([]byte(`<response status="success"><result><json>{"lr": {"10.0.0.0/8": [{"protocol": "static"}], "bad": [{}]}}</json></result></response>`))
	if err != nil || len(got) != 1 || got[0].Destination.String() != "10.0.0.0/8" {
		t.Errorf("got %v, %v", got, err)
	}
}

func TestReadHAState(t *testing.T) {
	st, err := ReadHAState(opFixture(t, "fw02-ha-state.xml"))
	if err != nil || st.Enabled {
		t.Errorf("fw02 without HA = %+v, %v", st, err)
	}
	// Synthetic: the pair shape is not verified on a device yet.
	passive := `<response status="success"><result><enabled>yes</enabled><group><mode>Active-Passive</mode>
	  <local-info><state>passive</state><serial-num>0001</serial-num></local-info>
	  <peer-info><state>active</state><serial-num>0002</serial-num><mgmt-ip>192.0.2.10/24</mgmt-ip></peer-info>
	</group></result></response>`
	st, err = ReadHAState([]byte(passive))
	if err != nil || !st.Enabled || st.LocalState != "passive" || st.PeerState != "active" ||
		st.LocalSerial != "0001" || st.PeerSerial != "0002" || st.PeerMgmtIP != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("passive = %+v, %v", st, err)
	}
	if _, err := ReadHAState([]byte(`<response status="success"><result/></response>`)); err == nil {
		t.Error("output without <enabled> must be refused")
	}
	if _, err := ReadHAState([]byte(`not xml`)); err == nil {
		t.Error("garbage must be refused")
	}
}

// Verified on fw02: nh_type 3 is the device's own address; the rest is 0.
func TestFIBRoutesCarryTheNextHopType(t *testing.T) {
	got, err := ReadFIBRoutes(opFixture(t, "fw02-advanced-routing-fib.xml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		want := "0"
		if strings.HasSuffix(r.Flags, "h") {
			want = NextHopLocal
		}
		if r.NextHopType != want || r.ECMP {
			t.Errorf("%v: nh_type %q, ecmp %v", r.Destination, r.NextHopType, r.ECMP)
		}
	}
}

// A second dataplane block repeating the table must not repeat its routes.
func TestFIBRoutesAreKeptOnce(t *testing.T) {
	table := `<entry><vr>default</vr><type>0</type><ecmp>1</ecmp><entries>
	  <entry><dst>10.0.0.0/8</dst><interface>ethernet1/1</interface><nexthop>192.0.2.1</nexthop><flags>ug</flags><nh_type>0</nh_type></entry>
	</entries></entry>`
	in := `<response status="success"><result><fibs>` + table + table + `</fibs></result></response>`
	got, err := ReadFIBRoutes([]byte(in))
	if err != nil || len(got) != 1 || !got[0].ECMP {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestInterfaceStatesHoldEveryAddress(t *testing.T) {
	got, err := ReadInterfaceStates(opFixture(t, "fw02-interface-all.xml"))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]InterfaceState{}
	for _, i := range got {
		by[i.Name] = i
	}
	if v := by["vlan.32"]; len(v.Addrs) != 1 || v.Addrs[0] != v.Prefix || v.Zone != "labor" || v.Router != "default" {
		t.Errorf("vlan.32 = %+v", v)
	}
	// A Layer 2 interface has a zone but no router.
	if l2 := by["ethernet1/2"]; l2.Router != "" || l2.Zone == "" || len(l2.Addrs) != 0 {
		t.Errorf("ethernet1/2 = %+v", l2)
	}
	// Synthetic: the member shape of <addr> and <dyn-addr> is unverified.
	in := `<response status="success"><result><ifnet><entry><name>ethernet1/1</name><zone>z</zone><fwd>lr:default</fwd>
	  <ip>10.0.0.1/24</ip><addr><member>10.0.1.1/24</member></addr><dyn-addr><member>203.0.113.5/29</member></dyn-addr>
	</entry></ifnet></result></response>`
	sts, err := ReadInterfaceStates([]byte(in))
	if err != nil || len(sts) != 1 || len(sts[0].Addrs) != 3 || sts[0].Addrs[2].String() != "203.0.113.5/29" {
		t.Errorf("got %+v, %v", sts, err)
	}
}

// Verified on fw01 (PAN-OS 11.2.5): the table also holds entries it did not
// select, such as the local twin of each loopback's connected route.
func TestReadRIBRoutesKeepsUnselectedEntries(t *testing.T) {
	got, err := ReadRIBRoutes(opFixture(t, "fw01-advanced-routing-route.xml"))
	if err != nil {
		t.Fatal(err)
	}
	var selected, unselected int
	routers := map[string]bool{}
	for _, r := range got {
		routers[r.Router] = true
		if r.Destination.String() != "198.19.255.1/32" {
			continue
		}
		if r.Selected {
			selected++
			if r.Protocol != "connected" {
				t.Errorf("selected = %+v", r)
			}
		} else {
			unselected++
		}
	}
	if selected != 1 || unselected != 1 || !routers["default"] || !routers["lte"] {
		t.Errorf("selected %d, unselected %d, routers %v", selected, unselected, routers)
	}
}
