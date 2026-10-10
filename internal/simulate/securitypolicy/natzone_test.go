package securitypolicy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// net1 is fw01's stored interfaces and forwarding table as a network of one.
type net1 struct{ d simulate.DeviceData }

func (n net1) Devices() []string { return []string{n.d.Name} }

func (n net1) Device(name string) (simulate.DeviceData, error) {
	if name != n.d.Name {
		return simulate.DeviceData{}, errors.New("no snapshot of " + name)
	}
	return n.d, nil
}

func fw01Network(t *testing.T) net1 {
	t.Helper()
	ib, _ := os.ReadFile("../../../testdata/opdata/fw01-interface-all.xml")
	fb, _ := os.ReadFile("../../../testdata/opdata/fw01-advanced-routing-fib.xml")
	ifs, err := resolve.ReadInterfaceStates(ib)
	if err != nil {
		t.Fatal(err)
	}
	fib, err := resolve.ReadFIBRoutes(fb)
	if err != nil {
		t.Fatal(err)
	}
	return net1{simulate.DeviceData{Name: "fw01", Interfaces: ifs, FIB: fib}}
}

func natEnv(t *testing.T) *simulate.Env {
	e := env(t, "firewall-nat.xml", true)
	e.Network = fw01Network(t)
	return e
}

// The destination zone is the post-NAT one (spec §18 F5, N10), as fw01 showed.
func TestThePostNATZone(t *testing.T) {
	t.Parallel()
	r, v := run(t, natEnv(t), simulate.Flow{Source: ep("198.19.0.1"), Destination: ep("198.18.250.10"), DestPort: 8443})
	if strings.Join(v.Zones.To, ",") != "server" || !strings.Contains(stage(r, "derive-zones").Detail, "to server (after NAT rule t-dnat-port)") ||
		v.Zones.Source != "forwarding table, after NAT rule t-dnat-port" ||
		first(v) != "t-allow-8443" {
		t.Errorf("zones %+v, detail %q, first %s", v.Zones, stage(r, "derive-zones").Detail, first(v))
	}
	// Without a port t-dnat-port is a doubt, and the pre-NAT zone stays.
	r, v = run(t, natEnv(t), simulate.Flow{Source: ep("198.19.0.1"), Destination: ep("198.18.250.10")})
	if strings.Join(v.Zones.To, ",") != "transport" || !strings.Contains(stage(r, "derive-zones").Fidelity.String(), "the NAT rule is not certain") {
		t.Errorf("no port: %+v, %s", v.Zones, stage(r, "derive-zones").Fidelity)
	}
	if rs := stage(r, "derive-zones").Fidelity.Reasons(); len(rs) == 0 || rs[0].Code != "doubt.nat-rule" {
		t.Errorf("the NAT summary has its own code: %v", rs)
	}
}

// A NAT rule in doubt above the destination NAT may match first and leave the
// destination alone, so the derived zones keep the pre-NAT zone with the
// post-NAT one. nat-https names service-https, which only the device's
// predefined services define; with them stored, it cannot match tcp/8443 and the
// post-NAT zone stands alone (lab L4b).
func TestANATDoubtKeepsThePreNATZone(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../../testdata/config/firewall-nat.xml")
	if err != nil {
		t.Fatal(err)
	}
	doubted := `<entry name="nat-https"><from><member>any</member></from><to><member>transport</member></to>` +
		`<source><member>any</member></source><destination><member>198.18.250.10</member></destination>` +
		`<service>service-https</service></entry><entry name="t-dnat-port">`
	b = bytes.Replace(b, []byte(`<entry name="t-dnat-port">`), []byte(doubted), 1)
	ask := func(predefined, zones bool) (simulate.Run, Verdict) {
		dir := t.TempDir()
		path := filepath.Join(dir, "firewall-nat.xml")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if predefined {
			p, err := os.ReadFile("../../../testdata/predefined/predefined.xml")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, config.PredefinedFile), p, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		e := envPath(t, path, zones)
		e.Network = fw01Network(t)
		return run(t, e, simulate.Flow{Source: ep("198.19.0.1"), Destination: ep("198.18.250.10"), DestPort: 8443})
	}
	r, v := ask(false, true)
	st := stage(r, "derive-zones")
	if strings.Join(v.Zones.To, ",") != "server,transport" || !strings.Contains(st.Detail, "to server (after NAT rule t-dnat-port)") ||
		!strings.Contains(st.Fidelity.String(), "nat rule nat-https: service service-https is not defined") {
		t.Errorf("in doubt: zones %+v, detail %q, fidelity %s", v.Zones, st.Detail, st.Fidelity)
	}
	if !slices.ContainsFunc(v.Candidates, func(r resolve.Rule) bool { return r.Name == "t-allow-8443" }) {
		t.Errorf("the post-NAT rule stays a candidate: %v", v.Candidates)
	}
	_, v = ask(true, true)
	if strings.Join(v.Zones.To, ",") != "server" || first(v) != "t-allow-8443" {
		t.Errorf("with the predefined services: zones %+v, first %s", v.Zones, first(v))
	}
	// Zones from the configuration, which places no zone on the destination:
	// the side does not narrow, and NAT's zone is only named, not claimed.
	r, v = ask(false, false)
	st = stage(r, "derive-zones")
	if len(v.Zones.To) != 0 || strings.Contains(v.Zones.Source, "after NAT") || strings.Contains(st.Detail, "(after NAT rule") ||
		!strings.Contains(v.Zones.Detail, "NAT may give to server (after NAT rule t-dnat-port), but a NAT rule is in doubt") {
		t.Errorf("no pre-NAT zone: zones %+v, detail %q", v.Zones, st.Detail)
	}
}

func TestGivenZonesWinOverNAT(t *testing.T) {
	t.Parallel()
	r, v := run(t, natEnv(t), simulate.Flow{Source: ep("198.19.0.1"), Destination: ep("198.18.250.10"), DestPort: 8443, FromZone: "transport", ToZone: "transport"})
	if strings.Join(v.Zones.To, ",") != "transport" || !strings.Contains(stage(r, "derive-zones").Detail, "note: NAT would give to server") {
		t.Errorf("given: %+v, %q", v.Zones, stage(r, "derive-zones").Detail)
	}
	// Given zones NAT agrees with: no note.
	r, _ = run(t, natEnv(t), simulate.Flow{Source: ep("198.19.0.1"), Destination: ep("198.18.250.10"), DestPort: 8443, FromZone: "transport", ToZone: "server"})
	if strings.Contains(stage(r, "derive-zones").Detail, "note") {
		t.Errorf("agreeing: %q", stage(r, "derive-zones").Detail)
	}
}

func TestNATIsSkippedWithoutTables(t *testing.T) {
	t.Parallel()
	s := &state{in: simulate.Input{Device: "fw01", Flow: simulate.Flow{Destination: ep("198.18.250.10")}}}
	if z := s.postNATZones(nil); !strings.Contains(z.skipped, "no stored interfaces") {
		t.Errorf("no network: %+v", z)
	}
	s.env = &simulate.Env{Network: fw01Network(t)}
	s.in.Device = "fw09"
	if z := s.postNATZones(nil); !strings.Contains(z.skipped, "no snapshot of fw09") {
		t.Errorf("unknown device: %+v", z)
	}
	// fw01 has two routers; a source connected nowhere names none.
	s.in.Device = "fw01"
	s.in.Flow.Source = ep("8.8.8.8")
	if z := s.postNATZones(nil); !strings.Contains(z.skipped, "several routers") {
		t.Errorf("routers: %+v", z)
	}
}

// fw01 reduced to its default router: a source only a default route reaches gives
// no source zone, so NAT runs once with the ingress unknown.
func TestNATWithOneRouterAndNoSourceZone(t *testing.T) {
	t.Parallel()
	n := fw01Network(t)
	var ifs []resolve.InterfaceState
	for _, i := range n.d.Interfaces {
		if i.Router != "lte" {
			ifs = append(ifs, i)
		}
	}
	var fib []resolve.FIBRoute
	for _, r := range n.d.FIB {
		if r.Router == "default" {
			fib = append(fib, r)
		}
	}
	e := env(t, "firewall-nat.xml", true)
	e.Network = net1{simulate.DeviceData{Name: "fw01", Interfaces: ifs, FIB: fib}}
	_, v := run(t, e, simulate.Flow{Source: ep("8.8.4.4"), Destination: ep("198.18.250.10"), DestPort: 8443})
	if len(v.Zones.From) != 0 || strings.Join(v.Zones.To, ",") != "server" {
		t.Errorf("zones = %+v", v.Zones)
	}
}
