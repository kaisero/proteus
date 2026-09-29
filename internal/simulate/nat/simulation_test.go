package nat

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// fw01 is a network of one device: fw01's interface state and forwarding table as
// captured, with firewall-nat.xml as its configuration.
type fw01 struct{ data simulate.DeviceData }

func (n fw01) Devices() []string { return []string{"fw01"} }

func (n fw01) Device(name string) (simulate.DeviceData, error) {
	if name != "fw01" {
		return simulate.DeviceData{}, errors.New("no snapshot")
	}
	return n.data, nil
}

func fw01Env(t *testing.T, file string) *simulate.Env {
	t.Helper()
	fib, err := os.ReadFile("../../../testdata/opdata/fw01-advanced-routing-fib.xml")
	if err != nil {
		t.Fatal(err)
	}
	routes, err := resolve.ReadFIBRoutes(fib)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := config.Load("../../../testdata/config/" + file)
	if err != nil {
		t.Fatal(err)
	}
	return &simulate.Env{
		Network: fw01{simulate.DeviceData{Name: "fw01", Interfaces: fw01Interfaces(t), FIB: routes}},
		Load:    func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg}, nil },
	}
}

func run(t *testing.T, env *simulate.Env, src, dst string, port uint16, params map[string]string) (simulate.Run, Result, error) {
	t.Helper()
	f := simulate.Flow{Destination: simulate.Addr(netip.MustParseAddr(dst)), Protocol: "tcp", DestPort: port}
	if src != "" {
		f.Source = simulate.Addr(netip.MustParseAddr(src))
	}
	p := map[string]string{"device": "fw01"}
	maps.Copy(p, params)
	r, err := Simulation{}.Run(context.Background(), env, simulate.Input{Flow: f, Params: p})
	res, _ := r.Output.(Result)
	return r, res, err
}

func slugs(r simulate.Run) string {
	var out []string
	for _, s := range r.Stages {
		out = append(out, s.Slug+"="+s.Fidelity.Level())
	}
	return strings.Join(out, " ")
}

// The port forward fw01 applied to real traffic: from transport to 198.18.250.10:8443,
// translated to 198.18.10.100:443 and routed into server (spec §18.5 traffic test 1).
func TestSimulateThePortForward(t *testing.T) {
	t.Parallel()
	r, res, err := run(t, fw01Env(t, "firewall-nat.xml"), "198.18.1.10", "198.18.250.10", 8443, map[string]string{"router": "default"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rule == nil || res.Rule.Name != "t-dnat-port" || res.Flow.Destination.String() != "198.18.10.100" || res.Flow.DestPort != 443 ||
		res.PostNAT == nil || res.PostNAT.Out.Zone != "server" || res.PreNAT.Out.Zone != "transport" {
		t.Fatalf("result = %+v", res)
	}
	// 198.18.1.10 is not connected on fw01: its ingress comes from the return route.
	if got := slugs(r); got != "place=inferred pbf=exact lookup=exact match=exact translate=exact post-lookup=exact" || r.Vsys != "vsys1" {
		t.Errorf("stages = %s, vsys %s", got, r.Vsys)
	}
	// Given the zone, the ingress is exact.
	r, _, _ = run(t, fw01Env(t, "firewall-nat.xml"), "198.18.1.10", "198.18.250.10", 8443, map[string]string{"from-zone": "transport", "router": "default"})
	if r.Stages[0].Fidelity.Level() != "exact" || !strings.Contains(r.Stages[0].Detail, "zone transport") {
		t.Errorf("from-zone: %+v", r.Stages[0])
	}
}

func TestSimulateIngress(t *testing.T) {
	t.Parallel()
	env := fw01Env(t, "firewall-nat.xml")
	// Connected in client: t-dip-pool with its pool.
	if r, res, _ := run(t, env, "198.18.11.5", "198.18.250.200", 443, nil); res.Rule.Name != "t-dip-pool" || r.Stages[0].Fidelity.Level() != "exact" {
		t.Errorf("connected: %v %s", res.Rule, slugs(r))
	}
	// Given by interface.
	// No source: the dmz rules that name one are doubts, internet-a is sure.
	if _, res, _ := run(t, env, "", "198.18.250.200", 443, map[string]string{"from-interface": "ethernet1/4"}); res.Rule == nil || res.Rule.Name != "internet-a" ||
		len(res.Doubts) != 2 || res.Doubts[0].Rule != "t-bidir" || res.Doubts[0].Reason != "the source is unknown" {
		t.Errorf("from-interface: %v, doubts %v", res.Rule, res.Doubts)
	}
	if _, _, err := run(t, env, "", "198.18.250.200", 443, map[string]string{"from-interface": "nope", "router": "default"}); err == nil {
		t.Error("an unknown interface")
	}
	// No source and no override: every zone-dependent rule is a doubt.
	r, res, _ := run(t, env, "", "198.18.250.200", 443, map[string]string{"router": "default"})
	if !strings.Contains(r.Stages[0].Detail, "unknown") || len(res.Doubts) == 0 || r.Fidelity.Level() != "overmatch" {
		t.Errorf("unknown ingress: %s, %v", slugs(r), res.Doubts)
	}
	// No rule: to server from transport has none but server-access; to mgmt from client none.
	if _, res, _ := run(t, env, "198.18.11.5", "198.18.100.9", 443, nil); res.Rule != nil {
		t.Errorf("no rule: %v", res.Rule)
	}
}

func TestSimulateResolvesTheDynamicDestination(t *testing.T) {
	t.Parallel()
	env := fw01Env(t, "firewall-nat.xml")
	env.Resolve = func(_ context.Context, name string) ([]netip.Addr, error) {
		if name != "dns.google" {
			t.Errorf("resolved %s", name)
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}, nil
	}
	_, res, _ := run(t, env, "198.18.1.10", "198.18.250.30", 443, map[string]string{"from-zone": "transport", "router": "default"})
	if res.Flow.Destination.String() != "8.8.4.4" || res.PostNAT == nil {
		t.Errorf("dynamic: %+v", res)
	}
}

func TestSimulatePBFAndChoices(t *testing.T) {
	t.Parallel()
	// firewall-routing.xml's PBF rule for branch-vpn, on fw01's tables.
	env := fw01Env(t, "firewall-routing.xml")
	r, res, _ := run(t, env, "10.20.5.5", "8.8.8.8", 443, map[string]string{"from-zone": "branch-vpn", "router": "default"})
	if r.Stages[1].Fidelity.Level() != "inferred" || len(res.Notes) == 0 || !strings.Contains(res.Notes[0], "pbf rule branch-to-zscaler") {
		t.Errorf("pbf: %s, notes %v", slugs(r), res.Notes)
	}
	env.Load = nil
	if r, _, _ := run(t, env, "198.18.11.5", "8.8.8.8", 443, nil); r.Stages[1].Fidelity.Level() != "overmatch" {
		t.Errorf("no configuration: %s", slugs(r))
	}
	// The route lookup ends before NAT: fw01's lte router has no route to 8.8.8.8.
	env = fw01Env(t, "firewall-nat.xml")
	if r, res, _ := run(t, env, "", "8.8.8.8", 443, map[string]string{"router": "lte"}); !strings.Contains(res.Dropped, "no route") || !strings.Contains(r.Stages[2].Detail, "no-route") {
		t.Errorf("no route: %+v", res.MatchResult)
	}
	var ce *simulate.ChoiceError
	for name, tc := range map[string]struct {
		env    *simulate.Env
		src    string
		dst    string
		params map[string]string
	}{
		"no device":   {env, "", "8.8.8.8", map[string]string{"device": ""}},
		"unknown":     {env, "", "8.8.8.8", map[string]string{"device": "fw09"}},
		"routers":     {env, "", "8.8.8.8", nil},
		"ipv6":        {env, "", "2001:db8::1", nil},
		"ipv6 source": {env, "2001:db8::1", "8.8.8.8", nil},
	} {
		if _, _, err := run(t, tc.env, tc.src, tc.dst, 443, tc.params); !errors.As(err, &ce) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (Simulation{}).Run(context.Background(), &simulate.Env{}, simulate.Input{}); err == nil {
		t.Error("no network")
	}
	s := Simulation{}
	if s.Kind() != "nat" || s.Describe() == "" || len(s.Stages()) != 6 || vsysName("", "") != "vsys1" || vsysName("vsys2") != "vsys2" || orUnknown("") != "unknown" {
		t.Error("describe")
	}
}
