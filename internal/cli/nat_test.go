package cli

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// natLab is fw01 with its NAT test rules: its captured interfaces and forwarding
// table, and firewall-nat.xml as its configuration.
func natLab(t *testing.T) *cli {
	t.Helper()
	d := lab(t)
	d.Config = read(t, "../../testdata/config/firewall-nat.xml")
	c := newCLI(t)
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	return c
}

// The port forward fw01 applied to real traffic (spec §18.5 traffic test 1).
func TestSimulateNATPortForward(t *testing.T) {
	t.Parallel()
	c := natLab(t)
	out := c.want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01", "--router", "default", "--from-zone", "transport", "--port", "8443")
	want := `simulate nat 198.18.1.10 -> 198.18.250.10 tcp/8443 on fw01            fidelity: exact

  ┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m ────────┐
  │  zones   transport -> server                         │
  │  out     ethernet1/2   198.18.10.1/24                │
  │  route   0.0.0.0/0 via 198.19.0.1   (pre-NAT)        │
  │  route   198.18.10.0/24  connected   (post-NAT)      │
  │  rule    t-dnat-port, matched transport -> transport │
  │  dest    198.18.250.10:8443 -> 198.18.10.100:443     │
  └──────────────────────────────────────────────────────┘

  before   198.18.1.10 -> 198.18.250.10:8443  tcp
  after    198.18.1.10 -> 198.18.10.100:443  tcp

security policy matches: 198.18.1.10 -> 198.18.250.10, port 8443, zones transport -> server
`
	if out != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
	// Without the zone the ingress is the return route's, inferred; --why lists
	// the rules above the match and every stage.
	out = c.want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01", "--router", "default", "--port", "8443", "--why")
	for _, w := range []string{
		"may be incomplete: inferred\n  place        routed: 198.18.1.10 by the return route on ethernet1/1\n",
		"  not t-no-nat               from zone client ≠ transport\n", "  not t-disabled             disabled\n",
		"  post-lookup    exact      198.18.10.100 leaves by ethernet1/2 (zone server)\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

func TestSimulateNATRows(t *testing.T) {
	t.Parallel()
	c := natLab(t)
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"198.18.11.5", "198.18.250.200", "--port", "443"}, []string{
			"│  source  198.18.11.5 -> 198.18.250.64/29, port unchanged; fallback 198.19.0.254 │",
			"  after    198.18.250.64 -> 198.18.250.200:443  tcp",
		}},
		{[]string{"198.18.1.10", "198.18.250.20", "--from-zone", "transport", "--router", "default"}, []string{
			"t-bidir (implicit rule of the bi-directional t-bidir), matched transport -> transport",
			"zones transport -> dmz",
		}},
		{[]string{"198.18.10.5", "8.8.8.8", "--port", "443"}, []string{
			"│  source  198.18.10.5 -> 198.19.0.254, port assigned at runtime",
			"  after    198.19.0.254:(runtime) -> 8.8.8.8:443  tcp",
		}},
		{[]string{"-", "198.18.250.10", "--from-interface", "ethernet1/3"}, []string{
			"simulate nat (no source) -> 198.18.250.10 tcp on fw01",
			"│  doubt   t-dnat-port: service t-8443 not known without a port: give --port",
			"may be incomplete: overmatch",
		}},
		{[]string{"198.18.11.5", "198.18.100.9", "--port", "443"}, []string{
			"│  rule    none: the packet leaves untranslated",
		}},
	} {
		out := c.want(0, append([]string{"simulate", "nat", "--device", "fw01"}, tc.args...)...)
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: missing %q in:\n%s", tc.args, w, out)
			}
		}
	}
}

func TestSimulateNATExits(t *testing.T) {
	t.Parallel()
	c := natLab(t)
	for _, a := range [][]string{
		{"198.18.1.10", "8.8.8.8"},
		{"198.18.1.10", "8.8.8.8", "--device", "fw01"},
		{"198.18.1.10", "8.8.8.8", "--device", "fw01", "--from-zone", "a", "--from-interface", "b"},
		{"2001:db8::1", "8.8.8.8", "--device", "fw01"},
		{"198.18.1.10", "8.8.8.8", "--device", "fw01", "--port", "x"},
		{"198.18.1.10", "8.8.8.8", "--device", "fw01", "--at", "tuesday"},
		{"198.18.1.10", "8.8.8.8", "--device", "fw09"},
	} {
		c.want(2, append([]string{"simulate", "nat"}, a...)...)
	}
	// fw01 could not resolve t-dnat-fqdn's name, and --no-dns resolves none here:
	// the translation is unresolved (spec §18 D8).
	out := c.want(3, "simulate", "nat", "198.18.1.10", "198.18.250.30", "--device", "fw01", "--router", "default", "--from-zone", "transport", "--no-dns")
	if !strings.Contains(out, "resolves to no address") {
		t.Errorf("unresolved:\n%s", out)
	}
	c.want(2, "simulate", "nat", "198.18.1.10", "no-such-host.invalid", "--device", "fw01", "--no-dns")
}

func TestSimulateNATJSON(t *testing.T) {
	t.Parallel()
	c := natLab(t)
	out := c.want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01", "--router", "default", "--from-zone", "transport", "--port", "8443", "--output", "json")
	var env struct {
		Command string
		Results []struct {
			Rule struct{ Name string }
			Flow struct {
				Destination struct{ Addrs []string }
				Port        int
			}
			PostNAT struct {
				Out struct{ Zone string }
			} `json:"post_nat"`
			Fidelity struct{ Level string }
			Stages   []struct{ Slug string }
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(env.Results) != 1 {
		t.Fatalf("results = %+v", env.Results)
	}
	r := env.Results[0]
	if env.Command != "simulate nat" || r.Rule.Name != "t-dnat-port" || r.Flow.Destination.Addrs[0] != "198.18.10.100" || r.Flow.Port != 443 ||
		r.PostNAT.Out.Zone != "server" || r.Fidelity.Level != "exact" || len(r.Stages) != 6 {
		t.Errorf("json = %+v", env)
	}
}

// The live traffic test, simulated: from fw02's side to 198.18.250.10:8443, fw01
// translated the destination to 198.18.10.100:443 in zone server, and t-allow-8443
// allowed it (spec §18.5 traffic test 1).
func TestPolicyUsesThePostNATZone(t *testing.T) {
	t.Parallel()
	c := natLab(t)
	out := c.want(0, "simulate", "policy", "198.19.0.1", "198.18.250.10", "--device", "fw01", "--port", "8443", "--why")
	for _, w := range []string{"to server (after NAT rule t-dnat-port)", "first match: t-allow-8443 (allow)"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
	// A given zone wins, with a note when NAT gives another.
	out = c.want(0, "simulate", "policy", "198.19.0.1", "198.18.250.10", "--device", "fw01", "--port", "8443",
		"--from-zone", "transport", "--to-zone", "transport", "--why")
	if !strings.Contains(out, "note: NAT would give to server (after NAT rule t-dnat-port)") {
		t.Errorf("given zones:\n%s", out)
	}
}

// fw01's lte router has no route to 8.8.8.8: the packet is dropped before NAT, and
// security policy matches nothing.
func TestSimulateNATDroppedBeforeNAT(t *testing.T) {
	t.Parallel()
	c := natLab(t)
	out := c.want(0, "simulate", "nat", "-", "8.8.8.8", "--device", "fw01", "--router", "lte", "--port", "443")
	if !strings.Contains(out, "│  rule    none: no route to 8.8.8.8: dropped before NAT") || strings.Contains(out, "security policy matches") {
		t.Errorf("dropped:\n%s", out)
	}
	c.want(2, "simulate", "routing", "198.18.1.10", "198.18.250.10", "--port", "x")
}

// A device without a snapshot is a hole, not a usage error (spec §4.2).
func TestNATWithoutASnapshotIsAHole(t *testing.T) {
	t.Parallel()
	d := lab(t)
	c := newCLI(t)
	c.inventory(inventoryFor(d.Start(t)))
	out := c.want(3, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01", "--output", "json")
	var env struct {
		Results []any
		Holes   []struct{ Device string }
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Results) != 0 || len(env.Holes) != 1 || env.Holes[0].Device != "fw01" {
		t.Errorf("%v %s", err, out)
	}
	c.want(2, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw09")
}

// Notes the text shows reach the JSON too.
func TestNATNotesReachTheEnvelope(t *testing.T) {
	t.Parallel()
	c := natLab(t)
	c.clock = c.clock.Add(48 * time.Hour) // past the 24h age limit
	out := c.want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01",
		"--router", "default", "--from-zone", "transport", "--port", "8443", "--output", "json")
	if !strings.Contains(out, `"notes": [`) || !strings.Contains(out, "past the 24h0m0s limit") {
		t.Errorf("the stale-snapshot note must be in notes:\n%s", out)
	}
}

// A NAT result's own notes (here, a destination FQDN resolved by this machine's
// DNS) reach the envelope's top-level notes too, not only the device's, and not
// only nested inside results[0].notes (nat.Result already carries its own
// notes there; the check must be about the envelope's own array).
func TestNATResultNotesReachTheEnvelope(t *testing.T) {
	t.Parallel()
	c := natLab(t)
	c.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	out := c.want(0, "simulate", "nat", "198.18.1.10", "198.18.250.30", "--device", "fw01",
		"--router", "default", "--from-zone", "transport", "--output", "json")
	var env struct {
		Notes []struct{ Device, Note string }
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	found := false
	for _, n := range env.Notes {
		if n.Device == "fw01" && strings.Contains(n.Note, "resolved by this machine's DNS") {
			found = true
		}
	}
	if !found {
		t.Errorf("the translation note must be in the envelope's own notes:\n%s", out)
	}
}
