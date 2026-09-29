package main

import (
	"encoding/json"
	"strings"
	"testing"
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
	c := natLab(t)
	out := c.want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01", "--router", "default", "--from-zone", "transport", "--port", "8443", "--output", "json")
	var env struct {
		Command string
		Results struct {
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
	r := env.Results
	if env.Command != "simulate nat" || r.Rule.Name != "t-dnat-port" || r.Flow.Destination.Addrs[0] != "198.18.10.100" || r.Flow.Port != 443 ||
		r.PostNAT.Out.Zone != "server" || r.Fidelity.Level != "exact" || len(r.Stages) != 6 {
		t.Errorf("json = %+v", env)
	}
}
