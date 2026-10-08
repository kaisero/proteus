package cli

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/fakepanos"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
)

// labFW02 is fw02 as captured: a PA-440 on PAN-OS 12.2 joined to fw01 by
// 198.19.0.0/24. Its configuration is the path fixture's: zones home and labor,
// and no security rule.
func labFW02(t *testing.T) *fakepanos.Device {
	t.Helper()
	d := lab(t)
	d.Config = string(pathlab.Read(t, pathlab.ConfigFile(pathlab.FW02)))
	d.Ops["<show><system><info/></system></show>"] = fakepanos.Success(
		"<system><hostname>fw02</hostname><model>PA-440</model><serial>000000000002</serial><sw-version>12.2.2</sw-version></system>")
	d.Ops["<show><interface>all</interface></show>"] = read(t, "../../testdata/opdata/fw02-interface-all.xml")
	d.Ops["<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>"] = read(t, "../../testdata/opdata/fw02-advanced-routing-fib.xml")
	d.Ops["<show><advanced-routing><route><afi>ipv4</afi></route></advanced-routing></show>"] = read(t, "../../testdata/opdata/fw02-advanced-routing-route.xml")
	return d
}

// pathLab is the path fixture as an inventory of fw01 and fw02, both fetched:
// each with a configuration that defines its zones and holds no security rule.
func pathLab(t *testing.T) *cli {
	t.Helper()
	fw01 := lab(t)
	fw01.Config = string(pathlab.Read(t, pathlab.ConfigFile(pathlab.FW01)))
	c := newCLI(t)
	c.inventory(inventoryFor(fw01.Start(t), labFW02(t).Start(t)))
	c.want(0, "fetch", "fw01", "fw02")
	return c
}

// routingLab is an inventory of fw01 and fw02, both fetched, plus fw03, never
// fetched when withHole is set.
func routingLab(t *testing.T, withHole bool) *cli {
	t.Helper()
	c := newCLI(t)
	hosts := []string{lab(t).Start(t), labFW02(t).Start(t)}
	if withHole {
		hosts = append(hosts, "127.0.0.1:1")
	}
	c.inventory(inventoryFor(hosts...))
	c.want(0, "fetch", "fw01", "fw02")
	return c
}

func TestRoutingAcrossTwoFirewalls(t *testing.T) {
	t.Parallel()
	c := routingLab(t, false)
	out := c.want(0, "simulate", "routing", "198.18.10.5", "8.8.8.8")
	for _, want := range []string{
		"simulate routing 198.18.10.5 -> 8.8.8.8",
		"┌─ fw01 ─ vsys1 ─ router default ─ snapshot 1m",
		"     │ 198.19.0.0/24   198.19.0.254 -> 198.19.0.1\n",
		"┌─ fw02 ─ vsys1 ─ router default ─ snapshot 1m",
		"  192.168.0.1   leaves the estate (not in the inventory)\n",
		"firewalls on the path: fw01 (server -> transport), fw02 (labor -> wan)\n",
		"│  route   0.0.0.0/0 via 198.19.0.1   static",
		"may be incomplete:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	out = c.want(0, "simulate", "routing", "198.18.1.10", "198.18.10.100")
	if !strings.Contains(out, "firewalls on the path: fw02 (home -> labor), fw01 (transport -> server)\n") ||
		!strings.Contains(out, "  198.18.10.100   delivered\n") {
		t.Errorf("reverse:\n%s", out)
	}
	// fw02 routes 10.10.0.0/16 into an unnumbered tunnel.
	// Its routing table says static, so the route reads via the tunnel, not connected.
	if out := c.want(0, "simulate", "routing", "198.18.1.10", "10.10.5.5"); !strings.Contains(out, "leaves by tunnel.100 (zone prisma)") ||
		!strings.Contains(out, "│  route   10.10.0.0/16 via tunnel.100   static") {
		t.Errorf("tunnel:\n%s", out)
	}
}

func TestRoutingAsksWhereToStart(t *testing.T) {
	t.Parallel()
	c := routingLab(t, false)
	_, errOut, code := c.run("simulate", "routing", "198.18.100.50", "8.8.8.8")
	if code != 2 || !strings.Contains(errOut, "fw01 ethernet1/5, fw02 vlan.100") {
		t.Errorf("tie: exit %d\n%s", code, errOut)
	}
	_, errOut, code = c.run("simulate", "routing", "8.8.8.8", "--device", "fw01")
	if code != 2 || !strings.Contains(errOut, "fw01 has several routers; name one with --router: default, lte") {
		t.Errorf("routers: exit %d\n%s", code, errOut)
	}
	if out := c.want(0, "simulate", "routing", "8.8.8.8", "--device", "fw01", "--router", "default"); !strings.Contains(out, "  start on fw01, router default\n") {
		t.Errorf("--router:\n%s", out)
	}
	_, errOut, code = c.run("simulate", "routing", "8.8.8.8")
	if code != 2 || !strings.Contains(errOut, "give a source, or a start device with --device") {
		t.Errorf("one argument: exit %d\n%s", code, errOut)
	}
	c.want(2, "simulate", "routing", "2001:db8::1", "--device", "fw01", "--router", "default")
	c.want(2, "simulate", "routing", "198.18.1.10", "8.8.8.8", "--at", "tuesday")
	c.want(2, "simulate", "routing", "10.0.0.0/8", "8.8.8.8")
}

func TestRoutingRIBAndWhy(t *testing.T) {
	t.Parallel()
	c := routingLab(t, false)
	out := c.want(0, "simulate", "routing", "198.18.1.10", "8.8.8.8", "--rib", "--why")
	for _, want := range []string{
		"│  route   0.0.0.0/0 via 192.168.0.1   static",
		"│  alt     0.0.0.0/0 via 192.168.0.1   static, distance 10 (active)",
		"  hop1/lookup ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestRoutingJSON(t *testing.T) {
	t.Parallel()
	c := routingLab(t, false)
	out := c.want(0, "simulate", "routing", "198.18.10.5", "8.8.8.8", "--output", "json")
	var env struct {
		Format  int
		Command string
		Results []struct {
			Outcome  string
			Fidelity struct{ Level string }
			Hops     []struct {
				Device string
				Vsys   string
				Flow   struct {
					Source      struct{ Addrs []string }
					Destination struct{ Addrs []string }
					FromZone    string `json:"from_zone"`
					ToZone      string `json:"to_zone"`
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(env.Results) != 1 {
		t.Fatalf("results = %+v", env.Results)
	}
	r := env.Results[0]
	if env.Format != 1 || env.Command != "simulate routing" || r.Outcome != "left-estate" || r.Fidelity.Level != "undermatch" ||
		len(r.Hops) != 2 || r.Hops[1].Device != "fw02" || r.Hops[0].Flow.FromZone != "server" || r.Hops[0].Flow.ToZone != "transport" ||
		r.Hops[0].Flow.Source.Addrs[0] != "198.18.10.5" || r.Hops[1].Vsys != "vsys1" {
		t.Errorf("json = %+v", env)
	}
}

// A device of the inventory without a snapshot may hide part of the path.
func TestRoutingWithAHole(t *testing.T) {
	t.Parallel()
	c := routingLab(t, true)
	out := c.want(3, "simulate", "routing", "198.18.10.5", "8.8.8.8")
	if !strings.Contains(out, "unresolved: fw01: fw03 cannot be read") {
		t.Errorf("hole:\n%s", out)
	}
}

func TestRoutingWithoutSnapshotsIsAHole(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), labFW02(t).Start(t)))
	out := c.want(3, "simulate", "routing", "198.18.10.5", "8.8.8.8", "--output", "json")
	if !strings.Contains(out, `"results": []`) || strings.Count(out, `"device": "fw0`) < 2 {
		t.Errorf("both devices must be holes and results empty:\n%s", out)
	}
}

// The FQDN note the text shows (an endpoint resolving to several addresses)
// reaches the envelope's top-level notes too — not only nested inside
// results[0].notes, where routing.Path already carries the same text.
func TestRoutingNotesReachTheEnvelope(t *testing.T) {
	t.Parallel()
	c := routingLab(t, false)
	c.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("8.8.4.4")}, nil
	}
	out := c.want(0, "simulate", "routing", "198.18.10.5", "dns.example", "--output", "json")
	var env struct {
		Notes []struct{ Device, Note string }
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	found := false
	for _, n := range env.Notes {
		if strings.Contains(n.Note, "dns.example resolved to 2 addresses") {
			found = true
		}
	}
	if !found {
		t.Errorf("the FQDN note must be in the envelope's own notes:\n%s", out)
	}
}

// On the path fixture the lab flow crosses fw02 home -> labor, then fw01
// transport -> server, and the default rule denies it at hop 1.
func TestThePathFixture(t *testing.T) {
	t.Parallel()
	c := pathLab(t)
	out := c.want(0, "simulate", "routing", pathlab.Source, pathlab.Destination)
	if !strings.Contains(out, "firewalls on the path: fw02 (home -> labor), fw01 (transport -> server)\n") ||
		!strings.Contains(out, "  198.18.10.100   delivered\n") {
		t.Errorf("routing:\n%s", out)
	}
	out = c.want(0, "simulate", "policy", pathlab.Source, pathlab.Destination, "--device", "fw02", "--vsys", "vsys1",
		"--from-zone", "home", "--to-zone", "labor")
	if !strings.Contains(out, "first match: interzone-default (deny), default rule (built-in)\n") {
		t.Errorf("policy at hop 1:\n%s", out)
	}
}

// A start device absent from the inventory is a usage error, not a hole.
func TestRoutingDeviceNotInInventoryIsUsage(t *testing.T) {
	t.Parallel()
	c := routingLab(t, false)
	c.want(2, "simulate", "routing", "8.8.8.8", "--device", "fw09")
}

// A start device in the inventory but never fetched is a hole, with results
// empty.
func TestRoutingStartWithoutASnapshotIsAHole(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	out := c.want(3, "simulate", "routing", "8.8.8.8", "--device", "fw01", "--output", "json")
	if !strings.Contains(out, `"results": []`) {
		t.Errorf("a hole must give empty results:\n%s", out)
	}
}
