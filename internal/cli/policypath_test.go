package cli

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/estate"
)

// Every exit-2 row of spec 2026-10-07 §7, and the mode choice of §3.1.
func TestPolicyModeChoice(t *testing.T) {
	t.Parallel()
	c := pathLab(t)
	const src, dst = "198.18.1.10", "198.18.10.100"
	file := fixture("firewall-zones.xml")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"each", []string{"--each"}, "fan-out (--each) arrives in a later release"},
		{"each before file", []string{"--each", "--file", file}, "fan-out (--each) arrives in a later release"},
		{"several devices", []string{"--device", "fw01", "--device", "fw02"}, "path mode starts on one device"},
		{"several devices in one value", []string{"--device", "fw01,fw02"}, "path mode starts on one device"},
		{"router without device", []string{"--router", "default"}, "--router needs --device"},
		{"router with file", []string{"--router", "default", "--file", file}, "--router picks the start router of --device"},
		{"vsys", []string{"--vsys", "vsys1"}, "--vsys selects a vsys, but path mode checks every firewall and vsys on the path; use --file <path> --vsys <name> for one configuration"},
		{"label", []string{"--label", "site=lab"}, "--label selects devices, but path mode"},
		{"from zone", []string{"--from-zone", "home"}, "--from-zone: the path gives the zones; use --file"},
		{"to zone", []string{"--to-zone", "labor"}, "--to-zone: the path gives the zones; use --file"},
		{"both zones", []string{"--from-zone", "home", "--to-zone", "labor"}, "--from-zone: the path gives the zones"},
		{"fresh", []string{"--fresh"}, "unknown flag: --fresh"},
		{"all devices", []string{"--all-devices"}, "unknown flag: --all-devices"},
		{"device not in the inventory", []string{"--device", "fw09"}, "fw09"},
		{"file with device", []string{"--file", file, "--device", "fw01"}, "--device selects from the store; --file reads one configuration"},
		{"file with at", []string{"--file", file, "--at", "2026-01-01"}, "--at selects from the store"},
		{"file with one zone", []string{"--file", file, "--from-zone", "dmz"}, "--from-zone and --to-zone go together"},
		{"bad at", []string{"--at", "tuesday"}, "--at \"tuesday\""},
	} {
		_, errOut, code := c.run(append([]string{"simulate", "policy", src, dst}, tc.args...)...)
		if code != exitUsage || !strings.Contains(errOut, tc.want) {
			t.Errorf("%s: exit %d, want 2 and %q\n%s", tc.name, code, tc.want, errOut)
		}
	}
}

// A start only the user can choose exits 2 with routing's text and the way
// forward (spec §3.3, §7).
func TestPolicyPathAsksWhereToStart(t *testing.T) {
	t.Parallel()
	c := routingLab(t, false)
	_, errOut, code := c.run("simulate", "policy", "198.18.100.50", "8.8.8.8")
	if code != exitUsage || !strings.Contains(errOut, "could enter at several firewalls; name one with --device: fw01 ethernet1/5, fw02 vlan.100; name the start with --device <name>") {
		t.Errorf("tie: exit %d\n%s", code, errOut)
	}
	_, errOut, code = c.run("simulate", "policy", "203.0.113.5", "8.8.8.8")
	if code != exitUsage || !strings.Contains(errOut, "only default routes reach 203.0.113.5") || !strings.Contains(errOut, "; name the start with --device <name>") {
		t.Errorf("default routes only: exit %d\n%s", code, errOut)
	}
	// With --device given, the choice left is the router's; the text stays.
	_, errOut, code = c.run("simulate", "policy", "198.18.1.10", "8.8.8.8", "--device", "fw01")
	if code != exitUsage || !strings.Contains(errOut, "fw01 has several routers; name one with --router: default, lte") || strings.Contains(errOut, "name the start") {
		t.Errorf("router: exit %d\n%s", code, errOut)
	}
}

// An FQDN endpoint needs an IPv4 address in path mode (spec §3.3).
func TestPolicyPathNeedsAnAddress(t *testing.T) {
	t.Parallel()
	const want = "path mode needs an address for www.example.com; remove --no-dns or give an address"
	for _, tc := range []struct {
		name   string
		lookup func(context.Context, string) ([]netip.Addr, error)
		args   []string
	}{
		{"no dns", nil, []string{"--no-dns"}},
		{"failed lookup", func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }, nil},
		{"no address", func(context.Context, string) ([]netip.Addr, error) { return nil, nil }, nil},
		{"IPv6 only", func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("2001:db8::1")}, nil
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := pathLab(t)
			if tc.lookup != nil {
				c.lookup = tc.lookup
			}
			_, errOut, code := c.run(append([]string{"simulate", "policy", "198.18.1.10", "www.example.com"}, tc.args...)...)
			if code != exitUsage || !strings.Contains(errOut, want) {
				t.Errorf("exit %d\n%s", code, errOut)
			}
		})
	}
}

// The first IPv4 address in the resolver's order is traced; the path notes
// the others.
func TestPolicyPathTracesTheFirstIPv4Address(t *testing.T) {
	t.Parallel()
	c := pathLab(t)
	c.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("198.18.10.100"), netip.MustParseAddr("198.18.10.101")}, nil
	}
	out := c.want(0, "simulate", "policy", "198.18.1.10", "server.example.com")
	if !strings.Contains(out, "server.example.com resolved to 3 addresses; traced 198.18.10.100, not 2001:db8::1, 198.18.10.101") ||
		!strings.HasPrefix(out, "denied at hop 1: fw02 / vsys1") {
		t.Errorf("fqdn:\n%s", out)
	}
}

// A start device in the inventory but never fetched is a hole: results empty,
// exit 3.
func TestPolicyPathWithoutSnapshotsIsAHole(t *testing.T) {
	t.Parallel()
	c := pathFixture(t, false)
	out := c.want(3, "simulate", "policy", "198.18.1.10", "198.18.10.100", "--output", "json")
	if !strings.Contains(out, `"results": []`) || !strings.Contains(out, `"holes": [`) {
		t.Errorf("holes:\n%s", out)
	}
}

// Every registered simulation kind has a command builder.
func TestEveryKindHasACommand(t *testing.T) {
	t.Parallel()
	for _, k := range estate.Kinds() {
		if kindCommands[k] == nil {
			t.Errorf("kind %s has no command builder", k)
		}
	}
}
