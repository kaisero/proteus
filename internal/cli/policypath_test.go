package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/fakepanos"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// pathConfigs varies the path fixture: each device's configuration (the base
// one when nil), and fw01 without its default routes, so a destination beyond
// it has no route there.
type pathConfigs struct {
	fw01, fw02 []byte
	noDefault  bool
	// fw02NextHop replaces fw02's next hop to fw01, so the path leaves the
	// estate there.
	fw02NextHop string
}

// fibCmd asks a device for its forwarding table.
const fibCmd = "<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>"

// defaultRoute is a default route's entry in a forwarding table.
var defaultRoute = regexp.MustCompile(`(?s)<entry>\s*<id>\d+</id>\s*<dst>0\.0\.0\.0/0</dst>.*?</entry>`)

// pathVariant is the path fixture as an inventory of fw01 and fw02, both
// fetched when complete is set.
func pathVariant(t *testing.T, pc pathConfigs, complete bool) *cli {
	t.Helper()
	if pc.fw01 == nil {
		pc.fw01 = pathlab.Read(t, pathlab.ConfigFile(pathlab.FW01))
	}
	fw01, fw02 := lab(t), labFW02(t)
	fw01.Config = string(pc.fw01)
	if pc.fw02 != nil {
		fw02.Config = string(pc.fw02)
	}
	if pc.noDefault {
		fw01.Ops[fibCmd] = defaultRoute.ReplaceAllString(fw01.Ops[fibCmd], "")
	}
	if pc.fw02NextHop != "" {
		fw02.Ops[fibCmd] = strings.Replace(fw02.Ops[fibCmd], "<nexthop>198.19.0.254</nexthop>", "<nexthop>"+pc.fw02NextHop+"</nexthop>", 1)
	}
	c := newCLI(t)
	c.inventory(inventoryFor(fw01.Start(t), fw02.Start(t)))
	if complete {
		c.want(0, "fetch", "fw01", "fw02")
	}
	return c
}

// allowing is a device's base configuration whose interzone default rule allows.
func allowing(t *testing.T, device string) []byte {
	t.Helper()
	return pathlab.Config(t, device, pathlab.Defaults{Local: pathlab.Entry(pathlab.Interzone, "allow")})
}

// withRule is a device's base configuration with one security rule between two
// zones.
func withRule(t *testing.T, device, from, to, name, action string) []byte {
	t.Helper()
	rule := `<rulebase><security><rules><entry name="` + name + `">` +
		`<from><member>` + from + `</member></from><to><member>` + to + `</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<source-user><member>any</member></source-user><application><member>any</member></application>` +
		`<service><member>any</member></service><action>` + action + `</action></entry></rules></security></rulebase>`
	return bytes.Replace(pathlab.Read(t, pathlab.ConfigFile(device)), []byte("</zone>"), []byte("</zone>"+rule), 1)
}

// pathGoldens are the path mode answers the golden files hold: allowed, denied
// by a rule, by a default rule and by no route, and undecided (spec §10.1).
func pathGoldens(t *testing.T) []struct {
	name string
	code int
	pc   pathConfigs
	args []string
} {
	t.Helper()
	differ := pathlab.Defaults{Local: pathlab.Entry(pathlab.Interzone, "allow"), Pushed: pathlab.Entry(pathlab.Interzone, "deny")}
	flow := []string{"simulate", "policy", pathlab.Source, pathlab.Destination, "--port", "443"}
	return []struct {
		name string
		code int
		pc   pathConfigs
		args []string
	}{
		{"simulate-policy-path-allowed", 0, pathConfigs{fw01: allowing(t, pathlab.FW01), fw02: allowing(t, pathlab.FW02)}, flow},
		{"simulate-policy-path-rule", 0, pathConfigs{fw01: withRule(t, pathlab.FW01, "transport", "server", "block-servers", "deny"), fw02: allowing(t, pathlab.FW02)}, flow},
		{"simulate-policy-path-default", 0, pathConfigs{}, append(flow, "--why")},
		{"simulate-policy-path-no-route", 0, pathConfigs{fw02: allowing(t, pathlab.FW02), noDefault: true}, []string{"simulate", "policy", pathlab.Source, "198.18.30.5", "--port", "443"}},
		{"simulate-policy-path-undecided", 3, pathConfigs{fw02: pathlab.Config(t, pathlab.FW02, differ)}, flow},
		{"simulate-policy-path-left-estate", 3, pathConfigs{fw02: allowing(t, pathlab.FW02), fw02NextHop: "198.19.0.77"}, flow},
	}
}

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

// The path answer as JSON: one result in the path shape, hop keys present even
// when empty, the checks object in check order.
func TestPolicyPathJSON(t *testing.T) {
	t.Parallel()
	out := pathLab(t).want(0, "simulate", "policy", pathlab.Source, pathlab.Destination, "--output", "json")
	var env struct {
		Input   struct{ Mode string }
		Results []struct {
			Mode, Verdict string
			At            struct{ Hop int }
			Hops          []map[string]json.RawMessage
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Results) != 1 {
		t.Fatalf("%v\n%s", err, out)
	}
	r := env.Results[0]
	if env.Input.Mode != "path" || r.Mode != "path" || r.Verdict != "denied" || r.At.Hop != 1 || len(r.Hops) != 2 {
		t.Fatalf("%+v", env)
	}
	for _, k := range []string{"notes", "pbf", "ecmp_not_followed", "zone_placeholder", "after_deny", "checks"} {
		if _, ok := r.Hops[0][k]; !ok {
			t.Errorf("hop has no %q", k)
		}
	}
	if got := string(r.Hops[1]["after_deny"]); got != "true" {
		t.Errorf("after_deny = %s", got)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, r.Hops[0]["checks"]); err != nil || !strings.HasPrefix(compact.String(), `{"security":{"verdict":"stop"`) {
		t.Errorf("checks = %s", r.Hops[0]["checks"])
	}
}

// An undecided hop is an unresolved entry, after the deny too, so the answer
// exits 3 (spec §5.4).
func TestPolicyPathUndecidedIsUnresolved(t *testing.T) {
	t.Parallel()
	differ := pathlab.Defaults{Local: pathlab.Entry(pathlab.Interzone, "allow"), Pushed: pathlab.Entry(pathlab.Interzone, "deny")}
	// fw02 denies first; fw01, after the deny, cannot decide.
	c := pathVariant(t, pathConfigs{fw01: pathlab.Config(t, pathlab.FW01, differ)}, true)
	out := c.want(3, "simulate", "policy", pathlab.Source, pathlab.Destination)
	if !strings.HasPrefix(out, "denied at hop 1:") ||
		!strings.Contains(out, "policy  undecided: local and pushed default rules disagree; precedence not verified (after the deny)") ||
		!strings.Contains(out, "unresolved: fw01/vsys1: local and pushed default rules disagree") {
		t.Errorf("after the deny:\n%s", out)
	}
}

// An HA node's hop reads the active member's snapshot, not the first
// member's (spec §3.4). fw01 and fw03 are one pair; fw03 is active and its
// default rule allows.
func TestPolicyPathReadsTheActiveMember(t *testing.T) {
	t.Parallel()
	haCmd := "<show><high-availability><state/></high-availability></show>"
	state := func(local, localSerial, peer, peerSerial string) string {
		return fakepanos.Success(`<enabled>yes</enabled><group><mode>active-passive</mode><local-info><state>` + local +
			`</state><serial-num>` + localSerial + `</serial-num></local-info><peer-info><state>` + peer +
			`</state><serial-num>` + peerSerial + `</serial-num><mgmt-ip>192.0.2.2</mgmt-ip></peer-info></group>`)
	}
	first, active := lab(t), lab(t)
	first.Config = string(pathlab.Read(t, pathlab.ConfigFile(pathlab.FW01)))
	active.Config = string(allowing(t, pathlab.FW01))
	// The first member names a suspended peer, so its fetch keeps its own data.
	first.Ops[haCmd] = state("passive", "A", "suspended", "B")
	active.Ops[haCmd] = state("active", "B", "passive", "A")
	c := newCLI(t)
	c.inventory(inventoryFor(first.Start(t), pathVariantFW02(t), active.Start(t)))
	c.want(0, "fetch", "fw01", "fw02", "fw03")
	out := c.want(0, "simulate", "policy", pathlab.Source, pathlab.Destination, "--output", "json")
	var env struct {
		Results []struct {
			Hops []struct {
				Device string
				Checks struct {
					Security struct{ Verdict, Rule string }
				}
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Results) != 1 || len(env.Results[0].Hops) != 2 {
		t.Fatalf("%v\n%s", err, out)
	}
	if h := env.Results[0].Hops[1]; h.Device != "fw01" || h.Checks.Security.Verdict != "pass" {
		t.Errorf("hop 2 must read fw03's configuration: %+v", h)
	}
}

// pathVariantFW02 is fw02 of the path fixture, started.
func pathVariantFW02(t *testing.T) string { t.Helper(); return labFW02(t).Start(t) }

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

// A version gap on a hop is a note in the text and in the envelope, not an
// unresolved entry: the hop's check is inferred and still decides (spec E25).
func TestPolicyPathVersionGapIsANote(t *testing.T) {
	t.Parallel()
	gapped := bytes.Replace(pathlab.Read(t, pathlab.ConfigFile(pathlab.FW02)), []byte(`version="11.2.0"`), []byte(`version="12.2.0"`), 1)
	c := pathVariant(t, pathConfigs{fw02: gapped}, true)
	args := []string{"simulate", "policy", pathlab.Source, pathlab.Destination}
	out := c.want(0, args...)
	if !strings.Contains(out, "  note: fw02 / vsys1: ") || !strings.Contains(out, "12.2.0") || !strings.Contains(out, "fidelity: inferred") {
		t.Errorf("text:\n%s", out)
	}
	var env struct {
		Unresolved []any
		Notes      []struct{ Device, Vsys, Note string }
	}
	out = c.want(0, append(args, "--output", "json")...)
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Unresolved) != 0 {
		t.Fatalf("json: %v\n%s", err, out)
	}
	found := false
	for _, n := range env.Notes {
		found = found || n.Device == "fw02" && n.Vsys == "vsys1" && strings.Contains(n.Note, "PAN-OS 12.2.0")
	}
	if !found {
		t.Errorf("the gap must be an envelope note: %+v", env.Notes)
	}
}

// Routing draws a hop where no route matched: its router is the ingress's.
func TestRoutingDropsWithoutARoute(t *testing.T) {
	t.Parallel()
	c := pathVariant(t, pathConfigs{noDefault: true}, true)
	out := c.want(0, "simulate", "routing", pathlab.Source, "198.18.30.5")
	if !strings.Contains(out, "┌─ fw01 ─ vsys1 ─ router default") || !strings.Contains(out, "dropped on fw01: no route to 198.18.30.5") {
		t.Errorf("routing:\n%s", out)
	}
}

// The run log follows the path: the start, each hop's check and verdict, the
// answer (spec §9).
func TestPolicyPathLogs(t *testing.T) {
	t.Parallel()
	c := pathLab(t)
	c.want(0, "simulate", "policy", pathlab.Source, pathlab.Destination, "--device", "fw02")
	log := c.logFile()
	for _, want := range []string{
		"[STEP] policy path 198.18.1.10 -> 198.18.10.100, start fw02",
		"[STEP] routing/hop1/lookup: ",
		"[STEP] hop1: security on fw02/vsys1",
		"[STEP] policy/first-match: ",
		"[STEP] hop1: stop (default rule interzone-default (deny), built-in)",
		"[STEP] hop2: security on fw01/vsys1",
		"[STEP] path verdict: denied at hop 1 (security)",
		"[RUN] answer: simulate policy: ",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q in:\n%s", want, log)
		}
	}
	c.want(0, "simulate", "policy", pathlab.Source, pathlab.Destination)
	if log := c.logFile(); !strings.Contains(log, "start placed by the source") {
		t.Errorf("start:\n%s", log)
	}
}

// A hop's configuration that cannot be read is a hole; the answer is
// undecided and exits 3.
func TestPolicyPathUnreadableConfigIsAHole(t *testing.T) {
	t.Parallel()
	c := pathLab(t)
	cfgs, err := filepath.Glob(filepath.Join(c.env["PROTEUS_STORE"], "fw01", "*", "config.xml"))
	if err != nil || len(cfgs) == 0 {
		t.Fatalf("no stored configuration of fw01: %v", err)
	}
	for _, f := range cfgs {
		if err := os.WriteFile(f, []byte("<config"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c.want(3, "simulate", "policy", pathlab.Source, pathlab.Destination, "--no-dns")
	out := c.want(3, "simulate", "policy", pathlab.Source, pathlab.Destination, "--device", "fw02", "--port", "443", "--output", "json")
	var env struct {
		Holes   []struct{ Device, Reason string }
		Results []struct{ Verdict string }
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Holes) != 1 || env.Holes[0].Device != "fw01" || len(env.Results) != 1 {
		t.Errorf("%v\n%s", err, out)
	}
}

// Errors before a path is traced.
func TestPolicyPathInputErrors(t *testing.T) {
	t.Parallel()
	c := pathLab(t)
	c.want(2, "simulate", "policy", "10.0.0.0/8", pathlab.Destination)
	c.want(2, "simulate", "policy", pathlab.Source, pathlab.Destination, "--port", "https")
	c.env["PROTEUS_USERS"] = filepath.Join(c.dir, "no-such-users.json")
	c.want(1, "simulate", "policy", pathlab.Source, pathlab.Destination)
	newCLI(t).want(1, "simulate", "policy", pathlab.Source, pathlab.Destination)
}

// --file keeps the single-target answer: no rule and no default rule, and a
// vsys the file lacks.
func TestPolicyFileEdges(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	out := c.want(3, "simulate", "policy", "10.2.0.5", "10.1.0.5", "--file", fixture("firewall-ruletype.xml"), "--vsys", "vsys1")
	if !strings.Contains(out, "no enabled rule matches\n") || !strings.Contains(out, "undecided: the default rule depends on the zones") {
		t.Errorf("no match:\n%s", out)
	}
	out = c.want(3, "simulate", "policy", "1.1.1.1", "2.2.2.2", "--file", fixture("firewall-zones.xml"), "--vsys", "vsys9", "--output", "json")
	if !strings.Contains(out, `"results": []`) {
		t.Errorf("a missing vsys has no result:\n%s", out)
	}
}

// printRun says what a stored forwarding table tells about relevance, and
// printCandidates colours an allowing default rule ok.
func TestPrintRunRelevanceAndDefault(t *testing.T) {
	t.Parallel()
	ts, _, err := estate.OpenFile(fixture("firewall-zones.xml"), []string{"vsys1"}, nil)
	if err != nil || len(ts) != 1 {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		rel  securitypolicy.Relevance
		want string
	}{
		{securitypolicy.Relevance{Known: true, Relevant: true, Reason: "10.0.0.0/8 via default covers 10.0.0.1"}, "  relevant   10.0.0.0/8 via default covers 10.0.0.1\n"},
		{securitypolicy.Relevance{Known: true, Reason: "only a default route"}, "  relevance  not relevant: only a default route\n"},
	} {
		var b bytes.Buffer
		v := securitypolicy.Verdict{
			Relevance: tc.rel, Default: "intrazone-default", DefaultAction: "allow", DefaultSource: "built-in",
			Zones: securitypolicy.ZoneDerivation{To: []string{"inside"}, Source: "given"},
		}
		printRun(&textOut{w: &b, pal: palette{on: true}}, simulate.Run{Fidelity: simulate.Exact}, ts[0], v, simulate.Flow{Protocol: "tcp"}, true)
		if !strings.Contains(b.String(), tc.want) || !strings.Contains(b.String(), "zones      from any, to inside (given)") ||
			!strings.Contains(b.String(), palette{on: true}.ok("allow")) {
			t.Errorf("got:\n%s", b.String())
		}
	}
}

// A check without a security verdict names no action; checks marshal in list
// order.
func TestCheckActionAndChecksJSON(t *testing.T) {
	t.Parallel()
	if got := checkAction(pathpolicy.CheckResult{}); got != "" {
		t.Errorf("checkAction = %q", got)
	}
	b, err := json.Marshal(checksJSON{{name: "security"}, {name: "nat"}})
	if err != nil || !strings.HasPrefix(string(b), `{"security":{`) || !strings.Contains(string(b), `},"nat":{`) {
		t.Errorf("%v %s", err, b)
	}
}

// The verdict line names what the hop looked up, the translated address after
// a destination NAT, and survives a point without its hop.
func TestVerdictLineEdges(t *testing.T) {
	t.Parallel()
	pre, post := simulate.Addr(netip.MustParseAddr("198.18.250.10")), simulate.Addr(netip.MustParseAddr("198.18.10.100"))
	r := pathpolicy.Result{
		Verdict: pathpolicy.VerdictDenied, At: &pathpolicy.Point{Hop: 1, Check: "routing"},
		Hops: []pathpolicy.Hop{{Index: 1, Routing: routing.Hop{Device: "fw01", Flow: simulate.Flow{Destination: pre}, PostNAT: &simulate.Flow{Destination: post}}}},
	}
	if got := verdictLine(palette{}, r); got != "denied at hop 1: no route to 198.18.10.100 on fw01" {
		t.Errorf("after NAT: %s", got)
	}
	r = pathpolicy.Result{Verdict: pathpolicy.VerdictUndecided, At: &pathpolicy.Point{Hop: 0, Check: "routing", Reason: "no hop"}}
	if got := verdictLine(palette{}, r); got != "undecided at hop 0: no hop" {
		t.Errorf("no hop: %s", got)
	}
	if un := pathUnresolved(r, nil); len(un) != 1 || un[0].Reason != "no hop" {
		t.Errorf("unresolved: %+v", un)
	}
}
