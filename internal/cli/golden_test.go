package cli

import (
	"context"
	"encoding/json"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
	"github.com/okaiser/proteus/internal/testconfig"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/golden")

// Values that change from run to run: stage timings, the fake devices' ports and the
// harness's temporary directories.
var (
	elapsedJSON = regexp.MustCompile(`"elapsed_(ms|ns)": [0-9.e-]+`)
	elapsedYAML = regexp.MustCompile(`elapsed_(ms|ns): [0-9.e-]+`)
	elapsedText = regexp.MustCompile(`\b[0-9]+(\.[0-9]+)?(ns|µs|ms|s)\b`)
	fakePort    = regexp.MustCompile(`127\.0\.0\.1:[0-9]+`)
	tempDir     = regexp.MustCompile(`/[^\s"]*/(TestGolden|TestContract)[^\s"]*`)
)

// normalise replaces what differs between runs. Text timings only occur in --why
// stage tables and the progress line, so the text pattern cannot hit a count.
func normalise(out string) string {
	out = elapsedJSON.ReplaceAllString(out, `"elapsed_$1": 0`)
	out = elapsedYAML.ReplaceAllString(out, `elapsed_$1: 0`)
	out = fakePort.ReplaceAllString(out, "127.0.0.1:PORT")
	return tempDir.ReplaceAllString(out, "TMP")
}

// golden compares a command's JSON output with testdata/golden/<name>.json.
func golden(t *testing.T, name, out string) { t.Helper(); goldenFile(t, name+".json", out) }

// goldenText compares text output; timings are normalised too.
func goldenText(t *testing.T, name, out string) {
	t.Helper()
	goldenFile(t, name+".txt", elapsedText.ReplaceAllString(out, "T"))
}

// sgrTags makes coloured output reviewable: each SGR sequence becomes a tag named
// after its palette role.
var sgrTags = strings.NewReplacer(
	"\x1b[31m", "‹bad›", "\x1b[33m", "‹warn›", "\x1b[32m", "‹ok›",
	"\x1b[1m", "‹head›", "\x1b[2m", "‹dim›", "\x1b[36m", "‹accent›", "\x1b[0m", "‹/›",
)

// goldenColour compares --color always text output, with SGR sequences as tags.
func goldenColour(t *testing.T, name, out string) {
	t.Helper()
	goldenFile(t, name+".color.txt", sgrTags.Replace(elapsedText.ReplaceAllString(out, "T")))
}

// goldenFile compares out with testdata/golden/<file>. The JSON envelope and the text
// layout are contracts: a change must show up here as a reviewed diff. Run go test
// ./internal/cli -run TestGolden -update to rewrite the files, then read the diff.
func goldenFile(t *testing.T, file, out string) {
	t.Helper()
	out = normalise(out)
	path := filepath.Join("testdata", "golden", file)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; run with -update to create it", err)
	}
	if out != string(want) {
		got, exp := strings.Split(out, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(got) || i < len(exp); i++ {
			var g, e string
			if i < len(got) {
				g = got[i]
			}
			if i < len(exp) {
				e = exp[i]
			}
			if g != e {
				t.Fatalf("%s differs at line %d:\n got: %s\nwant: %s", path, i+1, g, e)
			}
		}
	}
}

func fixture(name string) string { return "../../testdata/config/" + name }

// Every command's --output json, from files and from a fetched store.
func TestGoldenJSON(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		code int
		args []string
	}{
		{"search", 0, []string{"search", "10.124.0.1", "--file", fixture("firewall-multivsys.xml")}},
		{"search-limit", 0, []string{"search", "10.124.0.1", "--limit", "2", "--file", fixture("firewall-multivsys.xml")}},
		{"lookup", 0, []string{"lookup", "branch-to-dc", "--file", fixture("firewall-lookup.xml")}},
		{"snapshot-show-file", 0, []string{"snapshot", "show", "--file", fixture("firewall-multivsys.xml")}},
		{"simulate-policy", 0, []string{"simulate", "policy", "10.1.0.5", "10.2.0.5", "--port", "443", "--file", fixture("firewall-zones.xml")}},
		{"simulate-policy-default", 0, []string{"simulate", "policy", "10.2.0.5", "10.1.0.5", "--port", "443", "--from-zone", "dmz", "--to-zone", "inside", "--file", fixture("firewall-zones.xml")}},
		{"simulate-policy-doubt", 0, []string{"simulate", "policy", "198.19.0.254", "10.2.0.5", "--port", "443", "--from-zone", "labor", "--to-zone", "dmz", "--file", fixture("firewall-doubt.xml")}},
		{"simulate-policy-undecided", 3, []string{"simulate", "policy", "10.0.0.5", "203.0.113.5", "--port", "443", "--from-zone", "dmz", "--to-zone", "wan", "--file", fixture("firewall-doubt.xml")}},
		// Elements the schema does not describe stay out of the answer: no note,
		// nothing unresolved (AGENTS.md R3 keeps them in the load report).
		{"search-newfield", 0, []string{"search", "198.18.10.100", "--file", fixture("firewall-version-newfield.xml")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			golden(t, tc.name, newCLI(t).want(tc.code, append(tc.args, "--output", "json")...))
			goldenFile(t, tc.name+".yaml", newCLI(t).want(tc.code, append(tc.args, "--output", "yaml")...))
		})
	}

	t.Run("store", func(t *testing.T) {
		t.Parallel()
		d := lab(t)
		c := newCLI(t)
		c.inventory(inventoryFor(d.Start(t)))
		golden(t, "fetch", c.want(0, "fetch", "fw01", "--output", "json"))
		d.Config = read(t, fixture("firewall-lab-changed.xml"))
		c.want(0, "fetch", "fw01")
		golden(t, "snapshot-list", c.want(0, "snapshot", "list", "fw01", "--output", "json"))
		golden(t, "snapshot-show", c.want(0, "snapshot", "show", "--output", "json"))
		golden(t, "snapshot-diff", c.want(0, "snapshot", "diff", "--vsys", "vsys1", "--output", "json"))
		goldenFile(t, "snapshot-list.yaml", c.want(0, "snapshot", "list", "fw01", "--output", "yaml"))
		goldenFile(t, "snapshot-show.yaml", c.want(0, "snapshot", "show", "--output", "yaml"))
		goldenFile(t, "snapshot-diff.yaml", c.want(0, "snapshot", "diff", "--vsys", "vsys1", "--output", "yaml"))
	})

	t.Run("fetch-yaml", func(t *testing.T) {
		t.Parallel()
		c := newCLI(t)
		c.inventory(inventoryFor(lab(t).Start(t)))
		goldenFile(t, "fetch.yaml", c.want(0, "fetch", "fw01", "--output", "yaml"))
	})

	t.Run("inventory-init", func(t *testing.T) {
		t.Parallel()
		c := newCLI(t)
		golden(t, "inventory-init", c.want(0, "inventory", "init", "--output", "json"))
	})

	t.Run("empty-store", func(t *testing.T) {
		t.Parallel()
		c := newCLI(t)
		c.inventory(inventoryFor(lab(t).Start(t)))
		golden(t, "snapshot-list-empty", c.want(3, "snapshot", "list", "fw01", "--output", "json"))
		golden(t, "snapshot-show-empty", c.want(3, "snapshot", "show", "--output", "json"))
	})

	t.Run("simulate-nat", func(t *testing.T) {
		t.Parallel()
		out := natLab(t).want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01",
			"--router", "default", "--from-zone", "transport", "--port", "8443", "--output", "json")
		golden(t, "simulate-nat", out)
		outYAML := natLab(t).want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01",
			"--router", "default", "--from-zone", "transport", "--port", "8443", "--output", "yaml")
		goldenFile(t, "simulate-nat.yaml", outYAML)
	})

	for _, g := range pathGoldens(t) {
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			golden(t, g.name, pathVariant(t, g.pc, true).want(g.code, append(g.args, "--output", "json")...))
			goldenFile(t, g.name+".yaml", pathVariant(t, g.pc, true).want(g.code, append(g.args, "--output", "yaml")...))
		})
	}

	t.Run("simulate-routing", func(t *testing.T) {
		t.Parallel()
		out := routingLab(t, false).want(0, "simulate", "routing", "198.18.10.5", "8.8.8.8", "--output", "json")
		golden(t, "simulate-routing", out)
		outYAML := routingLab(t, false).want(0, "simulate", "routing", "198.18.10.5", "8.8.8.8", "--output", "yaml")
		goldenFile(t, "simulate-routing.yaml", outYAML)
	})
}

// colourFamilies are the table rows below that get a coloured golden twin (spec
// §11.2). The other families with one (fetch, snapshot-diff, simulate-nat,
// simulate-routing) get theirs in the store and simulate subtests.
var colourFamilies = map[string]bool{"search": true, "lookup": true, "simulate-policy-why": true, "simulate-policy-doubt": true}

// Every command's text output, so a change of layout shows up as a reviewed diff.
func TestGoldenText(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		code int
		args []string
	}{
		{"search", 0, []string{"search", "10.124.0.1", "--file", fixture("firewall-multivsys.xml")}},
		{"search-why", 0, []string{"search", "10.124.0.1", "--why", "--file", fixture("firewall-multivsys.xml")}},
		// With --why, so the JSON twin's answers are lines of it.
		{"search-limit", 0, []string{"search", "10.124.0.1", "--limit", "2", "--why", "--file", fixture("firewall-multivsys.xml")}},
		{"lookup", 0, []string{"lookup", "branch-to-dc", "--file", fixture("firewall-lookup.xml")}},
		{"snapshot-show-file", 0, []string{"snapshot", "show", "--file", fixture("firewall-multivsys.xml")}},
		{"simulate-policy", 0, []string{"simulate", "policy", "10.1.0.5", "10.2.0.5", "--port", "443", "--file", fixture("firewall-zones.xml")}},
		{"simulate-policy-why", 0, []string{"simulate", "policy", "10.1.0.5", "10.2.0.5", "--port", "443", "--why", "--file", fixture("firewall-zones.xml")}},
		{"simulate-policy-default", 0, []string{"simulate", "policy", "10.2.0.5", "10.1.0.5", "--port", "443", "--from-zone", "dmz", "--to-zone", "inside", "--file", fixture("firewall-zones.xml")}},
		{"simulate-policy-doubt", 0, []string{"simulate", "policy", "198.19.0.254", "10.2.0.5", "--port", "443", "--from-zone", "labor", "--to-zone", "dmz", "--why", "--file", fixture("firewall-doubt.xml")}},
		{"simulate-policy-undecided", 3, []string{"simulate", "policy", "10.0.0.5", "203.0.113.5", "--port", "443", "--from-zone", "dmz", "--to-zone", "wan", "--why", "--file", fixture("firewall-doubt.xml")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			goldenText(t, tc.name, newCLI(t).want(tc.code, tc.args...))
			if colourFamilies[tc.name] {
				goldenColour(t, tc.name, newCLI(t).want(tc.code, append(tc.args, "--color", "always")...))
			}
		})
	}

	t.Run("store", func(t *testing.T) {
		t.Parallel()
		d := lab(t)
		c := newCLI(t)
		c.inventory(inventoryFor(d.Start(t)))
		goldenText(t, "fetch", c.want(0, "fetch", "fw01"))
		d.Config = read(t, fixture("firewall-lab-changed.xml"))
		c.want(0, "fetch", "fw01")
		goldenText(t, "snapshot-list", c.want(0, "snapshot", "list", "fw01"))
		goldenText(t, "snapshot-show", c.want(0, "snapshot", "show"))
		goldenText(t, "snapshot-diff", c.want(0, "snapshot", "diff", "--vsys", "vsys1"))
		fresh := newCLI(t)
		fresh.inventory(inventoryFor(lab(t).Start(t)))
		goldenText(t, "fetch-why", fresh.want(0, "fetch", "fw01", "--why"))

		// Coloured twins of fetch and snapshot diff, on a fresh fixture, as the
		// plain ones are above.
		cc := newCLI(t)
		cd := lab(t)
		cc.inventory(inventoryFor(cd.Start(t)))
		goldenColour(t, "fetch", cc.want(0, "fetch", "fw01", "--color", "always"))
		cd.Config = read(t, fixture("firewall-lab-changed.xml"))
		cc.want(0, "fetch", "fw01", "--color", "always")
		goldenColour(t, "snapshot-diff", cc.want(0, "snapshot", "diff", "--vsys", "vsys1", "--color", "always"))
	})

	t.Run("simulate-nat", func(t *testing.T) {
		t.Parallel()
		goldenText(t, "simulate-nat", natLab(t).want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10",
			"--device", "fw01", "--router", "default", "--from-zone", "transport", "--port", "8443", "--why"))
		goldenColour(t, "simulate-nat", natLab(t).want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10",
			"--device", "fw01", "--router", "default", "--from-zone", "transport", "--port", "8443", "--why", "--color", "always"))
	})

	for _, g := range pathGoldens(t) {
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			goldenText(t, g.name, pathVariant(t, g.pc, true).want(g.code, g.args...))
			goldenColour(t, g.name, pathVariant(t, g.pc, true).want(g.code, append(g.args, "--color", "always")...))
		})
	}

	t.Run("simulate-routing", func(t *testing.T) {
		t.Parallel()
		goldenText(t, "simulate-routing", routingLab(t, false).want(0, "simulate", "routing", "198.18.10.5", "8.8.8.8", "--why"))
		goldenColour(t, "simulate-routing", routingLab(t, false).want(0, "simulate", "routing", "198.18.10.5", "8.8.8.8", "--why", "--color", "always"))
	})
}

// fqdnGoldens are simulate policy on an FQDN (spec 2026-10-09 §3.8). The fake
// resolver gives www.example.com one address and an alias. Off 203.0.113.0/24,
// to-web-by-name matches only through its FQDN object; on it, the address rule
// matches too.
var fqdnGoldens = []struct {
	name, addr string
}{
	{"simulate-policy-fqdn-only", "198.51.100.7"},
	{"simulate-policy-fqdn-and-address", "203.0.113.10"},
	// The first address is checked; the note names the second (D1b).
	{"simulate-policy-fqdn-two-addresses", "198.51.100.7 203.0.113.10"},
}

// fqdnCLI is a harness whose resolver answers www.example.com with the
// addresses in addr, separated by spaces, and web.cdn.example.net as its
// canonical name.
func fqdnCLI(t *testing.T, addr string) *cli {
	c := newCLI(t)
	c.lookup = func(context.Context, string) ([]netip.Addr, error) {
		var out []netip.Addr
		for a := range strings.FieldsSeq(addr) {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
	c.canonical = func(context.Context, string) (string, error) { return "web.cdn.example.net.", nil }
	return c
}

func TestGoldenFQDN(t *testing.T) {
	t.Parallel()
	for _, g := range fqdnGoldens {
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			args := []string{"simulate", "policy", "10.0.0.1", "www.example.com", "--port", "443", "--file", fixture("firewall-simulate.xml")}
			goldenText(t, g.name, fqdnCLI(t, g.addr).want(0, append(args, "--why")...))
			golden(t, g.name, fqdnCLI(t, g.addr).want(0, append(args, "--output", "json")...))
			goldenFile(t, g.name+".yaml", fqdnCLI(t, g.addr).want(0, append(args, "--output", "yaml")...))
		})
	}
}

// appConfig copies firewall-appid.xml into a new directory, with the content
// file of version 8000-1000 beside it as apps.xml.gz, and returns the copy's
// path (spec 2026-10-16 §6). No binary fixture is committed (D15).
func appConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte(read(t, fixture("firewall-appid.xml"))), 0o600); err != nil {
		t.Fatal(err)
	}
	testconfig.Content(t, filepath.Join(dir, estate.AppsFile))
	return path
}

// appPolicy runs simulate policy from inside to outside on the App-ID
// fixture and returns what its golden holds: stdout, or stderr for a usage
// error, which prints nothing on stdout.
func appPolicy(t *testing.T, code int, args ...string) string {
	t.Helper()
	argv := append([]string{"simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", appConfig(t)}, args...)
	out, errOut, got := newCLI(t).run(argv...)
	if got != code {
		t.Fatalf("%v: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", argv, got, code, out, errOut)
	}
	if code == exitUsage {
		return errOut
	}
	return out
}

// simulate policy with an application on a file (spec 2026-10-16 §4.1): an
// explicit match on the default port, an implicit match (I1), and a name the
// data lacks, which is a usage error with the nearest names (P10).
func TestGoldenApp(t *testing.T) {
	t.Parallel()
	for _, g := range []struct {
		name string
		code int
		args []string
	}{
		{"simulate-policy-app", 0, []string{"--application", "ssl", "--port", "443"}},
		{"simulate-policy-app-implicit", 0, []string{"--application", "web-browsing", "--port", "80"}},
		{"simulate-policy-app-unknown", exitUsage, []string{"--application", "app-medai", "--port", "443"}},
	} {
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			golden(t, g.name, appPolicy(t, g.code, append(g.args, "--output", "json")...))
			goldenFile(t, g.name+".yaml", appPolicy(t, g.code, append(g.args, "--output", "yaml")...))
			goldenText(t, g.name, appPolicy(t, g.code, append(g.args, "--why")...))
		})
	}
}

// userConfig is the User-ID fixture with its identity file beside it.
func userConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte(read(t, fixture("firewall-identity.xml"))), 0o600); err != nil {
		t.Fatal(err)
	}
	testconfig.Identity(t, filepath.Join(dir, estate.IdentityFile))
	return path
}

// simulate policy with the identity data on a file (spec 2026-10-17 §5.1,
// §5.4): a user from the mapping of the source, a UPN given as --user, and
// no user.
func TestGoldenUser(t *testing.T) {
	t.Parallel()
	for _, g := range []struct {
		name string
		args []string
	}{
		{"simulate-policy-user", []string{"198.51.100.11", "192.0.2.10"}},
		{"simulate-policy-user-given", []string{"203.0.113.5", "192.0.2.11", "--user", "alice@example.com"}},
		{"simulate-policy-user-none", []string{"203.0.113.5", "192.0.2.14"}},
	} {
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"simulate", "policy"}, g.args...)
			args = append(args, "--port", "443", "--from-zone", "inside", "--to-zone", "outside", "--file", userConfig(t))
			golden(t, g.name, newCLI(t).want(0, append(args, "--output", "json")...))
			goldenFile(t, g.name+".yaml", newCLI(t).want(0, append(args, "--output", "yaml")...))
			goldenText(t, g.name, newCLI(t).want(0, append(args, "--why")...))
		})
	}
}

// The user line names where the user came from, and a path hop with a user
// gets a user row (spec 2026-10-17 §5.1).
func TestUserLine(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		u    securitypolicy.FlowUser
		want string
	}{
		{securitypolicy.FlowUser{From: "none"}, "none"},
		{securitypolicy.FlowUser{Name: `example.com\alice`, From: "mapping", IP: "198.51.100.11"}, `example.com\alice (from the mapping of 198.51.100.11)`},
		{
			securitypolicy.FlowUser{Name: `example.com\alice`, From: "mapping", IP: "198.51.100.11", Given: `example.com\bob`},
			`example.com\alice (from the mapping of 198.51.100.11, which wins over --user example.com\bob)`,
		},
		{securitypolicy.FlowUser{Name: `example.com\alice`, From: "given"}, `example.com\alice (from --user)`},
		{securitypolicy.FlowUser{Name: `example.com\alice`, From: "given", Given: "alice@example.com"}, `example.com\alice (from --user alice@example.com)`},
	} {
		if got := userLine(tc.u); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.u, got, tc.want)
		}
	}
	check := func(u *securitypolicy.FlowUser) pathpolicy.Hop {
		return pathpolicy.Hop{Checks: []pathpolicy.CheckResult{{
			Name: "security", Verdict: pathpolicy.Pass, Rule: "r1", Security: &securitypolicy.Verdict{User: u},
		}}}
	}
	rows := policyRows(check(&securitypolicy.FlowUser{Name: `example.com\alice`, From: "given"}))
	if len(rows) != 2 || rows[1] != [2]string{"user", `example.com\alice (from --user)`} {
		t.Errorf("rows %v", rows)
	}
	for _, u := range []*securitypolicy.FlowUser{nil, {From: "none"}} {
		if rows := policyRows(check(u)); len(rows) != 1 {
			t.Errorf("%+v: rows %v", u, rows)
		}
	}
}

// search and lookup with the App-ID data on a file (spec 2026-10-16 §5): ssl
// found through nested groups and implicit use, the card of an application,
// and the card of a filter with the applications it selects.
func TestGoldenAppFind(t *testing.T) {
	t.Parallel()
	for _, g := range []struct {
		name string
		args []string
	}{
		// With --why, so the JSON twin's answers are lines of the text.
		{"search-app", []string{"search", "ssl", "--why"}},
		{"lookup-app", []string{"lookup", "app-remote"}},
		{"lookup-app-filter", []string{"lookup", "f-media"}},
	} {
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			args := append(slices.Clone(g.args), "--file", appConfig(t))
			golden(t, g.name, newCLI(t).want(0, append(args, "--output", "json")...))
			goldenFile(t, g.name+".yaml", newCLI(t).want(0, append(args, "--output", "yaml")...))
			goldenText(t, g.name, newCLI(t).want(0, args...))
		})
	}
}

// answerText is the text golden that shows a JSON golden's answers: search
// adds its findings' answers only with --why (spec 2026-10-09 §3.3).
var answerText = map[string]string{"search": "search-why"}

// answering are the commands whose results carry an answer: the questions of
// the query layer.
var answering = map[string]bool{
	"simulate policy": true, "simulate routing": true, "simulate nat": true,
	"search": true, "lookup": true, "snapshot diff": true,
}

// Every result's answer, and a summary's, is a line of the text output of the
// same question (spec 2026-10-09 §3.3, §7). Indentation is not part of it; a
// routing end line is compared with its runs of spaces collapsed.
func TestGoldenAnswersAreTextLines(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join("testdata", "golden", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		textName := name
		if n, ok := answerText[name]; ok {
			textName = n
		}
		text, err := os.ReadFile(filepath.Join("testdata", "golden", textName+".txt"))
		if err != nil {
			continue // no text twin, such as inventory init
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			Command string `json:"command"`
			Results []struct {
				Answer *string `json:"answer"`
			} `json:"results"`
			Summary *struct {
				Answer string `json:"answer"`
			} `json:"summary"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if !answering[env.Command] {
			continue
		}
		lines := map[string]bool{}
		for _, l := range strings.Split(string(text), "\n") {
			lines[strings.TrimSpace(l)] = true
			if env.Command == "simulate routing" {
				lines[strings.Join(strings.Fields(l), " ")] = true
			}
		}
		var answers []string
		for _, r := range env.Results {
			if r.Answer == nil {
				t.Errorf("%s: a result has no answer", file)
				continue
			}
			answers = append(answers, *r.Answer)
		}
		if env.Summary != nil {
			answers = append(answers, env.Summary.Answer)
		}
		for _, a := range answers {
			checked++
			if a == "" || !lines[a] {
				t.Errorf("%s: answer %q is not a line of %s.txt", file, a, textName)
			}
		}
	}
	if checked < 20 {
		t.Errorf("only %d answers checked", checked)
	}
}

// Every question's --detail summary (spec 2026-10-09 §3.5): the same
// envelope with "detail": "summary" and summary results.
func TestGoldenSummary(t *testing.T) {
	t.Parallel()
	summary := []string{"--output", "json", "--detail", "summary"}
	for _, tc := range []struct {
		name string
		code int
		args []string
	}{
		{"search-summary", 0, []string{"search", "10.124.0.1", "--file", fixture("firewall-multivsys.xml")}},
		{"lookup-summary", 0, []string{"lookup", "branch-to-dc", "--file", fixture("firewall-lookup.xml")}},
		{"simulate-policy-summary", 3, []string{"simulate", "policy", "10.0.0.5", "203.0.113.5", "--port", "443", "--from-zone", "dmz", "--to-zone", "wan", "--file", fixture("firewall-doubt.xml")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			golden(t, tc.name, newCLI(t).want(tc.code, append(tc.args, summary...)...))
		})
	}
	t.Run("search-summary-yaml", func(t *testing.T) {
		t.Parallel()
		goldenFile(t, "search-summary.yaml", newCLI(t).want(0, "search", "10.124.0.1", "--file", fixture("firewall-multivsys.xml"),
			"--output", "yaml", "--detail", "summary"))
	})
	for _, g := range pathGoldens(t) {
		if g.name != "simulate-policy-path-rule" && g.name != "simulate-policy-path-undecided" {
			continue
		}
		t.Run(g.name, func(t *testing.T) {
			t.Parallel()
			golden(t, g.name+"-summary", pathVariant(t, g.pc, true).want(g.code, append(g.args, summary...)...))
		})
	}
	t.Run("simulate-nat-summary", func(t *testing.T) {
		t.Parallel()
		golden(t, "simulate-nat-summary", natLab(t).want(0, append([]string{
			"simulate", "nat", "198.18.1.10", "198.18.250.10",
			"--device", "fw01", "--router", "default", "--from-zone", "transport", "--port", "8443",
		}, summary...)...))
	})
	t.Run("simulate-routing-summary", func(t *testing.T) {
		t.Parallel()
		golden(t, "simulate-routing-summary", routingLab(t, false).want(0, append([]string{"simulate", "routing", "198.18.10.5", "8.8.8.8"}, summary...)...))
	})
	t.Run("snapshot-diff-summary", func(t *testing.T) {
		t.Parallel()
		d := lab(t)
		c := newCLI(t)
		c.inventory(inventoryFor(d.Start(t)))
		c.want(0, "fetch", "fw01")
		d.Config = read(t, fixture("firewall-lab-changed.xml"))
		c.want(0, "fetch", "fw01")
		golden(t, "snapshot-diff-summary", c.want(0, append([]string{"snapshot", "diff", "--vsys", "vsys1"}, summary...)...))
	})
}

// --detail takes summary or full, and only with JSON or YAML output.
func TestDetailIsAUsageErrorWithText(t *testing.T) {
	t.Parallel()
	args := []string{"search", "10.124.0.1", "--file", fixture("firewall-multivsys.xml")}
	for _, extra := range [][]string{{"--detail", "summary"}, {"--detail", "full"}, {"--output", "json", "--detail", "short"}} {
		out, errOut, code := newCLI(t).run(append(append([]string{}, args...), extra...)...)
		if code != exitUsage || out != "" || !strings.Contains(errOut, "--detail") {
			t.Errorf("%v: exit %d\n%s\n%s", extra, code, out, errOut)
		}
	}
	full := newCLI(t).want(0, append(args, "--output", "json", "--detail", "full")...)
	if def := newCLI(t).want(0, append(args, "--output", "json")...); def != full || !strings.Contains(full, `"detail": "full"`) {
		t.Errorf("the default is not full:\n%s", def)
	}
}
