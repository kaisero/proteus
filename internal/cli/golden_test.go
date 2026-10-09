package cli

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
		{"lookup", 0, []string{"lookup", "branch-to-dc", "--file", fixture("firewall-lookup.xml")}},
		{"snapshot-show-file", 0, []string{"snapshot", "show", "--file", fixture("firewall-multivsys.xml")}},
		{"simulate-policy", 0, []string{"simulate", "policy", "10.1.0.5", "10.2.0.5", "--port", "443", "--file", fixture("firewall-zones.xml")}},
		{"simulate-policy-default", 0, []string{"simulate", "policy", "10.2.0.5", "10.1.0.5", "--port", "443", "--from-zone", "dmz", "--to-zone", "inside", "--file", fixture("firewall-zones.xml")}},
		{"simulate-policy-doubt", 0, []string{"simulate", "policy", "198.19.0.254", "10.2.0.5", "--port", "443", "--from-zone", "labor", "--to-zone", "dmz", "--file", fixture("firewall-doubt.xml")}},
		{"simulate-policy-undecided", 3, []string{"simulate", "policy", "10.0.0.5", "203.0.113.5", "--port", "443", "--from-zone", "dmz", "--to-zone", "wan", "--file", fixture("firewall-doubt.xml")}},
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
