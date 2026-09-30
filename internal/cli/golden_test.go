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
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			golden(t, tc.name, newCLI(t).want(tc.code, append(tc.args, "--output", "json")...))
		})
	}

	t.Run("store", func(t *testing.T) {
		t.Parallel()
		d := lab(t)
		c := newCLI(t)
		c.inventory(inventoryFor(d.Start(t)))
		c.want(0, "fetch", "fw01")
		d.Config = read(t, fixture("firewall-lab-changed.xml"))
		c.want(0, "fetch", "fw01")
		golden(t, "snapshot-list", c.want(0, "snapshot", "list", "fw01", "--output", "json"))
		golden(t, "snapshot-show", c.want(0, "snapshot", "show", "--output", "json"))
		golden(t, "snapshot-diff", c.want(0, "snapshot", "diff", "--vsys", "vsys1", "--output", "json"))
	})

	t.Run("simulate-nat", func(t *testing.T) {
		t.Parallel()
		out := natLab(t).want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01",
			"--router", "default", "--from-zone", "transport", "--port", "8443", "--output", "json")
		golden(t, "simulate-nat", out)
	})

	t.Run("simulate-routing", func(t *testing.T) {
		t.Parallel()
		out := routingLab(t, false).want(0, "simulate", "routing", "198.18.10.5", "8.8.8.8", "--output", "json")
		golden(t, "simulate-routing", out)
	})
}

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
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			goldenText(t, tc.name, newCLI(t).want(tc.code, tc.args...))
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
	})

	t.Run("simulate-nat", func(t *testing.T) {
		t.Parallel()
		goldenText(t, "simulate-nat", natLab(t).want(0, "simulate", "nat", "198.18.1.10", "198.18.250.10",
			"--device", "fw01", "--router", "default", "--from-zone", "transport", "--port", "8443", "--why"))
	})

	t.Run("simulate-routing", func(t *testing.T) {
		t.Parallel()
		goldenText(t, "simulate-routing", routingLab(t, false).want(0, "simulate", "routing", "198.18.10.5", "8.8.8.8", "--why"))
	})
}
