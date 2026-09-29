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

// Values that change from run to run: stage timings and the fake devices' ports.
var (
	elapsed  = regexp.MustCompile(`"elapsed_(ms|ns)": [0-9.e-]+`)
	fakePort = regexp.MustCompile(`127\.0\.0\.1:[0-9]+`)
)

// golden compares a command's JSON output with testdata/golden/<name>.json. The JSON
// envelope is a contract (spec §15 C10): a field that changes name or shape must show
// up here as a reviewed diff. Run go test ./internal/cli -run TestGolden -update to
// rewrite the files, then read the diff.
func golden(t *testing.T, name, out string) {
	t.Helper()
	out = elapsed.ReplaceAllString(out, `"elapsed_$1": 0`)
	out = fakePort.ReplaceAllString(out, "127.0.0.1:PORT")
	path := filepath.Join("testdata", "golden", name+".json")
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
