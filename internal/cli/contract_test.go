package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// planStep is the last step of docs/plans/2026-09-30-cli-consistency.md that has
// landed. A row or check that waits for a later step is skipped until then; each
// step raises this number. When it reaches 11, nothing is skipped.
const planStep = 4

// fixture builds a fresh CLI for one run. complete is false for the "no snapshot"
// fixture: the same inventory, never fetched.
type fixtureFunc func(t *testing.T, complete bool) *cli

func labFixture(fetches int) fixtureFunc {
	return func(t *testing.T, complete bool) *cli {
		t.Helper()
		d := lab(t)
		c := newCLI(t)
		c.inventory(inventoryFor(d.Start(t)))
		if complete {
			for range fetches {
				c.want(0, "fetch", "fw01")
			}
		}
		return c
	}
}

func natFixture(t *testing.T, complete bool) *cli {
	t.Helper()
	d := lab(t)
	d.Config = read(t, fixture("firewall-nat.xml"))
	c := newCLI(t)
	c.inventory(inventoryFor(d.Start(t)))
	if complete {
		c.want(0, "fetch", "fw01")
	}
	return c
}

func routingFixture(t *testing.T, complete bool) *cli {
	t.Helper()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), labFW02(t).Start(t)))
	if complete {
		c.want(0, "fetch", "fw01", "fw02")
	}
	return c
}

// brokenDocFixture serves fw01 with one show command refused.
func brokenDocFixture(t *testing.T, _ bool) *cli {
	t.Helper()
	d := lab(t)
	delete(d.Ops, "<show><interface>all</interface></show>")
	c := newCLI(t)
	c.inventory(inventoryFor(d.Start(t)))
	return c
}

// emptyFixture has no inventory at all.
func emptyFixture(t *testing.T, _ bool) *cli { t.Helper(); return newCLI(t) }

type contractRow struct {
	name     string
	fixture  fixtureFunc
	args     []string
	raw      bool // run with a fresh --config instead of the harness's
	complete int  // expected exit with the fixture fetched
	empty    int  // expected exit with nothing fetched
	answers  bool // an answer exists even on exit 1 (fetch)
	until    int  // the plan step that makes the row pass
}

// contractRows is spec §11.1. A leaf command with no row fails TestContractCoversEveryCommand.
func contractRows() []contractRow {
	return []contractRow{
		{name: "fetch", fixture: labFixture(0), args: []string{"fetch", "fw01"}, answers: true, until: 9},
		{name: "fetch-broken-doc", fixture: brokenDocFixture, args: []string{"fetch", "fw01"}, complete: 3, empty: 3, answers: true, until: 9},
		{name: "inventory-init", fixture: emptyFixture, args: []string{"inventory", "init"}, raw: true, until: 9},
		{name: "inventory-init-exists", fixture: labFixture(0), args: []string{"inventory", "init"}, complete: 2, empty: 2, until: 9},
		{name: "snapshot-list", fixture: labFixture(1), args: []string{"snapshot", "list", "fw01"}, empty: 3, until: 0},
		{name: "snapshot-show", fixture: labFixture(1), args: []string{"snapshot", "show"}, empty: 3, until: 0},
		{name: "snapshot-diff", fixture: labFixture(2), args: []string{"snapshot", "diff"}, empty: 3, until: 0},
		{name: "search", fixture: labFixture(1), args: []string{"search", "198.18.10.100"}, empty: 3},
		{name: "lookup", fixture: labFixture(1), args: []string{"lookup", "dc01"}, empty: 3},
		{name: "lookup-missing", fixture: labFixture(1), args: []string{"lookup", "no-such-name"}, empty: 3, until: 0},
		{name: "simulate-policy", fixture: labFixture(1), args: []string{"simulate", "policy", "198.18.1.10", "198.18.10.100", "--device", "fw01", "--vsys", "vsys1"}, empty: 3, until: 5},
		{name: "simulate-nat", fixture: natFixture, args: []string{"simulate", "nat", "198.18.1.10", "198.18.250.10", "--device", "fw01", "--router", "default", "--from-zone", "transport", "--port", "8443"}, empty: 3, until: 5},
		{name: "simulate-routing", fixture: routingFixture, args: []string{"simulate", "routing", "198.18.10.5", "8.8.8.8"}, empty: 3, until: 5},
	}
}

// usageRows exit 2 in every format, before or without a run log (spec §4.4, §4.6).
var usageRows = [][]string{
	{"bogus"},
	{"snapshot", "bogus"},
	{"help", "bogus"},
	{"search", "--bogus"},
	{"bogus", "--output", "json"},
	{"search"},
}

func TestContract(t *testing.T) {
	t.Parallel()
	formats := []string{"text", "json"}
	if planStep >= 7 {
		formats = append(formats, "yaml")
	}
	for _, row := range contractRows() {
		for _, complete := range []bool{true, false} {
			fixtureName := map[bool]string{true: "complete", false: "empty"}[complete]
			want := row.empty
			if complete {
				want = row.complete
			}
			outputs := map[string]string{}
			for _, f := range formats {
				t.Run(row.name+"/"+fixtureName+"/"+f, func(t *testing.T) {
					if row.until > planStep {
						t.Skipf("waits for plan step %d", row.until)
					}
					c := row.fixture(t, complete)
					args := append(append([]string{}, row.args...), "--output", f)
					var out, errOut string
					var code int
					if row.raw { // a fresh --config per run, not the harness's
						out, errOut, code = c.runRaw(append(args, "--config", filepath.Join(t.TempDir(), "new.yaml"))...)
					} else {
						out, errOut, code = c.run(args...)
					}
					if code != want {
						t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, want, out, errOut)
					}
					checkStreams(t, f, code, out, errOut)
					checkLog(t, c.logFile(), code, row.answers)
					outputs[f] = out
				})
			}
			if planStep >= 7 {
				t.Run(row.name+"/"+fixtureName+"/yaml-equals-json", func(t *testing.T) {
					if row.until > planStep {
						t.Skipf("waits for plan step %d", row.until)
					}
					sameAnswer(t, outputs["json"], outputs["yaml"])
				})
			}
		}
	}
	for _, args := range usageRows {
		for _, f := range formats {
			t.Run("usage/"+strings.Join(args, "_")+"/"+f, func(t *testing.T) {
				if planStep < 6 {
					t.Skip("waits for plan step 6")
				}
				c := newCLI(t)
				out, errOut, code := c.run(append(append([]string{}, args...), "--output", f)...)
				if code != exitUsage {
					t.Fatalf("exit %d, want 2\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
				}
				if out != "" && !strings.HasPrefix(args[0], "help") {
					t.Errorf("stdout must be empty on a usage error:\n%s", out)
				}
				checkStreams(t, f, code, "", errOut)
			})
		}
	}
}

// checkStreams is spec §3.5 and §4.4.
func checkStreams(t *testing.T, format string, code int, out, errOut string) {
	t.Helper()
	switch format {
	case "json":
		if out != "" {
			var env map[string]json.RawMessage
			if err := json.Unmarshal([]byte(out), &env); err != nil {
				t.Fatalf("stdout is not one JSON envelope: %v\n%s", err, out)
			}
			for _, k := range []string{"format", "command", "input", "results", "holes", "unresolved", "notes"} {
				if _, ok := env[k]; !ok {
					t.Errorf("envelope has no %q", k)
				}
			}
			if r := bytes.TrimSpace(env["results"]); len(r) == 0 || r[0] != '[' {
				t.Errorf("results must be an array, got %s", r)
			}
		}
	case "yaml":
		if out != "" {
			var v map[string]any
			if err := yaml.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("stdout is not YAML: %v\n%s", err, out)
			}
		}
	case "text":
		for _, bad := range []string{"\nproteus:", "\nlog: ", "\x1b["} {
			if strings.Contains("\n"+out, bad) {
				t.Errorf("text stdout holds %q:\n%s", bad, out)
			}
		}
	}
	if format != "text" && code != exitOK && planStep >= 6 {
		lines := strings.Split(strings.TrimRight(errOut, "\n"), "\n")
		var last struct {
			Format int `json:"format"`
			Exit   int `json:"exit"`
		}
		if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil || last.Format != 1 || last.Exit != code {
			t.Errorf("the last stderr line must be the JSON exit line (exit %d), got:\n%s", code, errOut)
		}
		if strings.Contains(errOut, "\x1b[") {
			t.Errorf("stderr must not be coloured in %s mode", format)
		}
	}
}

// checkLog is spec §5.1: one exit line; one answer line exactly when an answer exists.
func checkLog(t *testing.T, log string, code int, answers bool) {
	t.Helper()
	if log == "" {
		t.Fatal("no run log")
	}
	if n := strings.Count(log, "[RUN] exit "); n != 1 {
		t.Errorf("%d exit lines in the run log, want 1", n)
	}
	if planStep < 4 {
		return
	}
	want := 0
	if code == exitOK || code == exitIncomplete || answers {
		want = 1
	}
	if n := strings.Count(log, "[RUN] answer: "); n != want {
		t.Errorf("%d answer lines in the run log, want %d", n, want)
	}
}

// sameAnswer checks that the YAML output says what the JSON output says.
func sameAnswer(t *testing.T, jsonOut, yamlOut string) {
	t.Helper()
	var fromYAML any
	if err := yaml.Unmarshal([]byte(normalise(yamlOut)), &fromYAML); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(fromYAML)
	if err != nil {
		t.Fatal(err)
	}
	decode := func(s []byte) any {
		d := json.NewDecoder(bytes.NewReader(s))
		d.UseNumber()
		var v any
		if err := d.Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if a, b := decode([]byte(normalise(jsonOut))), decode(b); !reflect.DeepEqual(a, b) {
		t.Errorf("YAML and JSON differ:\njson: %v\nyaml: %v", a, b)
	}
}

// Every leaf command must have a contract row, so a new command cannot skip it.
func TestContractCoversEveryCommand(t *testing.T) {
	t.Parallel()
	covered := map[string]bool{}
	for _, row := range contractRows() {
		covered[row.args[0]] = true
		if len(row.args) > 1 {
			covered[row.args[0]+" "+row.args[1]] = true
		}
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			if sub.HasSubCommands() {
				walk(sub)
				continue
			}
			path := strings.TrimPrefix(sub.CommandPath(), "proteus ")
			if path == "help" || strings.HasPrefix(path, "completion") {
				continue
			}
			if !covered[path] {
				t.Errorf("%q has no row in contractRows; add one (spec §11.1)", path)
			}
		}
	}
	walk(newApp(nil, nil, func(string) string { return "" }, nil).root())
}
