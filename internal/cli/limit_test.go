package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// --limit takes 1 or more on each question with many results; anything else
// is a usage error before the question runs.
func TestLimitIsAUsageErrorBelowOne(t *testing.T) {
	t.Parallel()
	file := fixture("firewall-lab.xml")
	for _, cmd := range [][]string{
		{"search", "dc01", "--file", file},
		{"lookup", "dc01", "--file", file},
		{"snapshot", "diff"},
	} {
		for _, v := range []string{"0", "-2", "x"} {
			out, errOut, code := newCLI(t).run(append(append([]string{}, cmd...), "--limit", v)...)
			if code != exitUsage || out != "" || !strings.Contains(errOut, "--limit") {
				t.Errorf("%v --limit %s: exit %d\n%s\n%s", cmd, v, code, out, errOut)
			}
		}
	}
}

// The three commands share one --limit with one help text.
func TestLimitHasOneHelpText(t *testing.T) {
	t.Parallel()
	root := newApp(nil, nil, func(string) string { return "" }, nil).root()
	help := map[string]bool{}
	for _, path := range [][]string{{"search"}, {"lookup"}, {"snapshot", "diff"}} {
		c, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		f := c.Flags().Lookup("limit")
		if f == nil {
			t.Fatalf("%v has no --limit", path)
		}
		help[f.Usage] = true
	}
	if len(help) != 1 {
		t.Errorf("help texts: %v", help)
	}
}

// A lookup's limit keeps the first card over the devices; the line says how
// many it shows and what narrows it.
func TestLookupLimit(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), lab(t).Start(t)))
	c.want(0, "fetch", "fw01", "fw02")
	out := c.want(0, "lookup", "dc01", "--limit", "1")
	if !strings.Contains(out, "fw01 / vsys1") || strings.Contains(out, "fw02 / vsys1") ||
		!strings.Contains(out, "2 with it, 2 without, 0 holes; 1 of 2 shown, narrow by device or vsys") {
		t.Errorf("lookup --limit 1:\n%s", out)
	}
}

// A diff's limit keeps the first scopes; text and JSON say how many are left
// out.
func TestSnapshotDiffLimit(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	d := lab(t)
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	d.Config = read(t, fixture("firewall-lab-changed.xml"))
	c.want(0, "fetch", "fw01")
	out := c.want(0, "snapshot", "diff", "--limit", "1")
	if !strings.Contains(out, "  shared     no changes") || strings.Contains(out, "vsys:vsys1") ||
		!strings.Contains(out, "\n1 with changes, 0 without, 0 holes; 1 of 3 shown, narrow by device\n") {
		t.Errorf("diff --limit 1:\n%s", out)
	}
	var env struct {
		Input   struct{ Limit int }
		Results []struct{ Scope string }
		Summary struct{ Found, Omitted int }
	}
	out = c.want(0, "snapshot", "diff", "--limit", "2", "--output", "json")
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Input.Limit != 2 || len(env.Results) != 2 ||
		env.Summary.Found != 3 || env.Summary.Omitted != 1 {
		t.Errorf("json: %v %+v", err, env)
	}
	out = c.want(0, "snapshot", "diff", "--output", "json")
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Input.Limit != 0 || env.Summary.Omitted != 0 || len(env.Results) != 3 {
		t.Errorf("no limit: %v %+v", err, env)
	}
}
