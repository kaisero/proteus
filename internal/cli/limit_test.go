package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/fakepanos"
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

// A diff's limit keeps the first single changes: the scope where it falls
// shows its first changes and says so, the later scopes drop out, and text and
// JSON say how many are left out. The summary form counts every change.
func TestSnapshotDiffLimit(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	d := lab(t)
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	d.Config = read(t, fixture("firewall-lab-changed.xml"))
	c.want(0, "fetch", "fw01")
	out := c.want(0, "snapshot", "diff", "--limit", "1")
	for _, want := range []string{
		"  shared     no changes", "fw01/vsys:vsys1: 1 added, 1 removed, 2 changed (1 of 4 changes shown)\n",
		"\n1 with changes, 0 without, 0 holes; 1 of 4 shown, narrow by device\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diff --limit 1: no %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "vsys:vsys2") || strings.Count(out, "    changed ")+strings.Count(out, "    added ")+strings.Count(out, "    removed ") != 1 {
		t.Errorf("diff --limit 1 shows more than one change:\n%s", out)
	}
	var env struct {
		Input   struct{ Limit int }
		Results []struct {
			Scope   string
			Changes []any
		}
		Summary struct{ Found, Omitted int }
	}
	out = c.want(0, "snapshot", "diff", "--limit", "2", "--output", "json")
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Input.Limit != 2 || len(env.Results) != 2 ||
		len(env.Results[1].Changes) != 2 || env.Summary.Found != 4 || env.Summary.Omitted != 2 {
		t.Errorf("json: %v %+v", err, env)
	}
	var sum struct {
		Results []struct{ Added, Removed, Changed int }
	}
	out = c.want(0, "snapshot", "diff", "--limit", "2", "--output", "json", "--detail", "summary")
	if err := json.Unmarshal([]byte(out), &sum); err != nil || len(sum.Results) != 2 ||
		sum.Results[1].Added != 1 || sum.Results[1].Removed != 1 || sum.Results[1].Changed != 2 {
		t.Errorf("summary counts every change: %v %+v", err, sum)
	}
	// shared, vsys1, vsys2 and the identity data of both snapshots.
	out = c.want(0, "snapshot", "diff", "--output", "json")
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Input.Limit != 0 || env.Summary.Omitted != 0 || len(env.Results) != 4 {
		t.Errorf("no limit: %v %+v", err, env)
	}
}

// Text keeps the notes of targets whose results the limit cut: they print
// below, in the form note: <device>/<vsys>: <text>, as the MCP text does.
func TestLimitKeepsTheNotesInText(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), lab(t).Start(t)))
	c.want(0, "fetch", "fw01", "fw02")
	out := c.want(0, "search", "198.18.10.100", "--limit", "1", "--max-age", "1s")
	if !strings.Contains(out, "fw01 / vsys1") || strings.Contains(out, "fw02 / vsys1") ||
		!strings.Contains(out, "\nnote: fw02/vsys1: snapshot ") || !strings.Contains(out, "\nnote: fw01/vsys2: snapshot ") {
		t.Errorf("search --limit 1:\n%s", out)
	}
	out = c.want(0, "lookup", "dc01", "--limit", "1", "--max-age", "1s")
	if !strings.Contains(out, "\nnote: fw02/vsys1: snapshot ") {
		t.Errorf("lookup --limit 1:\n%s", out)
	}
}

// A diff device whose results the limit cut keeps its notes in text.
func TestDiffLimitKeepsTheNotesInText(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	d1, d2 := lab(t), lab(t)
	c.inventory(inventoryFor(d1.Start(t), d2.Start(t)))
	c.want(0, "fetch", "fw01", "fw02")
	d1.Config = read(t, fixture("firewall-lab-changed.xml"))
	d2.Config = read(t, fixture("firewall-lab-changed.xml"))
	// fw02's second snapshot comes from the other member of its pair.
	d2.Ops["<show><system><info/></system></show>"] = fakepanos.Success("<system><hostname>fw02-b</hostname><serial>000000000009</serial></system>")
	c.want(0, "fetch", "fw01", "fw02")
	out := c.want(0, "snapshot", "diff", "--limit", "1")
	if strings.Contains(out, "fw02   ") || !strings.Contains(out, "\nnote: fw02: the snapshots come from different firewalls") {
		t.Errorf("diff --limit 1:\n%s", out)
	}
}
