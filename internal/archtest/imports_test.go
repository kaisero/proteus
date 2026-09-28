package archtest

import (
	"errors"
	"go/build"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/okaiser/panos-analyst"

// ioPackages are what the read-only core must never reach. The core reads a file
// the caller names; it opens no connection and runs no command.
var ioPackages = []string{"net", "net/http", "net/url", "os/exec"}

// core is the read-only core, plus the schema substrate config decodes. It is the
// only part of this module the core may import.
var core = []string{"config", "resolve", "index", "internal/schema", "internal/digest"}

// rule forbids one package from reaching a set of packages, directly or through
// any package of this module it imports.
type rule struct {
	from    string   // module-relative package path
	forbid  []string // full import paths it must not reach
	allowIn []string // when set, the only module-relative packages it may reach
}

func mod(rel ...string) []string {
	out := make([]string, len(rel))
	for i, r := range rel {
		out[i] = module + "/" + r
	}
	return out
}

// rules is R12. A rule for a package that does not exist yet passes, and binds
// the moment the package lands.
var rules = []rule{
	{from: "config", forbid: ioPackages, allowIn: core},
	{from: "resolve", forbid: ioPackages, allowIn: core},
	{from: "index", forbid: ioPackages, allowIn: core},
	{from: "index", forbid: mod("simulate")},
	{from: "fetch", forbid: mod("simulate", "estate")},
	{from: "store", forbid: mod("fetch")},
	{from: "search", forbid: mod("fetch", "store", "estate")},
	{from: "drift", forbid: mod("fetch", "store", "estate")},
}

// violations reports every rule a graph breaks. graph maps a package of this
// module to its direct, non-test imports.
func violations(graph map[string][]string, rules []rule) []string {
	var out []string
	for _, r := range rules {
		from := module + "/" + r.from
		if _, ok := graph[from]; !ok {
			continue
		}
		forbid := map[string]bool{}
		for _, f := range r.forbid {
			forbid[f] = true
		}
		allowed := map[string]bool{from: true}
		for _, a := range r.allowIn {
			allowed[module+"/"+a] = true
		}
		for _, reached := range reach(graph, from) {
			switch {
			case forbid[reached]:
				out = append(out, r.from+" reaches "+reached)
			case r.allowIn != nil && strings.HasPrefix(reached, module+"/") && !allowed[reached]:
				out = append(out, r.from+" reaches "+reached+", outside the read-only core")
			}
		}
	}
	return out
}

// reach returns every import path from reaches, following only packages of this
// module, sorted.
func reach(graph map[string][]string, from string) []string {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(p string) {
		for _, imp := range graph[p] {
			if seen[imp] {
				continue
			}
			seen[imp] = true
			if _, ours := graph[imp]; ours {
				walk(imp)
			}
		}
	}
	walk(from)
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// The checker must be able to fail, or a green run proves nothing.
func TestViolationsCatchesABreach(t *testing.T) {
	graph := map[string][]string{
		module + "/config":   {"fmt", module + "/helper"},
		module + "/helper":   {"net/http"},
		module + "/index":    {module + "/simulate"},
		module + "/simulate": {"fmt"},
	}
	got := violations(graph, rules)
	// config reaches helper, which is outside the core, and through it net/http.
	// index reaches simulate, which both the core rule and the direction rule
	// forbid, so it is reported twice. resolve, fetch and store are absent, so
	// their rules pass.
	want := []string{
		"config reaches " + module + "/helper, outside the read-only core",
		"config reaches net/http",
		"index reaches " + module + "/simulate, outside the read-only core",
		"index reaches " + module + "/simulate",
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("violations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// loadGraph reads the direct, non-test imports of every package in the module.
func loadGraph(t *testing.T, root string) map[string][]string {
	t.Helper()
	graph := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != root && (strings.HasPrefix(name, ".") || name == "testdata" ||
			name == "docs" || name == "bin" || name == "schemas") {
			return filepath.SkipDir
		}
		pkg, err := build.ImportDir(path, 0)
		var noGo *build.NoGoError
		if errors.As(err, &noGo) {
			return nil
		}
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		ip := module
		if rel != "." {
			ip += "/" + filepath.ToSlash(rel)
		}
		graph[ip] = pkg.Imports
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

// R12. The read-only core imports no I/O and nothing of this module outside
// itself, and the packages above it point one way.
func TestImportDirection(t *testing.T) {
	graph := loadGraph(t, "../..")
	for _, p := range []string{"config", "resolve", "index"} {
		if _, ok := graph[module+"/"+p]; !ok {
			t.Fatalf("the walk did not find %s, so every rule would pass vacuously", p)
		}
	}
	for _, v := range violations(graph, rules) {
		t.Error(v)
	}
}
