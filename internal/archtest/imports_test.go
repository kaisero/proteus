package archtest

import (
	"errors"
	"go/build"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/okaiser/proteus"

// ioPackages are what the read-only core must never reach. The core reads a file
// the caller names; it opens no connection and runs no command.
var ioPackages = []string{"net", "net/http", "net/url", "os/exec"}

// core is the read-only core, plus the schema substrate config decodes. It is the
// only part of this module the core may import.
var core = []string{"internal/config", "internal/resolve", "internal/index", "internal/schema", "internal/digest"}

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

// rules is R12. TestImportDirection fails when a rule names a package that does
// not exist, so a moved or renamed package cannot switch its rule off.
var rules = []rule{
	{from: "internal/config", forbid: ioPackages, allowIn: core},
	{from: "internal/resolve", forbid: ioPackages, allowIn: core},
	{from: "internal/index", forbid: ioPackages, allowIn: core},
	{from: "internal/index", forbid: mod("internal/simulate")},
	{from: "internal/fetch", forbid: mod("internal/simulate", "internal/estate")},
	{from: "internal/store", forbid: mod("internal/fetch")},
	{from: "internal/search", forbid: mod("internal/fetch", "internal/store", "internal/estate")},
	{from: "internal/card", forbid: mod("internal/fetch", "internal/store", "internal/estate", "internal/simulate")},
	{from: "internal/drift", forbid: mod("internal/fetch", "internal/store", "internal/estate")},
	{from: "internal/simulate", forbid: mod("internal/estate", "internal/store", "internal/fetch", "internal/search", "internal/drift", "internal/simulate/securitypolicy", "internal/simulate/routing", "internal/simulate/nat", "internal/simulate/topology", "internal/simulate/rulebase")},
	{from: "internal/simulate/topology", forbid: append(mod("internal/estate", "internal/store", "internal/fetch", "internal/search", "internal/drift", "internal/simulate/routing", "internal/simulate/nat", "internal/simulate/securitypolicy"), ioPackages...)},
	{from: "internal/simulate/rulebase", forbid: append(mod("internal/estate", "internal/store", "internal/fetch", "internal/search", "internal/drift", "internal/simulate/routing", "internal/simulate/nat", "internal/simulate/securitypolicy"), ioPackages...)},
	{from: "internal/simulate/securitypolicy", forbid: mod("internal/estate", "internal/store", "internal/fetch")},
	{from: "internal/simulate/routing", forbid: append(mod("internal/estate", "internal/store", "internal/fetch", "internal/search", "internal/drift", "internal/simulate/securitypolicy"), ioPackages...)},
	{from: "internal/simulate/nat", forbid: append(mod("internal/estate", "internal/store", "internal/fetch", "internal/search", "internal/drift", "internal/simulate/routing", "internal/simulate/securitypolicy"), ioPackages...)},
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
	slices.Sort(out)
	return out
}

// The checker must be able to fail, or a green run proves nothing.
func TestViolationsCatchesABreach(t *testing.T) {
	t.Parallel()
	graph := map[string][]string{
		module + "/internal/config":   {"fmt", module + "/internal/helper"},
		module + "/internal/helper":   {"net/http"},
		module + "/internal/index":    {module + "/internal/simulate"},
		module + "/internal/simulate": {"fmt"},
	}
	got := violations(graph, rules)
	// config reaches helper, which is outside the core, and through it net/http.
	// index reaches simulate, which both the core rule and the direction rule
	// forbid, so it is reported twice. resolve, fetch and store are absent, so
	// their rules pass.
	want := []string{
		"internal/config reaches " + module + "/internal/helper, outside the read-only core",
		"internal/config reaches net/http",
		"internal/index reaches " + module + "/internal/simulate, outside the read-only core",
		"internal/index reaches " + module + "/internal/simulate",
	}
	slices.Sort(got)
	slices.Sort(want)
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
		if _, ok := errors.AsType[*build.NoGoError](err); ok {
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
	t.Parallel()
	graph := loadGraph(t, "../..")
	for _, r := range rules {
		if _, ok := graph[module+"/"+r.from]; !ok {
			t.Fatalf("the walk did not find %s, so its rule would pass vacuously", r.from)
		}
	}
	for _, v := range violations(graph, rules) {
		t.Error(v)
	}
}
