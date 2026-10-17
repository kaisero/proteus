package archtest

import (
	"errors"
	"go/build"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/okaiser/proteus"

// ioPackages are what the read-only core must never reach. The core reads a file
// the caller names; it opens no connection and runs no command.
var ioPackages = []string{"net", "net/http", "net/url", "os/exec"}

// reasonPkg names every kind of reason an answer carries. It imports only the
// standard library, so every rule allows it.
const reasonPkg = "internal/reason"

// appidPkg owns the App-ID content file. It imports only the standard library
// and reason, so the core may import it (spec 2026-10-16 §8).
const appidPkg = "internal/appid"

// core is the read-only core, plus the schema substrate config decodes, the
// App-ID content data and the reason codes. It is the only part of this module
// the core may import.
var core = []string{"internal/config", "internal/resolve", "internal/index", "internal/schema", "internal/digest", appidPkg, reasonPkg}

// rule forbids one package from reaching a set of packages, directly or through
// any package of this module it imports.
type rule struct {
	from    string   // module-relative package path
	forbid  []string // full import paths it must not reach
	allowIn []string // when set, the only module-relative packages it may reach
	direct  []string // when set, the only module-relative packages it may import directly
	stdlib  bool     // when set, it imports only the standard library and allowIn
}

// standard reports whether an import path is in the standard library: its first
// element has no dot, unlike a module path.
func standard(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
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
	{
		from:   "internal/simulate/pathpolicy",
		forbid: append(mod("internal/estate", "internal/store", "internal/fetch", "internal/search", "internal/drift", "internal/card"), ioPackages...),
		direct: []string{"internal/simulate", "internal/simulate/routing", "internal/simulate/securitypolicy", "internal/resolve", "internal/simulate/topology", "internal/config", "internal/index", reasonPkg},
	},
	{from: "internal/task", forbid: ioPackages, allowIn: []string{"internal/runlog", reasonPkg}},
	{from: reasonPkg, stdlib: true},
	{from: appidPkg, stdlib: true, allowIn: []string{reasonPkg}, forbid: ioPackages},
	{from: "internal/query", forbid: queryForbids, direct: queryImports},
}

// queryImports are the packages of this module the query layer may import: the
// questions' engines and their data, never a front end (spec 2026-10-09 §3.7).
var queryImports = []string{
	"internal/simulate", "internal/simulate/securitypolicy", "internal/simulate/routing",
	"internal/simulate/nat", "internal/simulate/pathpolicy", "internal/simulate/topology",
	"internal/simulate/rulebase", "internal/estate", "internal/store", "internal/inventory",
	"internal/search", "internal/drift", "internal/card", "internal/resolve", "internal/index",
	"internal/config", appidPkg, "internal/runlog", reasonPkg,
}

// queryForbids are the front ends and the fetcher: the query layer serves the
// command line and the MCP server alike, so it reaches neither, nor Cobra or a
// terminal.
var queryForbids = append(mod("internal/fetch", "internal/cli", "internal/mcp"),
	"github.com/spf13/cobra", "github.com/spf13/pflag", "golang.org/x/term")

// testOnly are helper packages for tests. They import testing, so no package's
// non-test code may reach them.
var testOnly = []string{"internal/fakepanos", "internal/simulate/pathlab", "internal/testconfig"}

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
		if r.direct != nil {
			direct := map[string]bool{}
			for _, d := range r.direct {
				direct[module+"/"+d] = true
			}
			for _, imp := range graph[from] {
				if strings.HasPrefix(imp, module+"/") && !direct[imp] {
					out = append(out, r.from+" imports "+imp+", outside its list")
				}
			}
		}
		if r.stdlib {
			for _, imp := range graph[from] {
				if !standard(imp) && !allowed[imp] {
					out = append(out, r.from+" imports "+imp+", outside the standard library")
				}
			}
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
		// pathpolicy may import simulate, but not nat directly.
		module + "/internal/simulate/pathpolicy": {module + "/internal/simulate", module + "/internal/simulate/nat"},
		module + "/internal/simulate/nat":        {"fmt"},
		// reason may import neither this module nor another module.
		module + "/" + reasonPkg: {"fmt", module + "/internal/simulate/nat", "github.com/RoaringBitmap/roaring/v2"},
		// query may import the estate, but no front end, fetch or Cobra.
		module + "/internal/query":  {module + "/internal/estate", module + "/internal/fetch", "github.com/spf13/cobra"},
		module + "/internal/estate": {"fmt"},
		module + "/internal/fetch":  {"net/http"},
	}
	got := violations(graph, rules)
	// config reaches helper, which is outside the core, and through it net/http.
	// index reaches simulate, which both the core rule and the direction rule
	// forbid, so it is reported twice. resolve and store are absent, so their
	// rules pass; fetch reaches net/http, which its rule allows.
	want := []string{
		"internal/config reaches " + module + "/internal/helper, outside the read-only core",
		"internal/config reaches net/http",
		"internal/index reaches " + module + "/internal/simulate, outside the read-only core",
		"internal/index reaches " + module + "/internal/simulate",
		"internal/simulate/pathpolicy imports " + module + "/internal/simulate/nat, outside its list",
		reasonPkg + " imports " + module + "/internal/simulate/nat, outside the standard library",
		reasonPkg + " imports github.com/RoaringBitmap/roaring/v2, outside the standard library",
		"internal/query imports " + module + "/internal/fetch, outside its list",
		"internal/query reaches " + module + "/internal/fetch",
		"internal/query reaches github.com/spf13/cobra",
	}
	slices.Sort(got)
	slices.Sort(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("violations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// appid imports the standard library and reason only: index and roaring
	// are violations, reason is not.
	graph = map[string][]string{
		module + "/internal/appid": {"fmt", module + "/internal/index", "github.com/RoaringBitmap/roaring/v2", module + "/" + reasonPkg},
		module + "/internal/index": {"fmt"},
		module + "/" + reasonPkg:   {"fmt"},
	}
	got = violations(graph, rules)
	want = []string{
		"internal/appid imports " + module + "/internal/index, outside the standard library",
		"internal/appid imports github.com/RoaringBitmap/roaring/v2, outside the standard library",
		"internal/appid reaches " + module + "/internal/index, outside the read-only core",
	}
	slices.Sort(got)
	slices.Sort(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("appid violations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// Every package may import reason: no rule forbids it, and every rule with an
// allow list names it.
func TestEveryRuleAllowsReason(t *testing.T) {
	t.Parallel()
	for _, r := range rules {
		if r.from == reasonPkg {
			continue
		}
		graph := map[string][]string{
			module + "/" + r.from:    {module + "/" + reasonPkg},
			module + "/" + reasonPkg: {"fmt"},
		}
		for _, v := range violations(graph, []rule{r}) {
			t.Errorf("%s may not import reason: %s", r.from, v)
		}
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
		pkg, err := allFiles.ImportDir(path, 0)
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

// A test helper imports testing, so only tests may import it, directly or not.
func TestTestHelpersStayInTests(t *testing.T) {
	t.Parallel()
	graph := loadGraph(t, "../..")
	for _, h := range testOnly {
		helper := module + "/" + h
		if _, ok := graph[helper]; !ok {
			t.Fatalf("the walk did not find %s, so its check would pass vacuously", h)
		}
		for p := range graph {
			if p != helper && slices.Contains(reach(graph, p), helper) {
				t.Errorf("%s reaches the test helper %s", p, h)
			}
		}
	}
}

// sdkModules are the MCP Go SDK, the schema module it brings, and x/sync, which
// it brings too and whose singleflight the server's cache uses. Only the MCP
// server imports them, in its code and in its tests (spec 2026-10-09 §12 S9).
var sdkModules = []string{"github.com/modelcontextprotocol/go-sdk", "github.com/google/jsonschema-go", "golang.org/x/sync"}

// mcpPkg is the one package that may import them.
const mcpPkg = module + "/internal/mcp"

// sdkImporters lists every package other than the MCP server that imports an
// SDK module. imports maps a package to its imports, tests' included.
func sdkImporters(imports map[string][]string) []string {
	var out []string
	for p, imps := range imports {
		if p == mcpPkg {
			continue
		}
		for _, imp := range imps {
			for _, m := range sdkModules {
				if imp == m || strings.HasPrefix(imp, m+"/") {
					out = append(out, p+" imports "+imp)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// allFiles reads every Go file of a package, those behind a build tag too
// (resolve's live test), so a tag cannot hide an import from R12. UseAllFiles
// also reads files behind //go:build ignore and files for another OS or
// architecture: their imports count as well.
var allFiles = func() build.Context {
	c := build.Default
	c.UseAllFiles = true
	return c
}()

// loadAllImports reads every package's imports, its tests' included.
func loadAllImports(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		name := d.Name()
		if path != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "docs" || name == "bin" || name == "schemas") {
			return filepath.SkipDir
		}
		pkg, err := allFiles.ImportDir(path, 0)
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
		out[ip] = slices.Concat(pkg.Imports, pkg.TestImports, pkg.XTestImports)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// R12: only internal/mcp imports the MCP SDK or jsonschema-go, tests included.
func TestOnlyMCPImportsTheSDK(t *testing.T) {
	t.Parallel()
	imports := loadAllImports(t, "../..")
	if !slices.ContainsFunc(imports[mcpPkg], func(imp string) bool { return strings.HasPrefix(imp, sdkModules[0]) }) {
		t.Fatalf("%s does not import the SDK, so the check would pass vacuously", mcpPkg)
	}
	for _, v := range sdkImporters(imports) {
		t.Error(v)
	}
}

// The SDK check must be able to fail.
func TestSDKImportersCatchesABreach(t *testing.T) {
	t.Parallel()
	got := sdkImporters(map[string][]string{
		mcpPkg:                   {"github.com/modelcontextprotocol/go-sdk/mcp", "github.com/google/jsonschema-go/jsonschema"},
		module + "/internal/cli": {"github.com/modelcontextprotocol/go-sdk/mcp"},
		module + "/internal/query": {
			"github.com/google/jsonschema-go/jsonschema", "github.com/google/jsonschema-go-other",
		},
	})
	want := []string{
		module + "/internal/cli imports github.com/modelcontextprotocol/go-sdk/mcp",
		module + "/internal/query imports github.com/google/jsonschema-go/jsonschema",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

// A file behind a build tag cannot hide an import: both loaders read it.
func TestLoadersReadTaggedFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for name, src := range map[string]string{
		"plain.go":     "package x\n",
		"tagged.go":    "//go:build live\n\npackage x\n\nimport _ \"example.com/hidden\"\n",
		"live_test.go": "//go:build live\n\npackage x_test\n\nimport _ \"example.com/hiddentest\"\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := loadGraph(t, root)[module]; !slices.Contains(got, "example.com/hidden") {
		t.Errorf("loadGraph = %v", got)
	}
	if got := loadAllImports(t, root)[module]; !slices.Contains(got, "example.com/hidden") || !slices.Contains(got, "example.com/hiddentest") {
		t.Errorf("loadAllImports = %v", got)
	}
}
