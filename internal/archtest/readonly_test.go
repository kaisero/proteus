package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// modelPackages hold the loaded configuration and what is built from it. R2: none
// of them exposes a way to change it.
var modelPackages = []string{"internal/config", "internal/resolve", "internal/index", "internal/schema"}

// mutators are the verbs of a function that changes what it is given. A name
// that starts with one, followed by a capital or nothing, reads as a setter:
// SetName and Add do, Addr and Settings do not.
var mutators = []string{
	"Set", "Add", "Append", "Insert", "Put", "Store", "Update", "Replace", "Edit", "Apply",
	"Delete", "Remove", "Clear", "Reset", "Mutate", "Write", "Save", "Commit", "Push",
}

// setterNames returns, for Go source files, each exported function or method
// whose name reads as a setter, as "file: name".
func setterNames(t *testing.T, files map[string]string) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	for _, name := range slices.Sorted(maps.Keys(files)) {
		f, err := parser.ParseFile(fset, name, files[name], parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || !isSetter(fn.Name.Name) {
				continue
			}
			out = append(out, filepath.Base(name)+": "+fn.Name.Name)
		}
	}
	return out
}

func isSetter(name string) bool {
	for _, verb := range mutators {
		rest, ok := strings.CutPrefix(name, verb)
		if !ok {
			continue
		}
		if r, _ := utf8.DecodeRuneInString(rest); rest == "" || unicode.IsUpper(r) {
			return true
		}
	}
	return false
}

// R2. The packages that hold a loaded configuration expose no setter: no
// exported function or method whose name says it changes something.
func TestPublicAPIIsReadOnly(t *testing.T) {
	t.Parallel()
	for _, pkg := range modelPackages {
		dir := filepath.Join("../..", pkg)
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(paths) == 0 {
			t.Fatalf("%s: no Go files, so the check would pass vacuously: %v", pkg, err)
		}
		files := map[string]string{}
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			files[p] = string(b)
		}
		for _, s := range setterNames(t, files) {
			t.Errorf("%s exposes a setter: %s", pkg, s)
		}
	}
}

// The check must be able to fail, or a green run proves nothing.
func TestSetterNamesCatchesASetter(t *testing.T) {
	t.Parallel()
	src := `package p
type T struct{ name string }
func (t *T) SetName(n string) { t.name = n }
func (t *T) Settings() string { return t.name }
func (t *T) Addr() string    { return t.name }
func (t *T) Add()            {}
func (t *T) reset()          {}
func Write(b []byte)         {}
func Name() string           { return "" }
`
	got := setterNames(t, map[string]string{"p.go": src})
	want := []string{"p.go: SetName", "p.go: Add", "p.go: Write"}
	if !slices.Equal(got, want) {
		t.Errorf("setters = %q, want %q", got, want)
	}
}
