package index

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The package keeps no state between calls: every index belongs to its caller
// (spec §4.8). A package-level cache keyed by file path grew without bound in a
// long-running process and returned a stale index for a file rewritten in place.
// This fails if one comes back: a package-level map or sync value, or one of the
// removed names.
func TestNoPackageLevelCache(t *testing.T) {
	t.Parallel()
	removed := map[string]bool{
		"For": true, "ForRulebase": true, "cache": true, "cacheMu": true,
		"edgeCache": true, "edgeCacheMu": true, "edgesOf": true, "clearCache": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && removed[d.Name.Name] {
					t.Errorf("%s: func %s is back; the caller builds and owns its indexes", fset.Position(d.Pos()), d.Name.Name)
				}
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				for _, s := range d.Specs {
					vs := s.(*ast.ValueSpec)
					for _, n := range vs.Names {
						if removed[n.Name] {
							t.Errorf("%s: var %s is back", fset.Position(n.Pos()), n.Name)
						}
					}
					if why := stateful(vs); why != "" {
						t.Errorf("%s: package-level var %s is %s; keep state in a value the caller owns",
							fset.Position(vs.Pos()), vs.Names[0].Name, why)
					}
				}
			}
		}
	}
}

// stateful says why a package-level var could hold state between calls: a map,
// or a sync value guarding one. Empty when it is neither.
func stateful(vs *ast.ValueSpec) string {
	exprs := append([]ast.Expr{vs.Type}, vs.Values...)
	why := ""
	for _, x := range exprs {
		if x == nil {
			continue
		}
		ast.Inspect(x, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.MapType:
				why = "a map"
			case *ast.SelectorExpr:
				if id, ok := n.X.(*ast.Ident); ok && id.Name == "sync" {
					why = "a sync." + n.Sel.Name
				}
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "make" {
					why = "made by make"
				}
			}
			return why == ""
		})
	}
	return why
}

// The check must catch what it is for.
func TestStatefulCatchesACache(t *testing.T) {
	t.Parallel()
	for src, want := range map[string]string{
		"var c = map[string]int{}":          "a map",
		"var c map[string]*Index":           "a map",
		"var mu sync.Mutex":                 "a sync.Mutex",
		"var c = make(chan int)":            "made by make",
		"var c = [...]string{\"a\"}":        "",
		"var c = regexp.MustCompile(`^a$`)": "",
	} {
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x\n"+src, 0)
		if err != nil {
			t.Fatal(err)
		}
		vs := f.Decls[0].(*ast.GenDecl).Specs[0].(*ast.ValueSpec)
		if got := stateful(vs); got != want {
			t.Errorf("%s: stateful = %q, want %q", src, got, want)
		}
	}
}
