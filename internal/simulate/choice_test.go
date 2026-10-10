package simulate

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Every ChoiceError whose question names a command line flag has a ToolText
// that names none: an MCP client has no flags (spec 2026-10-09 §4.5). The
// check reads the source of the simulations.
func TestChoiceErrorsHaveToolText(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	// src is an expression's source text.
	src := func(e ast.Expr) string {
		var b strings.Builder
		if err := printer.Fprint(&b, fset, e); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	found := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !strings.HasSuffix(name(lit.Type), "ChoiceError") {
				return true
			}
			fields := map[string]string{}
			for _, e := range lit.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					fields[name(kv.Key)] = src(kv.Value)
				}
			}
			found++
			if strings.Contains(fields["Question"], "--") && (fields["ToolText"] == "" || strings.Contains(fields["ToolText"], "--")) {
				t.Errorf("%s: a question that names a flag needs a ToolText without one: %s", fset.Position(lit.Pos()), fields["Question"])
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 5 {
		t.Errorf("only %d ChoiceError literals found", found)
	}
}

// name is an identifier or selector as written: "ChoiceError" or
// "simulate.ChoiceError".
func name(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return name(e.X) + "." + e.Sel.Name
	}
	return ""
}
