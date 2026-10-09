package reason

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// codeLiteral is a string that reads as a code: a class, a dot and a name.
var codeLiteral = regexp.MustCompile(`^(call|default|dns|doubt|gap|input|note|path|verdict|zone)\.[a-z0-9.-]+$`)

// Every string in the production code that reads as a code is registered. New
// catches an unregistered code only when a test reaches it; this test reads every
// source file, so a code on a path no test takes fails too.
func TestEveryCodeInTheSourceIsRegistered(t *testing.T) {
	t.Parallel()
	seen := 0
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || !codeLiteral.MatchString(s) {
				return true
			}
			seen++
			if !Known(Code(s)) {
				t.Errorf("%s: %q is not in the registry", path, s)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen == 0 {
		t.Error("no code found in the source; the walk is broken")
	}
}
