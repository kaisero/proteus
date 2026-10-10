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

// codeLiteral matches a string that reads as a code: a class of the registry, a
// dot and a name.
func codeLiteral() *regexp.Regexp {
	seen := map[Class]bool{}
	var classes []string
	for _, e := range Registry() {
		if !seen[e.Class] {
			seen[e.Class] = true
			classes = append(classes, regexp.QuoteMeta(string(e.Class)))
		}
	}
	return regexp.MustCompile(`^(` + strings.Join(classes, "|") + `)\.[a-z0-9.-]+$`)
}

// Every string in the production code that reads as a code is registered. New
// catches an unregistered code only when a test reaches it; this test reads every
// source file, so a code on a path no test takes fails too.
func TestEveryCodeInTheSourceIsRegistered(t *testing.T) {
	t.Parallel()
	code := codeLiteral()
	seen := 0
	// The registry itself names every code; a hit there proves nothing.
	registry, err := filepath.Abs("registry.go")
	if err != nil {
		t.Fatal(err)
	}
	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if abs, err := filepath.Abs(path); err != nil || abs == registry {
			return err
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
			if err != nil || !code.MatchString(s) {
				return true
			}
			seen++
			if !Known(Code(s)) {
				t.Errorf("%s: %q is not in the registry", path, s)
			}
			return true
		})
		return nil
	}
	for _, root := range []string{"..", "../../cmd"} {
		if err := filepath.WalkDir(root, walk); err != nil {
			t.Fatal(err)
		}
	}
	if seen == 0 {
		t.Error("no code found in the source; the walk is broken")
	}
}
