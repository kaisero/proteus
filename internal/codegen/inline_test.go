package codegen

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func allShapes(t *testing.T) (Shapes, []TypeName) {
	t.Helper()
	root := fixtureRoot(t)
	s := AllShapes(root)
	return s, Names(s)
}

func TestInlineShapesAreNamed(t *testing.T) {
	_, ns := allShapes(t)
	var dynamic *TypeName
	for i := range ns {
		if ns[i].Canonical == "Dynamic" {
			dynamic = &ns[i]
		}
	}
	if dynamic == nil {
		t.Fatal("the address-group dynamic sequence must get a type named Dynamic")
	}
	if dynamic.Kind != KindInline {
		t.Errorf("Dynamic has kind %v, want KindInline", dynamic.Kind)
	}
}

// An inline type has no Name field, because a sequence carries no name attribute.
func TestInlineTypeHasNoNameField(t *testing.T) {
	shapes, ns := allShapes(t)
	src := Emit(ModelPackage, fixtureRoot(t), ns, shapes)
	block := typeBlock(t, src, "Dynamic")
	if strings.Contains(block, "Name string `xml:\"name,attr\"`") {
		t.Error("an inline sequence has no name attribute, so no Name field")
	}
	if !strings.Contains(block, "Filter *string") {
		t.Errorf("Dynamic must carry Filter, got:\n%s", block)
	}
}

// One shape, one type, whichever owner reaches it.
func TestIdenticalInlineShapesShareAType(t *testing.T) {
	shapes, _ := allShapes(t)
	shared := 0
	for _, nodes := range shapes.Inline {
		if len(nodes) > 1 {
			shared++
		}
	}
	if shared == 0 {
		t.Fatal("no inline shape is shared; the fixture has repeated rulebase wrappers")
	}
}

func TestEmittedSourceStillParses(t *testing.T) {
	shapes, ns := allShapes(t)
	src := Emit(ModelPackage, fixtureRoot(t), ns, shapes)
	if _, err := parser.ParseFile(token.NewFileSet(), "model.go", src, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v", err)
	}
}

// typeBlock returns the source of one generated type declaration.
func typeBlock(t *testing.T, src, name string) string {
	t.Helper()
	marker := "\ntype " + name + " struct {"
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("no type %s in the generated source", name)
	}
	rest := src[i+1:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("type %s is not closed", name)
	}
	return rest[:end]
}
