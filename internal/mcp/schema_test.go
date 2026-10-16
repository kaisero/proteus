package mcp

import (
	"bytes"
	"encoding"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/resolve"
)

// update rewrites the checked-in schemas: go test ./internal/mcp -update.
var update = flag.Bool("update", false, "rewrite schemas/out")

// outDir holds the generated schemas. A change shows as a reviewed diff.
const outDir = "../../schemas/out"

// queryInputs are the query layer's inputs. They carry descriptions too, and
// the walk checks them like the answers.
var queryInputs = []reflect.Type{
	reflect.TypeFor[query.PolicyInput](), reflect.TypeFor[query.PolicyFileInput](), reflect.TypeFor[query.RoutingInput](),
	reflect.TypeFor[query.NATInput](), reflect.TypeFor[query.SearchInput](), reflect.TypeFor[query.LookupInput](),
	reflect.TypeFor[query.DiffInput](),
}

// sharedPointers lists every schema reached twice in s's tree. A shared
// pointer makes the SDK's AddTool panic (S2). The walk follows every field of
// type *Schema, []*Schema and map[string]*Schema, so a child kind added to
// jsonschema-go is walked too.
func sharedPointers(s *jsonschema.Schema) []string {
	seen := map[*jsonschema.Schema]bool{}
	var out []string
	var walk func(*jsonschema.Schema, string)
	walk = func(s *jsonschema.Schema, path string) {
		if s == nil {
			return
		}
		if seen[s] {
			out = append(out, path)
			return
		}
		seen[s] = true
		v := reflect.ValueOf(s).Elem()
		for i := range v.NumField() {
			f, name := v.Field(i), v.Type().Field(i).Name
			switch f.Type() {
			case schemaPtr:
				walk(f.Interface().(*jsonschema.Schema), path+"/"+name)
			case schemaSlice:
				for j, c := range f.Interface().([]*jsonschema.Schema) {
					walk(c, fmt.Sprintf("%s/%s/%d", path, name, j))
				}
			case schemaMap:
				m := f.Interface().(map[string]*jsonschema.Schema)
				for _, k := range slices.Sorted(maps.Keys(m)) {
					walk(m[k], path+"/"+name+"/"+k)
				}
			}
		}
	}
	walk(s, "")
	return out
}

// sharedPointers finds a pointer shared through any child field.
func TestSharedPointersCatchesABreach(t *testing.T) {
	t.Parallel()
	for name, mk := range map[string]func(c *jsonschema.Schema) *jsonschema.Schema{
		"items": func(c *jsonschema.Schema) *jsonschema.Schema { return &jsonschema.Schema{Items: c, Not: c} },
		"anyOf": func(c *jsonschema.Schema) *jsonschema.Schema {
			return &jsonschema.Schema{AnyOf: []*jsonschema.Schema{c, c}}
		},
		"allOf": func(c *jsonschema.Schema) *jsonschema.Schema {
			return &jsonschema.Schema{AllOf: []*jsonschema.Schema{c}, Items: c}
		},
		"prefixItems": func(c *jsonschema.Schema) *jsonschema.Schema {
			return &jsonschema.Schema{PrefixItems: []*jsonschema.Schema{c, c}}
		},
		"patternProperties": func(c *jsonschema.Schema) *jsonschema.Schema {
			return &jsonschema.Schema{PatternProperties: map[string]*jsonschema.Schema{"a": c, "b": c}}
		},
		"defs": func(c *jsonschema.Schema) *jsonschema.Schema {
			return &jsonschema.Schema{Defs: map[string]*jsonschema.Schema{"a": c}, Items: c}
		},
		"nested": func(c *jsonschema.Schema) *jsonschema.Schema {
			return object(map[string]*jsonschema.Schema{"a": {Items: c}, "b": {AnyOf: []*jsonschema.Schema{c}}})
		},
	} {
		if got := sharedPointers(mk(str(""))); len(got) != 1 {
			t.Errorf("%s: shared = %v, want one", name, got)
		}
	}
	if got := sharedPointers(object(map[string]*jsonschema.Schema{"a": str(""), "b": str("")})); len(got) != 0 {
		t.Errorf("a tree: shared = %v", got)
	}
}

// A card nested deeper than the unrolled levels still validates: below them
// an item may be anything. So does a NAT fallback below its levels.
func TestDeepNestingValidates(t *testing.T) {
	t.Parallel()
	item := map[string]any{"name": "leaf", "kind": "address", "value": "192.0.2.1"}
	for i := range 10 {
		item = map[string]any{"name": fmt.Sprintf("group-%d", i), "kind": "address-group", "children": []any{item}}
	}
	gen := generated(t)
	b, err := os.ReadFile(filepath.Join(goldenDir, "lookup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	card := doc["results"].([]any)[0].(map[string]any)["card"].(map[string]any)
	row := card["sections"].([]any)[0].(map[string]any)["rows"].([]any)[1].(map[string]any)
	row["items"] = []any{item}
	validate(t, gen["lookup.full.json"], doc, "a card nested 10 levels")

	nat, err := unrolled(reflect.TypeFor[resolve.SourceTranslation](), 2, map[reflect.Type]*jsonschema.Schema{})
	if err != nil {
		t.Fatal(err)
	}
	fb := map[string]any{"Kind": "dynamic-ip-and-port"}
	for range 4 {
		fb = map[string]any{
			"Kind": "dynamic-ip", "Addresses": nil, "Interface": "", "InterfaceIP": "", "FloatingIP": "",
			"IPv6Interface": "", "BiDirectional": false, "Fallback": fb,
		}
	}
	validate(t, nat, fb, "a fallback nested 4 levels")
}

// generated is every schema file: <name>.<detail>.json per envelope and
// <tool>.output.json and <tool>.input.json per tool.
func generated(t *testing.T) map[string]*jsonschema.Schema {
	t.Helper()
	out := map[string]*jsonschema.Schema{}
	for _, sh := range shapes {
		for _, d := range []string{query.DetailSummary, query.DetailFull} {
			s, err := envelopeSchema(sh, d)
			if err != nil {
				t.Fatalf("%s %s: %v", sh.name, d, err)
			}
			out[sh.name+"."+d+".json"] = s
		}
		if sh.tool == "" {
			continue
		}
		s, err := outputSchema(sh)
		if err != nil {
			t.Fatalf("%s output: %v", sh.tool, err)
		}
		out[sh.tool+".output.json"] = s
		in, err := inputSchema(sh.args, nil)
		if err != nil {
			t.Fatalf("%s input: %v", sh.tool, err)
		}
		out[sh.tool+".input.json"] = in
	}
	return out
}

func marshal(t *testing.T, s *jsonschema.Schema) []byte {
	t.Helper()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// The checked-in schemas are the generated ones; -update rewrites them. Each
// resolves, and none shares a schema pointer.
func TestSchemas(t *testing.T) {
	t.Parallel()
	gen := generated(t)
	for name, s := range gen {
		if shared := sharedPointers(s); len(shared) > 0 {
			t.Errorf("%s shares schemas at %v", name, shared)
		}
		if _, err := s.Resolve(nil); err != nil {
			t.Errorf("%s does not resolve: %v", name, err)
		}
		path := filepath.Join(outDir, name)
		b := marshal(t, s)
		if *update {
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(b, want) {
			t.Errorf("%s differs from the generated schema (%v); run go test ./internal/mcp -update and review the diff", path, err)
		}
	}
	files, err := filepath.Glob(filepath.Join(outDir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if gen[filepath.Base(f)] == nil {
			t.Errorf("%s is not generated any more; remove it", f)
		}
	}
}

// The tool output schema's oneOf has exactly one branch for each answer,
// also for empty results: the detail constant tells them apart.
func TestOutputSchemaTellsTheDetailsApart(t *testing.T) {
	t.Parallel()
	s, err := outputSchema(shapes[0])
	if err != nil {
		t.Fatal(err)
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	empty := func(detail string) any {
		e := query.Envelope[query.PolicyInput, query.PathResult]{Format: query.FormatVersion, Command: "simulate policy", Detail: detail}
		return plain(t, query.DocOf(e))
	}
	for _, tc := range []struct {
		name string
		out  map[string]any
		ok   bool
	}{
		{"empty summary", map[string]any{"envelope": empty("summary"), "error": nil}, true},
		{"empty full", map[string]any{"envelope": empty("full"), "error": nil}, true},
		{"an error", map[string]any{"envelope": nil, "error": map[string]any{"code": "call.usage", "text": "give destination", "options": []any{}, "needs": []any{}}}, true},
		{"another detail", map[string]any{"envelope": empty("brief"), "error": nil}, false},
		{"no error key", map[string]any{"envelope": empty("full")}, false},
	} {
		if err := rs.Validate(tc.out); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

// goldenDir holds the command line's JSON goldens.
const goldenDir = "../cli/testdata/golden"

// notQuestions are the commands whose JSON no tool returns.
var notQuestions = []string{"fetch", "inventory init", "snapshot list", "snapshot show"}

// Every CLI JSON golden of a question validates against its envelope's schema
// and, wrapped as a tool's output, against the tool's output schema.
func TestGoldensValidate(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join(goldenDir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no goldens: %v", err)
	}
	gen := generated(t)
	checked := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		command, _ := doc["command"].(string)
		if slices.Contains(notQuestions, command) {
			continue
		}
		if _, exit := doc["exit"]; exit && command == "" {
			continue // a usage error's stderr line: no envelope, and no tool returns it
		}
		sh, ok := shapeOf(doc)
		if !ok {
			t.Errorf("%s: no schema for command %q", f, command)
			continue
		}
		detail, _ := doc["detail"].(string)
		validate(t, gen[sh.name+"."+detail+".json"], doc, f)
		if sh.tool != "" {
			validate(t, gen[sh.tool+".output.json"], map[string]any{"envelope": doc, "error": nil}, f+" as output")
		}
		checked++
	}
	if checked < 20 {
		t.Errorf("only %d goldens checked", checked)
	}
}

// shapeOf picks a JSON envelope's shape by its command; simulate policy has
// two, told apart by the input's mode.
func shapeOf(doc map[string]any) (shape, bool) {
	command, _ := doc["command"].(string)
	name := strings.ReplaceAll(command, " ", "-")
	if in, _ := doc["input"].(map[string]any); command == "simulate policy" && in["mode"] != "path" {
		name += "-file"
	}
	for _, sh := range shapes {
		if sh.name == name {
			return sh, true
		}
	}
	return shape{}, false
}

func validate(t *testing.T, s *jsonschema.Schema, v any, what string) {
	t.Helper()
	if s == nil {
		t.Errorf("%s: no schema", what)
		return
	}
	rs, err := s.Resolve(nil)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if err := rs.Validate(v); err != nil {
		t.Errorf("%s: %v", what, err)
	}
}

var (
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

// marshals reports whether a type writes its own JSON or text.
func marshals(t reflect.Type) bool {
	p := reflect.PointerTo(t)
	return t.Implements(jsonMarshaler) || p.Implements(jsonMarshaler) || t.Implements(textMarshaler) || p.Implements(textMarshaler)
}

// typeProblems walks a type as encoding/json writes it and lists what
// jsonschema-go would describe wrongly: a type that writes its own JSON
// without an override, two fields with one JSON name (encoding/json and
// jsonschema-go pick different ones), an embedded struct with a JSON name
// (encoding/json nests it, jsonschema-go flattens it) and an interface. used
// collects the overrides the walk met.
func typeProblems(t reflect.Type, overrides map[reflect.Type]*jsonschema.Schema, seen, used map[reflect.Type]bool) []string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if seen[t] {
		return nil
	}
	seen[t] = true
	if overrides[t] != nil {
		used[t] = true
	}
	if marshals(t) {
		if overrides[t] == nil {
			return []string{t.String() + " writes its own JSON and has no schema override"}
		}
		return nil
	}
	var out []string
	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		out = typeProblems(t.Elem(), overrides, seen, used)
	case reflect.Map:
		// encoding/json writes a nil map as null, which jsonschema-go's
		// object does not allow.
		if overrides[t] == nil {
			out = append(out, t.String()+" is a map, which JSON writes as null when nil, and has no schema override")
		}
	case reflect.Interface:
		out = append(out, t.String()+" is an interface, which has no schema")
	case reflect.Struct:
		names := map[string]string{}
		for _, f := range reflect.VisibleFields(t) {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if f.Anonymous {
				if name != "" && name != "-" {
					out = append(out, fmt.Sprintf("%s embeds %s with the JSON name %q", t, f.Name, name))
				}
				continue
			}
			if !f.IsExported() || name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			if other, ok := names[name]; ok {
				out = append(out, fmt.Sprintf("%s has two fields named %q in JSON: %s and %s", t, name, other, f.Name))
			}
			names[name] = f.Name
			out = append(out, typeProblems(f.Type, overrides, seen, used)...)
		}
	default:
	}
	return out
}

// Every answer, input block, tool argument and query input is a type
// jsonschema-go describes as encoding/json writes it, and every override is
// in use.
func TestTypesHaveSchemas(t *testing.T) {
	t.Parallel()
	overrides, err := typeSchemas()
	if err != nil {
		t.Fatal(err)
	}
	seen, used := map[reflect.Type]bool{}, map[reflect.Type]bool{}
	roots := slices.Clone(queryInputs)
	for _, sh := range shapes {
		roots = append(roots, sh.full, sh.summary)
		if sh.args != nil {
			roots = append(roots, sh.args)
		}
	}
	for _, r := range roots {
		for _, p := range typeProblems(r, overrides, seen, used) {
			t.Error(p)
		}
	}
	// The overrides' own fields are not walked: Checks holds Security, which
	// the answers reach anyway.
	for ty := range overrides {
		if !used[ty] {
			t.Errorf("the override for %s is not used; remove it", ty)
		}
	}
}

// Types that break the rules, for the checker's self-test.
type (
	ownJSON struct{}
	DupA    struct {
		X string `json:"x"`
	}
	DupB struct {
		Y string `json:"x"`
	}
	named struct {
		DupA `json:"a"`
	}
	withAny struct {
		V any `json:"v"`
	}
)

func (ownJSON) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// The checker must be able to fail, or a green run proves nothing.
func TestTypeProblemsCatchesABreach(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		t    reflect.Type
		want string
	}{
		{reflect.TypeFor[[]ownJSON](), "writes its own JSON"},
		// Built at run time: vet refuses the declaration.
		{reflect.StructOf([]reflect.StructField{
			{Name: "DupA", Type: reflect.TypeFor[DupA](), Anonymous: true},
			{Name: "DupB", Type: reflect.TypeFor[DupB](), Anonymous: true},
		}), `two fields named "x"`},
		{reflect.TypeFor[named](), `with the JSON name "a"`},
		{reflect.TypeFor[withAny](), "is an interface"},
		{reflect.TypeFor[map[string]int](), "is a map"},
	} {
		got := typeProblems(tc.t, nil, map[reflect.Type]bool{}, map[reflect.Type]bool{})
		if len(got) != 1 || !strings.Contains(got[0], tc.want) {
			t.Errorf("%s: %v, want %q", tc.t, got, tc.want)
		}
	}
}
