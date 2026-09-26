package codegen

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/okaiser/go-panos-schema/internal/schema"
)

func emitted(t *testing.T) string {
	t.Helper()
	root := fixtureRoot(t)
	groups := schema.GroupByShape(schema.EntryTypes(root))
	return Emit(ModelPackage, Names(groups), groups)
}

func TestEmittedSourceParses(t *testing.T) {
	src := emitted(t)
	if _, err := parser.ParseFile(token.NewFileSet(), "model.go", src, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v", err)
	}
}

func TestGoLeafType(t *testing.T) {
	for in, want := range map[string]string{
		"string": "*string", "bool": "*string", "enum": "*string",
		"multiple": "*string", "rangedint": "*int", "float": "*float64",
		"ipspec": "*string", "unrecognised": "*string",
	} {
		if got := GoLeafType(in); got != want {
			t.Errorf("GoLeafType(%q) = %q, want %q", in, got, want)
		}
	}
}

// The distinction pango gets wrong, carried through to the generated field.
//
// The vsys field takes its shape's canonical type name, which is not
// necessarily VsysEntry: vsys/entry holds nothing but a name, and a shallower
// path with the same shape wins the canonical name. VsysEntry is then an alias.
// What must hold is that the field is an entry list and not a MemberList.
func TestEmitsEntryListNotMemberList(t *testing.T) {
	src := emitted(t)

	vsysField := fieldLine(t, src, "Vsys ")
	if strings.Contains(vsysField, "*MemberList") {
		t.Errorf("vsys generated a MemberList: %s", vsysField)
	}
	if !strings.Contains(vsysField, "EntryList") {
		t.Errorf("vsys must generate an entry list, got: %s", vsysField)
	}
	if !strings.Contains(src, "type VsysEntry = ") && !strings.Contains(src, "type VsysEntry struct") {
		t.Error("VsysEntry must exist, as a type or an alias")
	}

	if !strings.Contains(src, "ReferenceTemplates *MemberList `xml:\"reference-templates,omitempty\"`") {
		t.Error("reference-templates must generate a MemberList")
	}
}

// fieldLine returns the first generated line declaring the named field.
func fieldLine(t *testing.T, src, field string) string {
	t.Helper()
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, field) {
			return trimmed
		}
	}
	t.Fatalf("no generated field %q", strings.TrimSpace(field))
	return ""
}

func TestEmitsChoiceMembersAsSiblings(t *testing.T) {
	src := emitted(t)
	for _, want := range []string{
		"IpNetmask *string `xml:\"ip-netmask,omitempty\"`",
		"IpRange *string `xml:\"ip-range,omitempty\"`",
		"Fqdn *string `xml:\"fqdn,omitempty\"`",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("choice member missing: %s", want)
		}
	}
}

func TestEmitsAliases(t *testing.T) {
	src := emitted(t)
	if !strings.Contains(src, "type ParamsEntry = HeadersEntry") {
		t.Error("ParamsEntry must be an alias of HeadersEntry")
	}
	if !strings.Contains(src, "type ParamsEntryList = HeadersEntryList") {
		t.Error("an alias needs its list alias too")
	}
}

// Every struct that holds config data carries the escape hatch. The list
// wrappers, MemberList and RawNode hold no config fields of their own, so they
// do not.
func TestEveryStructCarriesTheEscapeHatch(t *testing.T) {
	src := emitted(t)
	var missing []string
	for _, block := range strings.Split(src, "\ntype ")[1:] {
		header, rest, ok := strings.Cut(block, "\n")
		if !ok || !strings.Contains(header, "struct {") {
			continue // an alias, not a struct
		}
		name, _, _ := strings.Cut(header, " ")
		switch {
		case name == "MemberList", name == "RawNode", strings.HasSuffix(name, "List"):
			continue
		}
		body, _, _ := strings.Cut(rest, "\n}")
		if !strings.Contains(body, ReservedUntyped+" []RawNode") {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%d structs lack the escape hatch: %v", len(missing), missing)
	}
}

// cms-schema.xml declares a field named unknown, so the hatch cannot be Unknown.
func TestReservedNameCannotCollide(t *testing.T) {
	if strings.ToLower(ReservedUntyped) == ReservedUntyped {
		t.Errorf("%s is all lowercase, so a schema field could produce it", ReservedUntyped)
	}
}

func TestEmitIsDeterministic(t *testing.T) {
	first := emitted(t)
	second := emitted(t)
	if first != second {
		t.Error("two runs produced different output; the drift gate needs determinism")
	}
}
