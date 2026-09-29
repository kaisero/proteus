package codegen

import (
	"os"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/schema"
)

func fixtureRoot(t *testing.T) *schema.Node {
	t.Helper()
	f, err := os.Open("../../testdata/schema/cms-schema-trimmed.xml")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	root, err := schema.Parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return root
}

func names(t *testing.T) []TypeName {
	t.Helper()
	return Names(AllShapes(fixtureRoot(t)))
}

func byCanonical(ns []TypeName, want string) *TypeName {
	for i := range ns {
		if ns[i].Canonical == want {
			return &ns[i]
		}
	}
	return nil
}

func TestPascal(t *testing.T) {
	for in, want := range map[string]string{
		"address":             "Address",
		"address-group":       "AddressGroup",
		"custom-url-category": "CustomUrlCategory",
		"ip-netmask":          "IpNetmask",
		"vsys":                "Vsys",
	} {
		if got := Pascal(in); got != want {
			t.Errorf("Pascal(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalNameFromShallowestPath(t *testing.T) {
	ns := names(t)
	addr := byCanonical(ns, "AddressEntry")
	if addr == nil {
		t.Fatal("AddressEntry not generated")
	}
	if addr.Shallowest != "/config/shared/address" {
		t.Errorf("shallowest = %q, want /config/shared/address", addr.Shallowest)
	}
}

// One package, because area packages form Go import cycles.
func TestEverythingLandsInOnePackage(t *testing.T) {
	for _, n := range names(t) {
		if n.Package != ModelPackage {
			t.Fatalf("%s is in package %q, want %q", n.Canonical, n.Package, ModelPackage)
		}
	}
}

// headers and params share a shape. One canonical type, one alias.
func TestAliasForAnAlternateName(t *testing.T) {
	ns := names(t)
	var holder *TypeName
	for i := range ns {
		joined := strings.Join(ns[i].Paths, " ")
		if strings.Contains(joined, "/headers") && strings.Contains(joined, "/params") {
			holder = &ns[i]
		}
	}
	if holder == nil {
		t.Fatal("headers and params must share one shape")
	}
	if holder.Canonical != "HeadersEntry" {
		t.Errorf("canonical = %q, want HeadersEntry (the shallower path)", holder.Canonical)
	}
	if len(holder.Aliases) != 1 || holder.Aliases[0] != "ParamsEntry" {
		t.Errorf("aliases = %v, want [ParamsEntry]", holder.Aliases)
	}
}

func TestNamesAreUniqueAndBounded(t *testing.T) {
	seen := map[string]string{}
	for _, n := range names(t) {
		for _, nm := range append([]string{n.Canonical}, n.Aliases...) {
			if prev, dup := seen[nm]; dup {
				t.Errorf("%s emitted twice: %s and %s", nm, prev, n.Shallowest)
			}
			seen[nm] = n.Shallowest
			if len(nm) > maxNameLen {
				t.Errorf("%s is %d chars, limit is %d", nm, len(nm), maxNameLen)
			}
		}
	}
}

// Ranking by joined path string picks template-stack over template, because '-'
// sorts before '/'. Ties must be broken segment by segment.
func TestShallowestTieBreaksOnSegments(t *testing.T) {
	root := fixtureRoot(t)
	tpl := root.Child("devices").Child("entry").Child("template")
	stack := root.Child("devices").Child("entry").Child("template-stack")
	if tpl == nil || stack == nil {
		t.Fatal("template and template-stack must both be in the fixture")
	}
	if !shallower(tpl, stack) {
		t.Error("template must rank before template-stack")
	}
}

func TestNamesAreDeterministic(t *testing.T) {
	first, second := names(t), names(t)
	if len(first) != len(second) {
		t.Fatalf("got %d then %d types", len(first), len(second))
	}
	for i := range first {
		if first[i].Canonical != second[i].Canonical {
			t.Fatalf("run differed at %d: %q then %q", i, first[i].Canonical, second[i].Canonical)
		}
	}
}
