package digest

import (
	"os"
	"testing"

	"github.com/okaiser/go-panos-schema/internal/schema"
)

// Pinned from the 11.2.0 Panorama schema. A change here means the schema or the
// classifier moved, and either deserves attention.
//
// Of 13,120 declarations, 8,234 are real object references: 5,698 configuration
// objects and 2,536 predefined. An earlier classifier reported only 6,733,
// because it treated a parenthesis anywhere as a computed expression and so
// misfiled 1,561 conditional references such as
// #config/shared/address/entry[not(ip-wildcard)]/@name.
var wantCensus = map[schema.TargetForm]int{
	schema.FormObject:      5698,
	schema.FormPredefined:  2536,
	schema.FormTemplateVar: 2708,
	schema.FormRuleField:   1136,
	schema.FormExpression:  915,
	schema.FormUnknown:     127,
}

const wantTotal = 13120

func TestRealSchemaFormCensus(t *testing.T) {
	f, err := os.Open("../../schemadigest/panos-11.2.0-panorama.json.gz")
	if err != nil {
		t.Skip("no committed digest to census")
	}
	defer func() { _ = f.Close() }()
	d, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}

	got := map[schema.TargetForm]int{}
	total := 0
	d.Root.Walk(func(n *schema.Node) {
		for _, raw := range n.MemberOf {
			got[schema.ClassifyTarget(raw)]++
			total++
		}
	})
	if total != wantTotal {
		t.Errorf("total memberof declarations = %d, want %d", total, wantTotal)
	}
	for form, want := range wantCensus {
		if got[form] != want {
			t.Errorf("%v = %d, want %d", form, got[form], want)
		}
	}
	sum := got[schema.FormObject] + got[schema.FormPredefined]
	t.Logf("real object references: %d of %d declarations", sum, total)
}

// Nothing unrecognised may be accepted as a reference.
func TestNoUnrecognisedTargetParses(t *testing.T) {
	f, err := os.Open("../../schemadigest/panos-11.2.0-panorama.json.gz")
	if err != nil {
		t.Skip("no committed digest")
	}
	defer func() { _ = f.Close() }()
	d, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}
	bad := 0
	d.Root.Walk(func(n *schema.Node) {
		for _, raw := range n.MemberOf {
			form := schema.ClassifyTarget(raw)
			_, err := schema.ParseTarget(raw)
			accepted := err == nil
			wantAccepted := form == schema.FormObject || form == schema.FormPredefined
			if accepted != wantAccepted {
				bad++
				if bad <= 3 {
					t.Errorf("%q is a %v but accepted=%v", raw, form, accepted)
				}
			}
		}
	})
	if bad > 0 {
		t.Errorf("%d declarations were accepted or rejected wrongly", bad)
	}
}
