package digest

import (
	"os"
	"testing"

	"github.com/okaiser/go-panos-schema/internal/schema"
)

// Pinned from the 11.2.0 Panorama schema. A change here means the schema or the
// classifier moved, and either deserves attention.
//
// Of 13,120 declarations, 9,647 are real object references: 7,111 configuration
// objects and 2,536 predefined.
//
// Two earlier classifiers undercounted. The first reported 6,733, because it treated a
// parenthesis anywhere as a computed expression and so misfiled 1,561 conditional
// references such as #config/shared/address/entry[not(ip-wildcard)]/@name. The second
// reported 8,234, because it treated every "#myentry(" anchor as a template variable.
// Most of those are scope-relative object references — #myentry(vsys)/zone/entry/@name
// names a zone — and discarding them cost 1,413 objects here and every zone target of a
// security rule's from and to fields. A template variable is specifically a variable
// under a template or a template stack.
var wantCensus = map[schema.TargetForm]int{
	schema.FormObject:      7111,
	schema.FormPredefined:  2536,
	schema.FormTemplateVar: 1069,
	schema.FormRuleField:   1362,
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
