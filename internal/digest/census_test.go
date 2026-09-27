package digest

import (
	"os"
	"testing"

	"github.com/okaiser/panos-analyst/internal/schema"
)

// Pinned from the 11.2.0 firewall schema. A change here means the schema or the
// classifier moved, and either deserves attention.
//
// Of 5,898 declarations, 5,144 are real object references: 3,811 configuration
// objects and 1,333 predefined. A firewall schema has no template variables,
// because a firewall has no templates.
//
// Two earlier classifiers undercounted. The first treated a parenthesis anywhere as
// a computed expression, and so misfiled conditional references such as
// #config/shared/address/entry[not(ip-wildcard)]/@name. The second treated every
// "#myentry(" anchor as a template variable. Most of those are scope-relative object
// references — #myentry(vsys)/zone/entry/@name names a zone — and discarding them
// cost 1,455 objects in this schema, every zone target of a security rule's from and
// to fields among them.
var wantCensus = map[schema.TargetForm]int{
	schema.FormObject:      3811,
	schema.FormPredefined:  1333,
	schema.FormTemplateVar: 0,
	schema.FormRuleField:   276,
	schema.FormExpression:  429,
	schema.FormUnknown:     49,
}

const wantTotal = 5898

func TestRealSchemaFormCensus(t *testing.T) {
	f, err := os.Open("../../schemadigest/panos-11.2.0-firewall.json.gz")
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
	f, err := os.Open("../../schemadigest/panos-11.2.0-firewall.json.gz")
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

// Pinned field-level counts from the same schema. A reference field carries the
// candidate kinds it may name, and one kind is not enough: the schema alone cannot
// say which kind a target is.
//
// These moved once already. The scope-relative classifier fix added candidates to
// existing fields and made some fields references for the first time, and two code
// comments went stale unnoticed. Pinning them here means the next such change has to
// be acknowledged.
const (
	wantRefFields = 1559
	wantMultiKind = 673
	wantWorstKind = 153
)

func TestReferenceFieldCensus(t *testing.T) {
	f, err := os.Open("../../schemadigest/panos-11.2.0-firewall.json.gz")
	if err != nil {
		t.Skip("no committed digest to census")
	}
	defer func() { _ = f.Close() }()
	d, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}

	total, multi, worst := 0, 0, 0
	for _, arr := range schema.EntryTypes(d.Root) {
		for _, fr := range schema.References(arr.EntrySequence()) {
			total++
			if len(fr.Candidates) > 1 {
				multi++
			}
			if len(fr.Candidates) > worst {
				worst = len(fr.Candidates)
			}
		}
	}
	if total != wantRefFields {
		t.Errorf("reference fields = %d, want %d", total, wantRefFields)
	}
	if multi != wantMultiKind {
		t.Errorf("fields declaring more than one kind = %d, want %d", multi, wantMultiKind)
	}
	if worst != wantWorstKind {
		t.Errorf("most kinds on one field = %d, want %d", worst, wantWorstKind)
	}
}
