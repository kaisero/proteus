package schema

import (
	"strings"
	"testing"
)

func TestParseTargetConfigScope(t *testing.T) {
	got, err := ParseTarget("#config/shared/address/entry/@name")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got.Scope != "shared" || got.Kind != "address" || got.Predefined {
		t.Errorf("got %+v, want scope=shared kind=address predefined=false", got)
	}
}

func TestParseTargetPredefined(t *testing.T) {
	got, err := ParseTarget("##/predefined/region/entry/@name")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if !got.Predefined || got.Kind != "region" {
		t.Errorf("got %+v, want predefined=true kind=region", got)
	}
}

func TestParseTargetStripsPredicate(t *testing.T) {
	got, err := ParseTarget("#config/shared/address/entry[not(ip-wildcard)]/@name")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if got.Kind != "address" {
		t.Errorf("got kind=%q, want address", got.Kind)
	}
	if got.Predicate != "not(ip-wildcard)" {
		t.Errorf("got predicate=%q, want not(ip-wildcard)", got.Predicate)
	}
}

func TestParseTargetTemplateVariable(t *testing.T) {
	got, err := ParseTarget("#myentry(template)/variable/entry[type/ip-netmask]/@name")
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if !got.Template || got.Kind != "variable" {
		t.Errorf("got %+v, want template=true kind=variable", got)
	}
}

func TestParseTargetRejectsLiteral(t *testing.T) {
	if _, err := ParseTarget("string('vlan')"); err == nil {
		t.Error("a string literal is not a reference target; want an error")
	}
}

func TestReferencesFromRuleFields(t *testing.T) {
	root := load(t)
	rules := root.Child("shared").Child("pre-rulebase").Child("security").Child("rules")
	refs := References(rules.EntrySequence())

	byField := map[string][]string{}
	for _, r := range refs {
		byField[r.Field] = append(byField[r.Field], r.Kind)
	}
	for _, field := range []string{"source", "destination"} {
		kinds := byField[field]
		if len(kinds) != 2 {
			t.Fatalf("%s: got %v, want address and address-group", field, kinds)
		}
		if kinds[0] != "address" || kinds[1] != "address-group" {
			t.Errorf("%s: got %v, want [address address-group]", field, kinds)
		}
	}
	if len(byField["application"]) != 0 {
		t.Errorf("application declares no memberof in the fixture, got %v", byField["application"])
	}
}

// Almost every real target sits inside a <validate>. Both forms must work.
func TestReferencesInsideValidate(t *testing.T) {
	const doc = `<sequence name="config">
	  <array name="thing">
	    <sequence name="entry">
	      <attr-req name="name" type="string"/>
	      <array name="source">
	        <element name="member" type="string">
	          <validate memberof="#config/shared/address/entry/@name"/>
	          <validate>
	            <memberof memberof="#config/shared/address-group/entry/@name"/>
	          </validate>
	        </element>
	      </array>
	    </sequence>
	  </array>
	</sequence>`
	root, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	refs := References(root.Child("thing").EntrySequence())
	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2 (one validate attribute, one nested element)", len(refs))
	}
	kinds := []string{refs[0].Kind, refs[1].Kind}
	if kinds[0] != "address" || kinds[1] != "address-group" {
		t.Errorf("got %v, want [address address-group]", kinds)
	}
}
