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

func TestParseTargetRejectsLiteral(t *testing.T) {
	if _, err := ParseTarget("string('vlan')"); err == nil {
		t.Error("a string literal is not a reference target; want an error")
	}
}

func TestReferencesFromRuleFields(t *testing.T) {
	root := load(t)
	byField := map[string][]string{}
	for _, fr := range References(securityRule(root)) {
		byField[fr.Field] = fr.Candidates
	}
	for _, field := range []string{"source", "destination"} {
		if got, want := strings.Join(byField[field], " "), "region address address-group external-list ip-block-list-v2"; got != want {
			t.Errorf("%s: got [%s], want [%s]", field, got, want)
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
	got := References(root.Child("thing").EntrySequence())
	if len(got) != 1 {
		t.Fatalf("got %d fields, want 1", len(got))
	}
	want := []string{"address", "address-group"}
	if len(got[0].Candidates) != 2 {
		t.Fatalf("got %v, want %v", got[0].Candidates, want)
	}
	for i := range want {
		if got[0].Candidates[i] != want[i] {
			t.Errorf("candidate %d: got %q, want %q", i, got[0].Candidates[i], want[i])
		}
	}
}

func TestClassifyTargetForms(t *testing.T) {
	for raw, want := range map[string]TargetForm{
		"#config/shared/address/entry/@name":                       FormObject,
		"##/predefined/region/entry/@name":                         FormPredefined,
		"#myentry(template)/variable/entry[type/ip-netmask]/@name": FormTemplateVar,
		"##/shared/pre-rulebase/*/rules/entry/from/member":         FormRuleField,
		"string('vlan')": FormExpression,
		"substring(string('loopback'),   1,  8*(not('$loip'='')) )": FormExpression,
		"": FormUnknown,
	} {
		if got := ClassifyTarget(raw); got != want {
			t.Errorf("ClassifyTarget(%q) = %v, want %v", raw, got, want)
		}
	}
}

// 36 of the targets in the 11.2 firewall schema begin substring(, which a
// leading-string( check misses. Each one accepted becomes a false index edge.
func TestParseTargetRejectsEveryExpression(t *testing.T) {
	for _, raw := range []string{
		"string('vlan')",
		"substring(string('tunnel'), 1, 6*(not('$tunip'='')))",
		"substring(string('vlan'), 1, 4*(not('$vlanip'='')))",
	} {
		if _, err := ParseTarget(raw); err == nil {
			t.Errorf("ParseTarget(%q) must fail: it is an expression, not a reference", raw)
		}
	}
}

func TestParseTargetRejectsRuleFieldReference(t *testing.T) {
	// This names another rule's field, not an object, so it is not an edge.
	if _, err := ParseTarget("##/shared/pre-rulebase/*/rules/entry/from/member"); err == nil {
		t.Error("a wildcard rule-field target must not parse as an object reference")
	}
}

// A field usually has several candidate kinds, so References groups by field.
func TestReferencesGroupCandidatesByField(t *testing.T) {
	root := load(t)
	got := References(securityRule(root))

	byField := map[string][]string{}
	for _, fr := range got {
		byField[fr.Field] = fr.Candidates
	}
	for _, field := range []string{"source", "destination"} {
		want := []string{"region", "address", "address-group", "external-list", "ip-block-list-v2"}
		gotKinds := byField[field]
		if len(gotKinds) != len(want) {
			t.Fatalf("%s: got %v, want %v", field, gotKinds, want)
		}
		for i := range want {
			if gotKinds[i] != want[i] {
				t.Errorf("%s candidate %d: got %q, want %q", field, i, gotKinds[i], want[i])
			}
		}
	}
	if _, present := byField["application"]; present {
		t.Error("application declares no memberof in the fixture, so it must not appear")
	}
}
