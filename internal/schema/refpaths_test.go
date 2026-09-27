package schema

import (
	"strings"
	"testing"
)

// The shape a security rule has: a named union holding the two ways a rule names
// its security profiles, a member list, a scalar leaf, and a nested entry array
// whose leaves belong to itself.
const refPathDoc = `<sequence name="config">
  <array name="rules">
    <sequence name="entry">
      <attr-req name="name" type="string"/>
      <array name="source">
        <element name="member" type="string">
          <validate memberof="#config/shared/address/entry/@name"/>
        </element>
      </array>
      <element name="log-setting" type="string">
        <validate memberof="#config/shared/log-settings/profiles/entry/@name"/>
      </element>
      <element name="type" type="string">
        <validate memberof="string('URL List')"/>
      </element>
      <union name="profile-setting">
        <sequence name="group">
          <array name="member-list">
            <element name="member" type="string">
              <validate memberof="#config/shared/profile-group/entry/@name"/>
            </element>
          </array>
        </sequence>
        <sequence name="profiles">
          <array name="virus">
            <element name="member" type="string">
              <validate memberof="#config/shared/profiles/virus/entry/@name"/>
            </element>
          </array>
        </sequence>
      </union>
      <choice>
        <element name="anon-branch" type="string">
          <validate memberof="#config/shared/tag/entry/@name"/>
        </element>
      </choice>
      <array name="nested">
        <sequence name="entry">
          <attr-req name="name" type="string"/>
          <element name="owned" type="string">
            <validate memberof="#config/shared/schedule/entry/@name"/>
          </element>
        </sequence>
      </array>
    </sequence>
  </array>
</sequence>`

func refPathsOf(t *testing.T, doc, array string) map[string][]string {
	t.Helper()
	root, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out := map[string][]string{}
	for _, pr := range ReferencePaths(root.Child(array).EntrySequence()) {
		out[strings.Join(pr.Path, "/")] = pr.Candidates
	}
	return out
}

func TestReferencePathsKeepsTheWholePath(t *testing.T) {
	got := refPathsOf(t, refPathDoc, "rules")

	for path, want := range map[string]string{
		"source/member": "address",
		"log-setting":   "profiles", // a scalar leaf, not a member list
		"profile-setting/group/member-list/member": "profile-group",
		"profile-setting/profiles/virus/member":    "virus",
		"anon-branch":                              "tag", // an anonymous choice adds no segment
	} {
		kinds, ok := got[path]
		if !ok {
			t.Errorf("missing reference path %q; got %v", path, keysOf(got))
			continue
		}
		if len(kinds) != 1 || kinds[0] != want {
			t.Errorf("%s: candidates = %v, want [%s]", path, kinds, want)
		}
	}
}

// profile-setting is a named union and a real element in the configuration. Fields
// flattens it away, which is right for the grammar and wrong for the file: the
// remaining path then matches nothing.
func TestReferencePathsKeepsANamedUnionButNotAnAnonymousOne(t *testing.T) {
	got := refPathsOf(t, refPathDoc, "rules")
	for path := range got {
		if strings.HasPrefix(path, "group/") || strings.HasPrefix(path, "profiles/") {
			t.Errorf("%q dropped the named union that holds it", path)
		}
	}
	if _, ok := got["anon-branch"]; !ok {
		t.Error("an anonymous choice must stay transparent")
	}
}

// A leaf inside a nested entry array belongs to that array, not to this one.
func TestReferencePathsStopsAtANestedEntryArray(t *testing.T) {
	got := refPathsOf(t, refPathDoc, "rules")
	for path := range got {
		if strings.HasPrefix(path, "nested/") {
			t.Errorf("%q belongs to the nested entry array, not to the rule", path)
		}
	}
}

// A memberof is not always a reference: a literal constraint names no object.
func TestReferencePathsSkipsLiteralConstraints(t *testing.T) {
	if kinds, ok := refPathsOf(t, refPathDoc, "rules")["type"]; ok {
		t.Errorf("string('URL List') is not an object reference, got %v", kinds)
	}
}

func TestPathFieldsFlattensOnlyAnonymousChoices(t *testing.T) {
	root, err := Parse(strings.NewReader(refPathDoc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var names []string
	for _, f := range PathFields(root.Child("rules").EntrySequence()) {
		if f.Name != "" {
			names = append(names, f.Name)
		}
	}
	wantPresent := []string{"profile-setting", "anon-branch", "source", "log-setting"}
	for _, w := range wantPresent {
		found := false
		for _, n := range names {
			if n == w {
				found = true
			}
		}
		if !found {
			t.Errorf("PathFields dropped %q; got %v", w, names)
		}
	}
	for _, n := range names {
		if n == "group" || n == "profiles" {
			t.Errorf("PathFields flattened the named union, exposing %q", n)
		}
	}
}

func keysOf(m map[string][]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
