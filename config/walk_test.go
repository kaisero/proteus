package config

import (
	"strings"
	"testing"
)

func TestWalkYieldsScopedReferenceEvents(t *testing.T) {
	cfg, _, err := Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var events []Event
	if err := cfg.Walk(func(e Event) bool {
		events = append(events, e)
		return true
	}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("the walk yielded nothing")
	}
	t.Logf("events: %d", len(events))

	// The device-group post-rule must appear, with its device-group scope. A walk
	// that consumes an entry wholesale misses it: a device group holds a rulebase
	// which holds rules, and all three are entries.
	var rule *Event
	for i := range events {
		if events[i].Field == "source" && len(events[i].Values) > 0 &&
			events[i].Values[0] == "corp-location" {
			rule = &events[i]
		}
	}
	if rule == nil {
		t.Fatal("the nested device-group rule was not reached")
	}
	if got, want := rule.Scope.String(), "dg:host_1_directory"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
	if !strings.Contains(rule.EntryPath, "Corp DC Access") {
		t.Errorf("entry path should name the rule, got %q", rule.EntryPath)
	}
	if len(rule.Candidates) < 2 {
		t.Errorf("source must carry several candidate kinds, got %v", rule.Candidates)
	}
}

// Two device groups can hold an object of the same name, so an event's path must
// identify the instance, not the schema location.
func TestWalkEntryPathsAreInstancePaths(t *testing.T) {
	cfg, _, _ := Load("../testdata/config/panorama-lab.xml")
	seen := map[string]bool{}
	_ = cfg.Walk(func(e Event) bool {
		seen[e.EntryPath] = true
		return true
	})
	var vienna, graz bool
	for p := range seen {
		if strings.Contains(p, "host_1_directory") && strings.Contains(p, "corp-location-vienna") {
			vienna = true
		}
		if strings.Contains(p, "corp-graz") && strings.Contains(p, "corp-location-graz") {
			graz = true
		}
	}
	if !vienna || !graz {
		t.Errorf("both device groups' objects must be distinguishable; vienna=%v graz=%v",
			vienna, graz)
	}
}

// any is a keyword, not an object, and must never be yielded as a reference.
func TestWalkExcludesKeywords(t *testing.T) {
	cfg, _, _ := Load("../testdata/config/panorama-lab.xml")
	_ = cfg.Walk(func(e Event) bool {
		for _, v := range e.Values {
			if Keywords[v] {
				t.Errorf("keyword %q yielded as a reference from %s/%s", v, e.EntryPath, e.Field)
			}
		}
		return true
	})
}

// Returning false from the callback stops the walk.
func TestWalkStops(t *testing.T) {
	cfg, _, _ := Load("../testdata/config/panorama-lab.xml")
	n := 0
	_ = cfg.Walk(func(Event) bool {
		n++
		return false
	})
	if n != 1 {
		t.Errorf("callback ran %d times, want 1", n)
	}
}

// The walk reads the wrapped form too.
func TestWalkHandlesTheWrappedForm(t *testing.T) {
	bare, _, _ := Load("../testdata/config/panorama-lab.xml")
	wrapped, _, _ := Load("../testdata/config/panorama-lab-wrapped.xml")
	count := func(c *Config) int {
		n := 0
		_ = c.Walk(func(Event) bool { n++; return true })
		return n
	}
	if a, b := count(bare), count(wrapped); a != b {
		t.Errorf("bare yielded %d events, wrapped yielded %d", a, b)
	}
}

// A Panorama configuration holds several nested <config> elements: a template
// embeds a whole firewall configuration, and an admin role's webui permissions
// have one too. Stopping at the first of them ends the walk early. On the real
// lab configuration that bug yielded 1 event instead of 24.
//
// The fixture puts the template, with its nested config, before the device
// groups, so every device-group event here arrives only if the walk continued.
func TestWalkContinuesPastANestedConfigElement(t *testing.T) {
	cfg, _, err := Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	afterNestedConfig := 0
	_ = cfg.Walk(func(e Event) bool {
		if e.Scope.Sort == ScopeDeviceGroup {
			afterNestedConfig++
		}
		return true
	})
	if afterNestedConfig == 0 {
		t.Error("no device-group event arrived, so the walk stopped at the nested config")
	}
	t.Logf("device-group events after the nested config: %d", afterNestedConfig)
}

// A field's candidate kinds come from the schema, so they are known even when the
// configuration never uses the field.
//
// This matters because "any" is a keyword and yields no walk event: a rulebase
// whose every rule says "source any" would otherwise look as though source names
// nothing, and a lookup wired from the configuration would have no resolver for it.
func TestFieldKindsComeFromTheSchema(t *testing.T) {
	cfg, _, err := Load("../testdata/config/firewall-urlcat.xml")
	if err != nil {
		t.Fatal(err)
	}

	kinds := cfg.FieldKinds("rulebase/security/rules")

	want := map[string][]string{
		"source":      {"address", "address-group", "external-list", "ip-block-list-v2", "region"},
		"category":    {"bc-url-categories", "custom-url-category", "external-list", "pan-url-categories", "url-predefined"},
		"source-user": {"dynamic-user-group", "user", "user-group"},
	}
	for field, exp := range want {
		got := kinds[field]
		if len(got) != len(exp) {
			t.Errorf("%s kinds = %v, want %v", field, got, exp)
			continue
		}
		for i := range exp {
			if got[i] != exp[i] {
				t.Errorf("%s kinds = %v, want %v", field, got, exp)
				break
			}
		}
	}
}

// A suffix that matches no entry array yields nothing rather than everything.
func TestFieldKindsUnknownSuffix(t *testing.T) {
	cfg, _, err := Load("../testdata/config/firewall-urlcat.xml")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.FieldKinds("no/such/array"); len(got) != 0 {
		t.Errorf("FieldKinds = %v, want empty", got)
	}
}

// A Panorama schema holds the same rules array three times, as pre-rulebase,
// rulebase and post-rulebase, so merging them must not repeat a kind.
func TestFieldKindsMergesArraysWithoutRepeating(t *testing.T) {
	cfg, _, err := Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatal(err)
	}

	kinds := cfg.FieldKinds("rulebase/security/rules")
	for field, ks := range kinds {
		seen := map[string]bool{}
		for _, k := range ks {
			if seen[k] {
				t.Errorf("%s repeats kind %q: %v", field, k, ks)
			}
			seen[k] = true
		}
	}
	if len(kinds["from"]) != 1 || kinds["from"][0] != "zone" {
		t.Errorf("from kinds = %v, want [zone]", kinds["from"])
	}
}
