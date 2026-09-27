package config

import (
	"strings"
	"testing"
)

func TestWalkYieldsScopedReferenceEvents(t *testing.T) {
	cfg, _, err := Load("../testdata/config/firewall-multivsys.xml")
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

	// The vsys rule must appear, with its vsys scope. A walk that consumes an entry
	// wholesale misses it: a vsys holds a rulebase which holds rules, and the vsys
	// and the rule are both entries.
	var rule *Event
	for i := range events {
		if events[i].Field == "source" && len(events[i].Values) > 0 &&
			events[i].Values[0] == "corp-location" {
			rule = &events[i]
		}
	}
	if rule == nil {
		t.Fatal("the nested vsys rule was not reached")
	}
	if got, want := rule.Scope.String(), "vsys:vsys1"; got != want {
		t.Errorf("scope = %q, want %q", got, want)
	}
	if !strings.Contains(rule.EntryPath, "Corp DC Access") {
		t.Errorf("entry path should name the rule, got %q", rule.EntryPath)
	}
	if len(rule.Candidates) < 2 {
		t.Errorf("source must carry several candidate kinds, got %v", rule.Candidates)
	}
}

// Two vsys can hold an object of the same name, so an event's path must identify
// the instance, not the schema location.
func TestWalkEntryPathsAreInstancePaths(t *testing.T) {
	cfg, _, _ := Load("../testdata/config/firewall-multivsys.xml")
	seen := map[string]bool{}
	_ = cfg.Walk(func(e Event) bool {
		seen[e.EntryPath] = true
		return true
	})
	var vienna, graz bool
	for p := range seen {
		if strings.Contains(p, "vsys1") && strings.Contains(p, "corp-location-vienna") {
			vienna = true
		}
		if strings.Contains(p, "vsys2") && strings.Contains(p, "corp-location-graz") {
			graz = true
		}
	}
	if !vienna || !graz {
		t.Errorf("both vsys' objects must be distinguishable; vienna=%v graz=%v", vienna, graz)
	}
}

// any is a keyword, not an object, and must never be yielded as a reference.
func TestWalkExcludesKeywords(t *testing.T) {
	cfg, _, _ := Load("../testdata/config/firewall-literals.xml")
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
	cfg, _, _ := Load("../testdata/config/firewall-multivsys.xml")
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
	bare, _, _ := Load("../testdata/config/firewall-multivsys.xml")
	wrapped, _, _ := Load("../testdata/config/firewall-multivsys-wrapped.xml")
	count := func(c *Config) int {
		n := 0
		_ = c.Walk(func(Event) bool { n++; return true })
		return n
	}
	if a, b := count(bare), count(wrapped); a != b {
		t.Errorf("bare yielded %d events, wrapped yielded %d", a, b)
	}
}

// A configuration can hold nested <config> elements: a firewall's
// shared/log-settings has one, and so do an admin role's webui permissions.
// Stopping at the first of them ends the walk early. On a real Panorama
// configuration that bug yielded 1 event instead of 24.
//
// The fixture puts shared/log-settings/config before the vsys, so every vsys
// event here arrives only if the walk continued.
func TestWalkContinuesPastANestedConfigElement(t *testing.T) {
	cfg, _, err := Load("../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	afterNestedConfig := 0
	_ = cfg.Walk(func(e Event) bool {
		if e.Scope.Sort == ScopeVsys {
			afterNestedConfig++
		}
		return true
	})
	if afterNestedConfig == 0 {
		t.Error("no vsys event arrived, so the walk stopped at the nested config")
	}
	t.Logf("vsys events after the nested config: %d", afterNestedConfig)
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

// Kinds from several matching arrays are merged, so merging must not repeat a
// kind. A Panorama schema holds the rules array three times, as pre-rulebase,
// rulebase and post-rulebase; a firewall schema holds it once, under vsys.
func TestFieldKindsMergesArraysWithoutRepeating(t *testing.T) {
	cfg, _, err := Load("../testdata/config/firewall-multivsys.xml")
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

// Where a kind lives under a scope comes from the schema, not from a list in the
// code. Most kinds are direct children; a custom URL category and every security
// profile are one level down, under profiles/.
func TestKindContainerComesFromTheSchema(t *testing.T) {
	cfg, _, err := Load("../testdata/config/firewall-urlcat.xml")
	if err != nil {
		t.Fatal(err)
	}

	for kind, want := range map[string]string{
		"address":             "address",
		"service":             "service",
		"external-list":       "external-list",
		"custom-url-category": "profiles/custom-url-category",
		"url-filtering":       "profiles/url-filtering",
	} {
		if got := strings.Join(cfg.KindContainer(kind), "/"); got != want {
			t.Errorf("KindContainer(%q) = %q, want %q", kind, got, want)
		}
	}
	if got := cfg.KindContainer("no-such-kind"); got != nil {
		t.Errorf("KindContainer of an unknown kind = %v, want nil", got)
	}
	if got := cfg.KindContainer(""); got != nil {
		t.Errorf("KindContainer of an empty kind = %v, want nil", got)
	}
}

// A kind name can appear at more than one place under a scope, and "user" does: the
// schema has a local user database and a separate user array under a vsys, and they are
// different things. KindContainer returns the shallowest, which for this kind is the
// wrong one, so a caller that might hit an ambiguous kind has to look at all of them.
func TestKindContainersReportsAmbiguity(t *testing.T) {
	cfg, _, err := Load("../testdata/config/firewall-users.xml")
	if err != nil {
		t.Fatal(err)
	}

	all := cfg.KindContainers("user")
	if len(all) < 2 {
		t.Fatalf("user should be ambiguous, got %v", all)
	}
	var found bool
	for _, p := range all {
		if strings.Join(p, "/") == "local-user-database/user" {
			found = true
		}
	}
	if !found {
		t.Errorf("the local user database is not among the candidates: %v", all)
	}
	// Shallowest first, so the ordering is stable for callers that accept the guess.
	for i := 1; i < len(all); i++ {
		if len(all[i-1]) > len(all[i]) {
			t.Errorf("candidates are not ordered shallowest first: %v", all)
		}
	}
	// Ambiguity is not rare. Two containers can sit at the same depth, and then the
	// order is alphabetical so it stays stable: an anti-spyware profile lives under
	// profiles/ while a custom spyware signature lives under threats/.
	spyware := cfg.KindContainers("spyware")
	if len(spyware) != 2 {
		t.Fatalf("spyware candidates = %v, want two", spyware)
	}
	if strings.Join(spyware[0], "/") != "profiles/spyware" ||
		strings.Join(spyware[1], "/") != "threats/spyware" {
		t.Errorf("same-depth candidates are not in alphabetical order: %v", spyware)
	}

	// An unambiguous kind has exactly one.
	if got := cfg.KindContainers("address"); len(got) != 1 {
		t.Errorf("address candidates = %v, want one", got)
	}
	if got := cfg.KindContainers(""); got != nil {
		t.Errorf("an empty kind gave %v, want nil", got)
	}
}
