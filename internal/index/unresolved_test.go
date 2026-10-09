package index

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/reason"
)

// The defect that started this, now closed.
//
// The fixture mirrors fw01: a custom URL category holding a long URL and a wildcard,
// one rule naming the category, and an earlier rule whose category is "any". Asking
// for the URL used to return the any-rule alone, which reads as "any-category-early
// handles this URL" — the URL was never evaluated.
func TestCandidatesFindsARuleByURLValue(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	const url = "superlong.example.azureapps.microsoft.com"
	rules, rep := idx.Candidates(Category, url)

	if !ruleNames(idx, rules)["URL-Example"] {
		t.Error("the rule whose category holds this URL was not found")
	}
	if len(rep.Hits) != 1 || rep.Hits[0].Name != "custom-azuresite-group" {
		t.Fatalf("hits = %+v, want the category", rep.Hits)
	}
	// The member that matched, so the reasoning can be checked.
	if rep.Hits[0].Via != url {
		t.Errorf("Via = %q, want the member that matched", rep.Hits[0].Via)
	}
	if len(rep.Unresolved) != 0 {
		t.Errorf("a URL that matched reported unresolved: %v", rep.Unresolved)
	}
}

// A wildcard member reaches the rule, and reports which pattern did it.
func TestCandidatesFindsARuleByWildcardURL(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	for _, url := range []string{"foo.wildcard-example.com", "a.b.wildcard-example.com"} {
		rules, rep := idx.Candidates(Category, url)
		if !ruleNames(idx, rules)["URL-Example"] {
			t.Errorf("%s did not reach URL-Example", url)
			continue
		}
		if len(rep.Hits) != 1 || rep.Hits[0].Via != "*.wildcard-example.com" {
			t.Errorf("%s hits = %+v, want the wildcard member", url, rep.Hits)
		}
	}
}

// The cases a substring match would get wrong, and the one a star cannot cover.
func TestCandidatesDoesNotOvermatchAURL(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	for _, url := range []string{
		"wildcard-example.com",          // a star needs at least one token
		"wildcard-example.com.evil.net", // substring matching would match this
		"unrelated.example.org",
	} {
		rules, rep := idx.Candidates(Category, url)
		if ruleNames(idx, rules)["URL-Example"] {
			t.Errorf("%s wrongly reached URL-Example", url)
		}
		// Recognised and not matched is a complete answer, so nothing is unresolved.
		if len(rep.Unresolved) != 0 {
			t.Errorf("%s reported unresolved: %v", url, rep.Unresolved)
		}
	}
}

// A value no value space recognises is a different matter, and must be reported.
func TestCandidatesReportsAValueNothingRecognises(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	rules, rep := idx.Candidates(Category, "not-a-url-and-not-an-object")
	if len(rep.Unresolved) == 0 {
		t.Fatal("an unrecognised value resolved silently")
	}
	if !strings.Contains(rep.Unresolved[0].Reason, "any") || rep.Unresolved[0].Code != "gap.object-unresolved" {
		t.Errorf("reason does not say only any-rules are reported: %q", rep.Unresolved[0].Reason)
	}
	if !ruleNames(idx, rules)["any-category-early"] {
		t.Error("the any-category rule still matches and should be reported")
	}
}

// The category name is a different question from the URL value, and that one does
// work. It must keep working, and must not be reported as unresolved.
func TestCandidatesResolvesACategoryName(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	rules, rep := idx.Candidates(Category, "custom-azuresite-group")
	unresolved := rep.Unresolved
	if len(unresolved) != 0 {
		t.Fatalf("a known category name reported unresolved: %v", unresolved)
	}
	if !ruleNames(idx, rules)["URL-Example"] {
		t.Error("the rule naming the category was not found")
	}
}

// An address and a prefix resolve, and say nothing about being incomplete.
func TestCandidatesResolvesAddressesQuietly(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	for _, v := range []string{"198.18.0.5", "198.18.0.0/24"} {
		if _, rep := idx.Candidates(Source, v); len(rep.Unresolved) != 0 {
			t.Errorf("%s reported unresolved: %v", v, rep.Unresolved)
		}
	}
}

// A query must never intern. The interner is an unlocked map and an index is
// documented immutable, so interning on a lookup path both leaks and races.
func TestQueriesDoNotInternNewNames(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")
	before := idx.Interner().Len()

	idx.Candidates(Source, "not-a-real-object")
	idx.CandidatesForName(Source, "also-not-real")
	idx.CandidatesFor(Source, netip.MustParseAddr("10.9.9.9"))

	if after := idx.Interner().Len(); after != before {
		t.Errorf("interner grew from %d to %d names during lookups", before, after)
	}
}

// The race the interning caused, exercised through the path that interned.
//
// CandidatesForName took an arbitrary name straight to Interner.ID, which writes
// an unlocked map and appends a slice. An index is cached and shared, so two
// callers asking about unknown names concurrently corrupted it. Under -race this
// test fails on the old code.
func TestConcurrentUnknownNameLookupsAreSafe(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			idx.CandidatesForName(Source, fmt.Sprintf("unknown-%d", n))
		}(i)
	}
	wg.Wait()
}

// ruleNames turns a candidate bitmap into a set of rule names, so a test can
// assert on names rather than on bit positions.
func ruleNames(idx *Index, b *roaring.Bitmap) map[string]bool {
	rules := idx.Rules()
	out := map[string]bool{}
	for it := b.Iterator(); it.HasNext(); {
		out[rules[it.Next()].Name] = true
	}
	return out
}

// An fqdn address object is found by its own value, but the addresses behind that
// name live on the device, not in the file. Both halves have to be said: the object
// matched, and the answer is still incomplete.
func TestCandidatesFindsAnFQDNObjectAndSaysWhatIsMissing(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	rules, rep := idx.Candidates(Source, "host.example.com")

	if len(rep.Hits) != 1 || rep.Hits[0].Name != "fqdn-host" {
		t.Fatalf("hits = %+v, want the fqdn-host object", rep.Hits)
	}
	if rep.Hits[0].Via != "host.example.com" {
		t.Errorf("Via = %q, want the value that matched", rep.Hits[0].Via)
	}
	if len(rep.Unresolved) == 0 || rep.Unresolved[0].Code != "gap.fqdn-no-address" {
		t.Error("an fqdn resolves on the device, so the answer is incomplete and must say so")
	}
	if !ruleNames(idx, rules)["fqdn-rule"] {
		t.Error("the rule naming the fqdn object was not found")
	}
}

// Matching is case-insensitive for an fqdn, because DNS names are.
func TestCandidatesMatchesAnFQDNIgnoringCase(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	_, rep := idx.Candidates(Source, "HOST.Example.COM")
	if len(rep.Hits) != 1 {
		t.Errorf("hits = %+v, want the fqdn-host object", rep.Hits)
	}
}

// A field's value spaces come from the schema, so source has an address resolver
// even in a configuration whose every rule says "source any".
func TestResolversComeFromTheSchemaNotTheConfiguration(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	if len(idx.resolversFor(Source)) == 0 {
		t.Fatal("source has no resolver; the wiring fell back to the configuration")
	}
	// Every field a security rule matches on now has at least one value space.
	for _, f := range []Field{Source, Destination, Category, Service, SourceUser, FromZone, ToZone, Application} {
		if len(idx.resolversFor(f)) == 0 {
			t.Errorf("%s has no resolver", f)
		}
	}
	// Tag needs none: a tag is a name, and looking a name up already works.
	if got := len(idx.resolversFor(Tag)); got != 0 {
		t.Errorf("tag resolvers = %d, want 0; a tag is a name", got)
	}
}

// An Unresolved prints its kind only when it has one.
func TestUnresolvedString(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		u    Unresolved
		want string
	}{
		{Unresolved{Value: "x", Reason: "why"}, "x: why"},
		{Unresolved{Value: "x", Kind: "zone", Reason: "why"}, "x (zone): why"},
	} {
		if got := tc.u.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

// An Unresolved keeps its code, and JSON writes it (format 2).
func TestUnresolvedKeepsItsCode(t *testing.T) {
	t.Parallel()
	r := reason.New("zone.missing", "why")
	u := NewUnresolved("x", "zone", r)
	if u != (Unresolved{Value: "x", Kind: "zone", Reason: "why", Code: "zone.missing"}) || u.Why() != r {
		t.Errorf("got %+v", u)
	}
	b, err := json.Marshal(u)
	if err != nil || string(b) != `{"value":"x","kind":"zone","code":"zone.missing","text":"why"}` {
		t.Errorf("json = %s, %v", b, err)
	}
}
