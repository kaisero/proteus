package index

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"
)

// The defect this guard exists for. The fixture mirrors fw01: a custom URL
// category holding a long URL, one rule naming the category, and an earlier rule
// whose category is "any".
//
// Asking for the URL used to return the any-rule and nothing else, which reads as
// "rule any-category-early handles this URL". The URL was never evaluated at all.
func TestCandidatesReportsAURLItCannotEvaluate(t *testing.T) {
	idx := indexOfVsys(t, "../testdata/config/firewall-urlcat.xml", "vsys1")

	const url = "superlong.example.azureapps.microsoft.com"
	rules, unresolved := idx.Candidates(Category, url)

	if len(unresolved) == 0 {
		t.Fatal("a URL value resolved silently; the caller cannot tell the answer is incomplete")
	}
	if got := unresolved[0].Value; got != url {
		t.Errorf("Unresolved.Value = %q, want the queried URL", got)
	}
	if !strings.Contains(unresolved[0].Reason, "any") {
		t.Errorf("reason does not say that only any-rules are reported: %q", unresolved[0].Reason)
	}

	// The any-rule is still a real match, so it is returned. What must not happen
	// is returning it without the warning above.
	names := ruleNames(idx, rules)
	if !names["any-category-early"] {
		t.Error("the any-category rule matches every URL and should still be reported")
	}
	if names["URL-Example"] {
		t.Error("URL-Example cannot be found by URL value yet; P2 adds that")
	}
}

// The category name is a different question from the URL value, and that one does
// work. It must keep working, and must not be reported as unresolved.
func TestCandidatesResolvesACategoryName(t *testing.T) {
	idx := indexOfVsys(t, "../testdata/config/firewall-urlcat.xml", "vsys1")

	rules, unresolved := idx.Candidates(Category, "custom-azuresite-group")
	if len(unresolved) != 0 {
		t.Fatalf("a known category name reported unresolved: %v", unresolved)
	}
	if !ruleNames(idx, rules)["URL-Example"] {
		t.Error("the rule naming the category was not found")
	}
}

// An address and a prefix resolve, and say nothing about being incomplete.
func TestCandidatesResolvesAddressesQuietly(t *testing.T) {
	idx := indexOfVsys(t, "../testdata/config/firewall-urlcat.xml", "vsys1")

	for _, v := range []string{"198.18.0.5", "198.18.0.0/24"} {
		if _, un := idx.Candidates(Source, v); len(un) != 0 {
			t.Errorf("%s reported unresolved: %v", v, un)
		}
	}
}

// A query must never intern. The interner is an unlocked map and an index is
// documented immutable, so interning on a lookup path both leaks and races.
func TestQueriesDoNotInternNewNames(t *testing.T) {
	idx := indexOfVsys(t, "../testdata/config/firewall-urlcat.xml", "vsys1")
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
	idx := indexOfVsys(t, "../testdata/config/firewall-urlcat.xml", "vsys1")

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
