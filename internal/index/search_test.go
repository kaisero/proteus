package index

import (
	"strings"
	"testing"
)

// The case the category name limit creates. PAN-OS caps a custom URL category name at
// 31 characters and one of its members at 255, so a long URL cannot appear in the name
// of the category holding it. Searching the values is the only way to find it.
func TestSearchValuesFindsALongURLByFragment(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	hits := idx.SearchValues("azureapps")
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1: %+v", len(hits), hits)
	}
	if hits[0].Name != "custom-azuresite-group" {
		t.Errorf("name = %q", hits[0].Name)
	}
	if !strings.Contains(hits[0].Via, "azureapps") {
		t.Errorf("Via = %q, want the member that contains the fragment", hits[0].Via)
	}
	// The fragment is in no name anywhere, which is the whole point.
	if strings.Contains(hits[0].Name, "azureapps") {
		t.Error("the fixture no longer demonstrates the problem")
	}
}

// Searching is case-insensitive, because a human typing a URL does not match case.
func TestSearchValuesIgnoresCase(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	if got := len(idx.SearchValues("AZUREAPPS")); got != 1 {
		t.Errorf("got %d hits for an upper-case fragment, want 1", got)
	}
}

// Searching spans value spaces, so an address fragment works too.
func TestSearchValuesFindsAddressesAndFQDNs(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	if got := idx.SearchValues("198.18"); len(got) == 0 {
		t.Error("an address fragment found nothing")
	}
	hits := idx.SearchValues("host.example")
	if len(hits) != 1 || hits[0].Name != "fqdn-host" {
		t.Errorf("an fqdn fragment gave %+v, want fqdn-host", hits)
	}
}

// Searching is not matching, and must not be used for it. A substring search finds
// the category here; a match does not, and that difference is the reason the two are
// separate calls.
func TestSearchValuesIsNotMatching(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	const trap = "wildcard-example.com"
	if got := len(idx.SearchValues(trap)); got == 0 {
		t.Fatalf("search should find the member containing %q", trap)
	}
	rules, _ := idx.Candidates(Category, trap+".evil.net")
	if ruleNames(idx, rules)["URL-Example"] {
		t.Error("matching must not follow the substring; the device does not")
	}
}

// An empty or blank search returns nothing rather than everything.
func TestSearchValuesRejectsAnEmptyFragment(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	for _, q := range []string{"", "   "} {
		if got := idx.SearchValues(q); got != nil {
			t.Errorf("SearchValues(%q) returned %d hits, want none", q, len(got))
		}
	}
}

// An ip-range decomposes into several prefixes, so one object can match a fragment
// more than once. The results are ordered by name and then by the value that
// matched, so the output is stable.
func TestSearchValuesOrdersSeveralHitsOnOneObject(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-urlcat.xml", "vsys1")

	hits := idx.SearchValues("198.18.5.")
	if len(hits) < 2 {
		t.Fatalf("an ip-range should match a fragment through several prefixes, got %+v", hits)
	}
	for _, h := range hits {
		if h.Name != "range-host" {
			t.Errorf("unexpected hit %+v", h)
		}
	}
	for i := 1; i < len(hits); i++ {
		if hits[i-1].Via > hits[i].Via {
			t.Errorf("hits are not ordered by value: %q before %q", hits[i-1].Via, hits[i].Via)
		}
	}
}
