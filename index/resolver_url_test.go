package index

import (
	"strings"
	"testing"
)

// A Category Match category lists predefined PAN-DB categories, not URLs, and what
// those hold is in Palo Alto's cloud rather than the configuration. Guessing would
// be worse than saying so.
func TestURLResolverReportsACategoryMatchCategory(t *testing.T) {
	idx := indexOfVsys(t, "../testdata/config/firewall-urlcat-edge.xml", "vsys1")

	_, rep := idx.Candidates(Category, "anything.example.com")

	var found bool
	for _, u := range rep.Unresolved {
		if u.Value == "cat-match-group" {
			found = true
			if !strings.Contains(u.Reason, "PAN-DB") {
				t.Errorf("reason does not explain why: %q", u.Reason)
			}
		}
	}
	if !found {
		t.Errorf("the Category Match category was not reported: %v", rep.Unresolved)
	}
}

// A member the parser cannot read contributes no match and is reported, the way an
// unreadable tag filter already is. The rest of the category still works.
func TestURLResolverReportsAnUnreadableMemberAndKeepsTheRest(t *testing.T) {
	idx := indexOfVsys(t, "../testdata/config/firewall-urlcat-edge.xml", "vsys1")

	rules, rep := idx.Candidates(Category, "good.example.com")

	if !ruleNames(idx, rules)["uses-bad-member"] {
		t.Error("the readable member did not reach its rule")
	}
	var found bool
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Value, "two-stars") {
			found = true
			if !strings.Contains(u.Reason, "cat-bad-member") {
				t.Errorf("reason does not name the category: %q", u.Reason)
			}
		}
	}
	if !found {
		t.Errorf("the unreadable member was not reported: %v", rep.Unresolved)
	}
}

// A bare word is a name, not a URL. Matching it as a URL would report every category
// whose members happen to share a token.
func TestURLResolverIgnoresAValueWithNoDotOrSlash(t *testing.T) {
	idx := indexOfVsys(t, "../testdata/config/firewall-urlcat-edge.xml", "vsys1")

	_, rep := idx.Candidates(Category, "cat-bad-member")
	if len(rep.Hits) != 0 {
		t.Errorf("a category name produced value hits: %+v", rep.Hits)
	}
}
