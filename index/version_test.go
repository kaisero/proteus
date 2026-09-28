package index

import (
	"strings"
	"testing"
)

// Spec §9: an answer from a configuration read with another version's schema says
// so, because it can be missing rules without looking incomplete.
func TestEveryReportCarriesTheVersionGap(t *testing.T) {
	idx := indexOf(t, "../testdata/config/firewall-version-12.2.xml", "vsys1")
	if idx.VersionGap() == "" {
		t.Fatal("a 12.2 configuration read with the 11.2 schema has a gap")
	}
	for _, q := range []struct {
		f     Field
		value string
	}{
		{Source, "198.18.10.100"},
		{Destination, "no-such-object"},
	} {
		_, rep := idx.Candidates(q.f, q.value)
		var told bool
		for _, u := range rep.Unresolved {
			if strings.Contains(u.Reason, "12.2.0") && strings.Contains(u.Reason, "11.2.0") {
				told = true
			}
		}
		if !told {
			t.Errorf("%s %s: the report does not carry the version gap: %v", q.f, q.value, rep.Unresolved)
		}
	}
}

func TestAnExactVersionAddsNothing(t *testing.T) {
	idx := indexOf(t, "../testdata/config/firewall-lab.xml", "vsys1")
	if idx.VersionGap() != "" {
		t.Errorf("gap = %q, want none", idx.VersionGap())
	}
	_, rep := idx.Candidates(Source, "198.18.10.100")
	for _, u := range rep.Unresolved {
		if strings.Contains(u.Reason, "schema") {
			t.Errorf("an exact version reported a schema gap: %s", u.Reason)
		}
	}
}
