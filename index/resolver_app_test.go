package index

import (
	"strings"
	"testing"
)

func appsIndex(t *testing.T) *Index {
	t.Helper()
	return indexOfVsys(t, "../testdata/config/firewall-apps.xml", "vsys1")
}

// A custom application is in the file, and the group holding it resolves through the
// ordinary group closure, so naming the application reaches the rule naming the group.
func TestAppResolverFindsACustomApplicationThroughItsGroup(t *testing.T) {
	idx := appsIndex(t)

	rules, rep := idx.Candidates(Application, "custom-erp")
	if !ruleNames(idx, rules)["erp-allow"] {
		t.Error("a custom application did not reach the rule naming its group")
	}
	var found bool
	for _, h := range rep.Hits {
		if h.Name == "custom-erp" && h.Kind == kindApplication {
			found = true
		}
	}
	if !found {
		t.Errorf("the custom application was not reported as a hit: %+v", rep.Hits)
	}
}

// A predefined application is not in the file, but its name is still a name: a rule
// naming it is found through the ordinary name path.
func TestAppResolverFindsAPredefinedApplicationByName(t *testing.T) {
	idx := appsIndex(t)

	rules, _ := idx.Candidates(Application, "ssl")
	if !ruleNames(idx, rules)["erp-allow"] {
		t.Error("a predefined application named in a group did not reach the rule")
	}
}

// An application filter selects predefined applications by metadata that lives in the
// content database, so its membership is reported rather than guessed. The rule using it
// is therefore never reported as a match for a specific application.
func TestAppResolverReportsAnApplicationFilter(t *testing.T) {
	idx := appsIndex(t)

	rules, rep := idx.Candidates(Application, "custom-erp")

	var told bool
	for _, u := range rep.Unresolved {
		if u.Value == "high-risk-filter" {
			told = true
			if !strings.Contains(u.Reason, "content database") {
				t.Errorf("reason does not explain why: %q", u.Reason)
			}
		}
	}
	if !told {
		t.Errorf("the application filter was not reported: %v", rep.Unresolved)
	}
	// It is reported, not matched.
	if ruleNames(idx, rules)["risk-deny"] {
		t.Error("a rule using an application filter was reported as a match")
	}
}

// An application container groups predefined applications, and its members are in the
// content database too.
func TestAppResolverReportsAnApplicationContainer(t *testing.T) {
	idx := appsIndex(t)

	_, rep := idx.Candidates(Application, "custom-erp")
	var told bool
	for _, u := range rep.Unresolved {
		if u.Value == "ms-office-bundle" && u.Kind == "application-container" {
			told = true
		}
	}
	if !told {
		t.Errorf("the application container was not reported: %v", rep.Unresolved)
	}
}

// Searching finds a custom application by a fragment of its name.
func TestAppResolverSearch(t *testing.T) {
	idx := appsIndex(t)

	var found bool
	for _, h := range idx.SearchValues("erp") {
		if h.Kind == kindApplication {
			found = true
		}
	}
	if !found {
		t.Errorf("searching did not find the custom application")
	}
}

// A value that plainly belongs to another value space is not treated as an application.
func TestAppResolverIgnoresOtherShapes(t *testing.T) {
	idx := appsIndex(t)

	for _, q := range []string{"10.0.0.0/8", "example.com/x", "a b"} {
		_, rep := idx.Candidates(Application, q)
		for _, h := range rep.Hits {
			if h.Kind == kindApplication {
				t.Errorf("%s was reported as an application: %+v", q, h)
			}
		}
	}
}
