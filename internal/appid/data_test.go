package appid_test

import (
	"slices"
	"testing"

	"github.com/okaiser/proteus/internal/appid"
)

// S9: a container holds its functions.
func TestContainersOf(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for app, want := range map[string][]string{
		"office-docs": {"office-suite"},
		"OFFICE-MAIL": {"office-suite"},
		"ssl":         nil,
		"no-such-app": nil,
	} {
		if got := d.ContainersOf(app); !slices.Equal(got, want) {
			t.Errorf("ContainersOf(%s) = %v, want %v", app, got, want)
		}
	}
	// The answer is a copy: a change by the caller does not reach the data.
	d.ContainersOf("office-docs")[0] = "changed"
	if got := d.ContainersOf("office-docs"); !slices.Equal(got, []string{"office-suite"}) {
		t.Errorf("ContainersOf after a change by the caller: %v", got)
	}
}

// §2.2: without the containers, no application has one.
func TestContainersOfWithoutContainers(t *testing.T) {
	t.Parallel()
	d, err := appid.Parse(gz(t, `<content version="8000-1000" trim="1" containers="missing"><application>`+
		`<entry name="office-docs"><application-container>office-suite</application-container></entry>`+
		`</application></content>`))
	if err != nil {
		t.Fatal(err)
	}
	if got := d.ContainersOf("office-docs"); got != nil {
		t.Errorf("ContainersOf without containers: %v", got)
	}
}

// I1, I3, I8: the content applications whose implicit-use-applications hold
// an application; use-applications do not count.
func TestImpliedBy(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	for app, want := range map[string][]string{
		"ssl":          {"app-other", "app-remote", "app-remote-b"},
		"SSL":          {"app-other", "app-remote", "app-remote-b"},
		"web-browsing": {"app-remote"},
		"dns":          nil,
		"no-such-app":  nil,
	} {
		if got := d.ImpliedBy(app); !slices.Equal(got, want) {
			t.Errorf("ImpliedBy(%s) = %v, want %v", app, got, want)
		}
	}
	d.ImpliedBy("ssl")[0] = "changed"
	if got := d.ImpliedBy("ssl"); got[0] != "app-other" {
		t.Errorf("ImpliedBy after a change by the caller: %v", got)
	}
}

// P10: near names for an unknown name; for a container, its functions.
func TestSuggestNamesContainerMembers(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	if got := d.Suggest("office-suite", 5); !slices.Equal(got, []string{"office-docs", "office-mail"}) {
		t.Errorf("Suggest(office-suite) = %v", got)
	}
	if got := d.Suggest("Office-Suite", 1); !slices.Equal(got, []string{"office-docs"}) {
		t.Errorf("Suggest(Office-Suite, 1) = %v", got)
	}
	got := d.Suggest("sssl", 5)
	if len(got) == 0 || got[0] != "ssl" || len(got) > 5 {
		t.Errorf("Suggest(sssl) = %v", got)
	}
	// A part of a name finds the names that hold it, at most n.
	if got := d.Suggest("app", 5); len(got) != 5 {
		t.Errorf("Suggest(app, 5) = %v, want 5 names", got)
	}
	if got := d.Suggest("REMOTE", 5); !slices.Equal(got, []string{"app-remote", "app-remote-b"}) {
		t.Errorf("Suggest(REMOTE) = %v", got)
	}
	if got := d.Suggest("zzzzzzzzzzzz", 5); got != nil {
		t.Errorf("Suggest of a far name = %v", got)
	}
	if got := d.Suggest("ssl", 0); got != nil {
		t.Errorf("Suggest(ssl, 0) = %v", got)
	}
}

// P14, F14: an application name matches in any case and gives the content
// name.
func TestDataFindsAnApplicationInAnyCase(t *testing.T) {
	t.Parallel()
	d := loadFixture(t)
	a, ok := d.App("SSL")
	if !ok || a.Name != "ssl" {
		t.Errorf("App(SSL) = %q, %v", a.Name, ok)
	}
}
