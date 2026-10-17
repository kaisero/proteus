package query

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
)

// A lookup over the store: the cards with their target and a summary; a name
// found nowhere is an empty answer, not an error.
func TestLookupTheStore(t *testing.T) {
	t.Parallel()
	env := labStore(t)
	e, err := Lookup(context.Background(), env, LookupInput{Name: "dc01", Expand: true})
	if err != nil || len(e.Results) != 1 || e.Summary.Found != 1 || e.Summary.With != 1 || e.Command != "lookup" {
		t.Fatalf("%+v %v", e, err)
	}
	if r := e.Results[0]; r.Card.Name != "dc01" || r.Device != "fw01" || e.Targets[r.TargetIndex].Device != "fw01" || !e.Input.Expand {
		t.Errorf("%+v", r)
	}
	e, err = Lookup(context.Background(), env, LookupInput{Name: "no-such-name"})
	if err != nil || len(e.Results) != 0 || e.Summary.Found != 0 || e.Summary.Without != len(e.Targets) {
		t.Errorf("missing: %+v %v", e.Summary, err)
	}
}

// A kind the lookup does not know, a name of several kinds, and a file with the
// store's selectors are usage errors.
func TestLookupInputRules(t *testing.T) {
	t.Parallel()
	file := fixture("firewall-lab.xml")
	_, err := Lookup(context.Background(), Env{}, LookupInput{Name: "dc01", Kind: "planet", Selection: Selection{File: file}})
	usageOK(t, err, "--kind: ")
	_, err = Lookup(context.Background(), Env{}, LookupInput{Name: "x", Selection: Selection{File: file, At: "2026-01-01"}})
	usageOK(t, err, "--at selects from the store")
	_, err = Lookup(context.Background(), labStore(t), LookupInput{Name: "x", Selection: Selection{At: "tuesday"}})
	usageOK(t, err, `--at "tuesday"`)
}

// A name that is a rule and an object is two kinds: the caller picks one.
func TestLookupOfSeveralKindsNeedsAKind(t *testing.T) {
	t.Parallel()
	b := bytes.Replace(pathlab.Read(t, fixture("firewall-lab.xml")), []byte(`<entry name="pushed-pre">`), []byte(`<entry name="dc01">`), 1)
	file := filepath.Join(t.TempDir(), "two-kinds.xml")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Lookup(context.Background(), Env{}, LookupInput{Name: "dc01", Selection: Selection{File: file}})
	usageOK(t, err, `"dc01" names more than one kind; pick one with --kind:`)
	e, err := Lookup(context.Background(), Env{}, LookupInput{Name: "dc01", Kind: "security-rule", Selection: Selection{File: file}})
	if err != nil || len(e.Results) == 0 {
		t.Fatalf("with a kind: %+v %v", e.Summary, err)
	}
	for _, r := range e.Results {
		if r.Card.Kind != "security-rule" {
			t.Errorf("kind %s", r.Card.Kind)
		}
	}
}

// appStore is fw01 with firewall-appid.xml and content 8000-1000, whose file
// the store holds, and an env whose content loads src counts.
func appStore(t *testing.T) (Env, *countingApps) {
	t.Helper()
	l := newLab(t)
	if err := l.st.WriteContent("8000-1000", contentOf(t, "8000-1000")); err != nil {
		t.Fatal(err)
	}
	l.write(store.Meta{Device: "fw01", Host: "fw01.example.test", AppVersion: "8000-1000"}, pathlab.Read(t, fixture("firewall-appid.xml")))
	src := &countingApps{loads: map[string]int{}}
	env := l.env()
	env.Apps = src
	return env, src
}

// lookupFw01 looks a name up on fw01.
func lookupFw01(t *testing.T, env Env, name, kind string) Envelope[LookupInput, LookupResult] {
	t.Helper()
	e, err := Lookup(context.Background(), env, LookupInput{Name: name, Kind: kind, Selection: Selection{Device: []string{"fw01"}}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A rule needs no application data, so lookup <rule> opens no content file;
// a predefined application, a filter and an application kind do (D11).
func TestLookupRuleLoadsNoContent(t *testing.T) {
	t.Parallel()
	env, src := appStore(t)
	if e := lookupFw01(t, env, "allow-media", ""); len(e.Results) != 1 || len(src.loads) != 0 {
		t.Fatalf("rule: %d cards, loads %v", len(e.Results), src.loads)
	}
	// A custom application has its card from the configuration.
	if e := lookupFw01(t, env, "erp-custom", ""); len(e.Results) != 1 || e.Results[0].Card.Kind != "application" || len(src.loads) != 0 {
		t.Fatalf("custom: %+v, loads %v", e.Results, src.loads)
	}
	for _, tc := range []struct{ name, kind, want string }{
		{"ssl", "", "application"},
		{"f-media", "", "application-filter"},
		{"erp-custom", "application", "application"},
		{"office-suite", "", "application-container"},
	} {
		before := sum(src.loads)
		e := lookupFw01(t, env, tc.name, tc.kind)
		if len(e.Results) != 1 || e.Results[0].Card.Kind != tc.want || sum(src.loads) != before+1 {
			t.Errorf("%s %s: %+v, loads %v", tc.name, tc.kind, e.Results, src.loads)
		}
	}
	// A filter card lists what the filter selects.
	e := lookupFw01(t, env, "f-media", "")
	if !strings.Contains(fmt.Sprint(e.Results[0].Card.Sections), "app-media") {
		t.Errorf("f-media: %+v", e.Results[0].Card)
	}
}

// Without the content file, lookup of a predefined application finds nothing
// and says why.
func TestLookupWithoutDataNotes(t *testing.T) {
	t.Parallel()
	e, err := Lookup(context.Background(), Env{}, LookupInput{Name: "ssl", Selection: Selection{File: appFile(t, false)}})
	if n, ok := noteWith(e.Notes, "note.app-data-missing"); err != nil || len(e.Results) != 0 || !ok || !strings.Contains(n.Note, "does not exist") {
		t.Errorf("%+v %+v %v", e.Results, e.Notes, err)
	}
	e, err = Lookup(context.Background(), Env{}, LookupInput{Name: "ssl", Selection: Selection{File: appFile(t, true)}})
	if _, ok := noteWith(e.Notes, "note.app-data-file"); err != nil || len(e.Results) != 1 || !ok {
		t.Errorf("%+v %+v %v", e.Results, e.Notes, err)
	}
}

func sum(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}
