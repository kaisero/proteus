package query

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/okaiser/proteus/internal/simulate/pathlab"
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
