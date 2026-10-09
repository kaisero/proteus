package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
	"github.com/okaiser/proteus/internal/store"
)

// A hop the store cannot give keeps the hole's kind, not a generic load failure.
func TestStoreLoaderKeepsTheHoleCode(t *testing.T) {
	t.Parallel()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	load := storeLoader(st, estate.When{}, estate.NewNetwork(st, nil, estate.When{}), nil)
	_, err = load("fw01", "vsys1")
	var coded *simulate.CodedError
	if !errors.As(err, &coded) || coded.Code() != "gap.snapshot-missing" || !strings.HasPrefix(err.Error(), "fw01/vsys1: ") {
		t.Errorf("%v (%T)", err, err)
	}
}

// A diff of a snapshot without a configuration says so; one that cannot be read
// is a failed load.
func TestConfigGap(t *testing.T) {
	t.Parallel()
	with := store.Snapshot{Device: "fw01", ID: "a", Dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(with.Dir, store.ConfigDoc+".xml"), []byte("<config"), 0o600); err != nil {
		t.Fatal(err)
	}
	without := store.Snapshot{Device: "fw01", ID: "b", Dir: t.TempDir()}
	if got := configGap(with, without); got != "gap.config-missing" {
		t.Errorf("without: %s", got)
	}
	if got := configGap(with, with); got != "gap.load-failed" {
		t.Errorf("with: %s", got)
	}
}

// Format 1 prints a note's text, not its code: two notes that print the same are
// one.
func TestPathNotesDropTheSameText(t *testing.T) {
	t.Parallel()
	res := pathpolicy.Result{Notes: simulate.Reasons{reason.New("note.ha-peer", "same"), reason.New("note.ha-binding", "same")}}
	if got := pathNotes(res); len(got) != 1 || got[0].Code != "note.ha-peer" {
		t.Errorf("%+v", got)
	}
}
