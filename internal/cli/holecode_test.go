package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/okaiser/proteus/internal/store"
)

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
