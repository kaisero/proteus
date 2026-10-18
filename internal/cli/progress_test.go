package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/task"
)

func TestIsTerminal(t *testing.T) {
	t.Parallel()
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	regular, err := os.Create(filepath.Join(t.TempDir(), "f"))
	if err != nil {
		t.Fatal(err)
	}
	closed, err := os.Create(filepath.Join(t.TempDir(), "g"))
	if err != nil {
		t.Fatal(err)
	}
	_ = regular.Close()
	_ = closed.Close()
	if !isTerminal(devNull) {
		t.Errorf("%s is a character device", os.DevNull)
	}
	for _, w := range []io.Writer{&bytes.Buffer{}, regular, closed} {
		if isTerminal(w) {
			t.Errorf("%T is not a terminal", w)
		}
	}
}

// Progress prints only in text mode, to a terminal, without --verbose.
func TestProgressOnlyOnATerminalInText(t *testing.T) {
	t.Parallel()
	var errOut bytes.Buffer
	a := newApp(&bytes.Buffer{}, &errOut, func(string) string { return "" }, time.Now)
	a.format = formatText
	a.color = colorNever // this test is about when progress fires, not its colour
	if a.progress() != nil {
		t.Error("no progress when stderr is not a terminal")
	}
	a.stderrTTY = true
	a.verbose = true
	if a.progress() != nil {
		t.Error("no progress with --verbose: the STEP lines echo")
	}
	a.verbose = false
	a.format = formatJSON
	if a.progress() != nil {
		t.Error("no progress in JSON mode")
	}
	a.format = formatText
	p := a.progress()
	if p == nil {
		t.Fatal("progress on a terminal in text mode")
	}
	p("fw01", task.Record{Slug: "login", Status: task.OK, Elapsed: 1500 * time.Microsecond})
	if got, want := errOut.String(), "fw01  login      ok  2ms\n"; got != want {
		t.Errorf("progress line %q, want %q", got, want)
	}
}

// A fetch on a terminal shows each device's stages on stderr as they end; stdout
// holds the same answer as without a terminal.
func TestFetchProgressOnATerminal(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), lab(t).Start(t)))
	var out, errOut bytes.Buffer
	a := newApp(&out, &errOut, func(k string) string { return c.env[k] }, func() time.Time { return c.clock })
	a.stderrTTY = true
	if code := a.execute(context.Background(), []string{"fetch", "--all", "--config", c.cfgPath}); code != exitOK {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	for _, dev := range []string{"fw01", "fw02"} {
		for _, slug := range []string{"resolve", "login", "ha", "documents", "applications", "store"} {
			if !strings.Contains(errOut.String(), dev+"  "+slug+" ") {
				t.Errorf("no progress line for %s/%s:\n%s", dev, slug, errOut.String())
			}
		}
	}
	if strings.Contains(out.String(), "  login ") {
		t.Errorf("progress reached stdout:\n%s", out.String())
	}
}
