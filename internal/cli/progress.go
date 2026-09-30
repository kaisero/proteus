package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/okaiser/proteus/internal/task"
)

// lockedWriter serialises writes. stderr is wrapped in one, so the run log's echo,
// progress and the exit lines cannot race while devices fetch in parallel.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// isTerminal reports whether w is a character device, such as a terminal.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// progress is the OnStep of a staged fetch: one line per finished step on stderr.
// It is nil unless the format is text, stderr is a terminal and --verbose is off
// (with --verbose the STEP lines already echo).
func (a *app) progress() func(kind string, r task.Record) {
	if a.format != formatText || !a.stderrTTY || a.verbose {
		return nil
	}
	return func(kind string, r task.Record) {
		fmt.Fprintf(a.stderr, "%s  %-10s %-8s %s\n", kind, r.Slug, r.Status, r.Elapsed.Round(time.Millisecond))
	}
}
