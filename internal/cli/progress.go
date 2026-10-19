package cli

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/kaisero/proteus/internal/task"
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
// /dev/null is also a character device, so it counts too. This is harmless: with
// output going to /dev/null, progress lines and colour codes are discarded either
// way.
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
	pal := palette{on: useColor(a.color, a.format, a.getenv, a.stderrTTY)}
	return func(kind string, r task.Record) {
		st := string(r.Status)
		switch r.Status {
		case task.OK:
			st = pal.ok(st)
		case task.Failed:
			st = pal.bad(st)
		default:
			st = pal.warn(st)
		}
		fmt.Fprintf(a.stderr, "%s  %-10s %s  %s\n", kind, r.Slug, st, pal.dim(r.Elapsed.Round(time.Millisecond).String()))
	}
}
