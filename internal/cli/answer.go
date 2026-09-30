package cli

import (
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/runlog"
)

// answer is what one command found. emit renders it; a command never writes to
// stdout itself (spec §3.1).
type answer interface {
	Command() string        // "search", "simulate nat"
	Input() any             // the typed input block (input.go)
	Results() any           // a slice; never nil
	Qualifiers() qualifiers // holes, unresolved, notes
	// Text writes the human rendering, qualifiers included where the command puts
	// them. It returns the first write error.
	Text(t *textOut) error
}

// qualifiers say how complete an answer is.
type qualifiers struct {
	Holes      []estate.Hole
	Unresolved []unresolved
	Notes      []note
}

// status is the exit status the qualifiers earn: incomplete when anything was a
// hole or unresolved.
func (q qualifiers) status() error {
	if len(q.Holes) > 0 || len(q.Unresolved) > 0 {
		return errIncomplete
	}
	return nil
}

// statuser is an answer that sets its own exit status. Only fetch needs it.
type statuser interface {
	Status() error
}

// textOut is what Text writes with. It is an io.Writer that keeps the first write
// error, so renderers can print without checking every call.
type textOut struct {
	w   io.Writer
	now time.Time
	pal palette
	err error
}

func (t *textOut) Write(p []byte) (int, error) {
	if t.err != nil {
		return 0, t.err
	}
	n, err := t.w.Write(p)
	t.err = err
	return n, err
}

// emit renders an answer in the chosen format, logs the answer line and returns
// the exit status the answer earns.
func (a *app) emit(ans answer) error {
	q := ans.Qualifiers()
	var err error
	switch a.format {
	case formatJSON:
		err = writeJSON(a.stdout, envelope{
			Command: ans.Command(), Input: ans.Input(), Results: ans.Results(),
			Holes: q.Holes, Unresolved: q.Unresolved, Notes: q.Notes,
		})
	case formatYAML:
		err = writeYAML(a.stdout, envelope{
			Command: ans.Command(), Input: ans.Input(), Results: ans.Results(),
			Holes: q.Holes, Unresolved: q.Unresolved, Notes: q.Notes,
		})
	default:
		err = ans.Text(&textOut{w: a.stdout, now: a.now(), pal: palette{on: useColor(a.color, a.format, a.getenv, a.stdoutTTY)}})
	}
	if err != nil {
		return err
	}
	a.log.Infof(runlog.TagRun, "answer: %s: %d holes, %d unresolved, %d notes",
		ans.Command(), len(q.Holes), len(q.Unresolved), len(q.Notes))
	if s, ok := ans.(statuser); ok {
		return s.Status()
	}
	return q.status()
}

// emitRun is how every RunE ends: an error when there is no answer, else the
// answer's rendering and status.
func (a *app) emitRun(ans answer, err error) error {
	if err != nil {
		return err
	}
	return a.emit(ans)
}

// printQualifiers prints holes and unresolved entries after an answer. Notes print
// under each target's header instead (printNotes).
func printQualifiers(t *textOut, q qualifiers) {
	for _, h := range q.Holes {
		fmt.Fprintf(t, "%s %s: %s\n", t.pal.bad("hole:"), where(h.Device, h.Vsys), h.Reason)
	}
	for _, u := range q.Unresolved {
		fmt.Fprintf(t, "%s %s: %s\n", t.pal.warn("unresolved:"), where(u.Device, u.Vsys), u.Reason)
	}
	if len(q.Holes)+len(q.Unresolved) > 0 {
		fmt.Fprintln(t)
	}
}

// printNotes prints a target's notes under its header. A version gap is left for
// printQualifiers, because it makes the answer incomplete rather than qualifying it.
func printNotes(t *textOut, tg estate.Target) {
	for _, n := range tg.Notes {
		if n != tg.Report.VersionGap {
			fmt.Fprintf(t, "  %s\n", noteStyle(t.pal, n)("note: "+n))
		}
	}
}

// noteStyle is a note's palette role (spec §9.2): warn for a stale snapshot, dim for
// any other. A stale note is recognised by the wording of estate.StaleNote.
func noteStyle(p palette, n string) func(string) string {
	if strings.HasPrefix(n, "snapshot ") && strings.Contains(n, " old, past the ") && strings.HasSuffix(n, " limit") {
		return p.warn
	}
	return p.dim
}

// emptySlice turns a nil slice into an empty one of the same type, so JSON prints []
// rather than null. Anything else is returned as it is.
func emptySlice(v any) any {
	rv := reflect.ValueOf(v)
	if v == nil {
		return []any{}
	}
	if rv.Kind() == reflect.Slice && rv.IsNil() {
		return reflect.MakeSlice(rv.Type(), 0, 0).Interface()
	}
	return v
}
