package cli

import (
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
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

// detailer is an answer with a summary form (spec 2026-10-09 §3.5): the
// questions of the query layer.
type detailer interface {
	Detail() string
	SummaryResults() any
}

// summarizer is an answer whose envelope counts its results: search, lookup
// and snapshot diff.
type summarizer interface {
	Summary() *query.Summary
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
		err = writeJSON(a.stdout, a.envelopeOf(ans))
	case formatYAML:
		err = writeYAML(a.stdout, a.envelopeOf(ans))
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

// envelopeOf is an answer's JSON envelope, in the form --detail asks.
func (a *app) envelopeOf(ans answer) envelope {
	q := ans.Qualifiers()
	e := envelope{
		Command: ans.Command(), Input: ans.Input(), Results: ans.Results(),
		Holes: q.Holes, Unresolved: q.Unresolved, Notes: q.Notes,
	}
	if s, ok := ans.(summarizer); ok {
		e.Summary = s.Summary()
	}
	if d, ok := ans.(detailer); ok {
		e.Detail = d.Detail()
		if a.detail == query.DetailSummary {
			e.Results, e.Detail = d.SummaryResults(), query.DetailSummary
		}
	}
	return e
}

// emitRun is how every RunE ends: an error when there is no answer, else the
// answer's rendering and status.
func (a *app) emitRun(ans answer, err error) error {
	if err != nil {
		return err
	}
	return a.emit(ans)
}

// printQualifiers prints holes and unresolved entries after an answer, then left:
// the notes of targets that printed no header, as when a limit cut all their
// results, so that no note is lost. Other notes print under their target's
// header (printNotes).
func printQualifiers(t *textOut, q qualifiers, left ...note) {
	for _, h := range q.Holes {
		fmt.Fprintf(t, "%s %s: %s\n", t.pal.bad("hole:"), where(h.Device, h.Vsys), h.Reason)
	}
	// A composite reason's parts read as one line, as one reason.
	for i := 0; i < len(q.Unresolved); {
		u, text := q.Unresolved[i], q.Unresolved[i].Reason
		for i++; i < len(q.Unresolved) && q.Unresolved[i].Part; i++ {
			text += "; " + q.Unresolved[i].Reason
		}
		fmt.Fprintf(t, "%s %s: %s\n", t.pal.warn("unresolved:"), where(u.Device, u.Vsys), text)
	}
	for _, n := range left {
		fmt.Fprintf(t, "%s %s: %s\n", noteStyle(t.pal, reason.Reason{Code: n.Code})("note:"), where(n.Device, n.Vsys), n.Note)
	}
	if len(q.Holes)+len(q.Unresolved)+len(left) > 0 {
		fmt.Fprintln(t)
	}
}

// leftNotes are the notes of the targets that printed no header: shown says
// which did.
func leftNotes(ts []estate.Target, shown func(i int) bool) []note {
	var out []note
	for i, tg := range ts {
		if shown(i) {
			continue
		}
		for _, n := range tg.Notes {
			out = append(out, noteOf(tg.Device, tg.Vsys, n))
		}
	}
	return out
}

// printNotes prints a target's notes under its header.
func printNotes(t *textOut, tg estate.Target) {
	for _, n := range tg.Notes {
		fmt.Fprintf(t, "  %s\n", noteStyle(t.pal, n)("note: "+n.Text))
	}
}

// noteStyle is a note's palette role (spec §9.2): warn for a stale snapshot, dim for
// any other. A stale note is recognised by its code.
func noteStyle(p palette, n reason.Reason) func(string) string {
	if n.Code == "note.snapshot-stale" {
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
