// Package task runs an operation as named steps and records each one: its status,
// what it concluded, how long it took. It is a leaf: it imports runlog and reason
// and nothing else of this module (AGENTS.md R12).
package task

import (
	"context"
	"fmt"
	"time"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/runlog"
)

// Status is how a step ended.
type Status string

// The statuses.
const (
	OK      Status = "ok"
	Partial Status = "partial" // the step did its work and part of it failed
	Skipped Status = "skipped" // the step had nothing to do
	Failed  Status = "failed"  // the step returned an error; the run stopped here
)

// Step is one named piece of work on the operation's state.
type Step[S any] struct {
	Name, Slug string
	Do         func(ctx context.Context, s *S) (Result, error)
}

// Result is what a step concluded.
type Result struct {
	Status Status          // OK when empty
	Detail string          // one line: the stage table and the STEP log line
	Notes  []reason.Reason // what a reader of the answer should know
	Debug  []string        // run log at debug level only
}

// Record is one step as it ran.
type Record struct {
	Name, Slug string
	Status     Status
	Detail     string
	Notes      []reason.Reason
	Elapsed    time.Duration
	Err        error
}

// Options tune Run.
type Options struct {
	Log    *runlog.Logger
	OnStep func(kind string, r Record) // called after each step; may be nil
}

// Run executes the steps in order. It stops at the first error, which it returns
// wrapped as "kind/slug: err". It checks ctx before each step: once ctx is done it
// returns ctx's error wrapped the same way, and the step it did not start has no
// Record.
func Run[S any](ctx context.Context, kind string, s *S, steps []Step[S], o Options) ([]Record, error) {
	var recs []Record
	for _, st := range steps {
		if err := ctx.Err(); err != nil {
			return recs, fmt.Errorf("%s/%s: %w", kind, st.Slug, err)
		}
		start := time.Now()
		res, err := st.Do(ctx, s)
		r := Record{Name: st.Name, Slug: st.Slug, Status: res.Status, Detail: res.Detail, Notes: res.Notes, Elapsed: time.Since(start)}
		if r.Status == "" {
			r.Status = OK
		}
		if err != nil {
			r.Status, r.Err = Failed, fmt.Errorf("%s/%s: %w", kind, st.Slug, err)
			recs = append(recs, r)
			o.Log.Errorf(runlog.TagStep, "%s/%s: failed: %v", kind, st.Slug, err)
			if o.OnStep != nil {
				o.OnStep(kind, r)
			}
			return recs, r.Err
		}
		recs = append(recs, r)
		o.Log.Infof(runlog.TagStep, "%s/%s: %s %s - %s", kind, st.Slug, r.Status, r.Elapsed.Round(time.Microsecond), r.Detail)
		for _, d := range res.Debug {
			o.Log.Debugf(runlog.TagStep, "%s/%s: %s", kind, st.Slug, d)
		}
		if o.OnStep != nil {
			o.OnStep(kind, r)
		}
	}
	return recs, nil
}
