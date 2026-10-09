package query

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/store"
)

// Summarize maps each result and keeps every qualifier and the targets.
func TestSummarizeKeepsTheQualifiers(t *testing.T) {
	t.Parallel()
	full := Envelope[string, int]{
		Format: FormatVersion, Command: "c", Detail: "full", Input: "in", Results: []int{1, 2},
		Summary: &Summary{Found: 2, With: 1}, Holes: []estate.Hole{{Device: "fw01"}},
		Unresolved: []Unresolved{{Device: "fw01"}}, Notes: []Note{{Device: "fw02"}},
		Targets: []estate.Target{{Device: "fw01"}},
	}
	s := Summarize(full, func(n int) string { return string(rune('a' + n)) })
	if s.Detail != "summary" || s.Command != "c" || s.Input != "in" || s.Format != FormatVersion ||
		len(s.Results) != 2 || s.Results[1] != "c" || s.Summary.Found != 2 ||
		len(s.Holes) != 1 || len(s.Unresolved) != 1 || len(s.Notes) != 1 || len(s.Targets) != 1 {
		t.Errorf("summary: %+v", s)
	}
	if none := Summarize(Envelope[string, int]{}, func(int) bool { return true }); none.Results != nil {
		t.Errorf("no results stay nil: %v", none.Results)
	}
}

// A usage error reads as the command line's text and keeps its cause.
func TestUsageErrorReadsAsItsText(t *testing.T) {
	t.Parallel()
	cause := errors.New("cause")
	u := &UsageError{Code: "call.usage", Text: "--port: no", ToolText: "port: no", err: cause}
	if u.Error() != "--port: no" || !errors.Is(u, cause) {
		t.Errorf("%v", u)
	}
}

// The qualifier constructors keep the reason's code out of the format-1 JSON.
func TestQualifiersCarryTheCode(t *testing.T) {
	t.Parallel()
	r := reason.New("note.snapshot-stale", "old")
	n, u := NoteOf("fw01", "vsys1", r), UnresolvedOf("fw01", "", r)
	if n.Code != r.Code || n.Note != "old" || u.Code != r.Code || u.Reason != "old" {
		t.Errorf("%+v %+v", n, u)
	}
	b, err := json.Marshal([]any{n, u})
	if err != nil || string(b) != `[{"device":"fw01","vsys":"vsys1","note":"old"},{"device":"fw01","reason":"old"}]` {
		t.Errorf("%s %v", b, err)
	}
}

// A target from a file has no snapshot; one from the store names it.
func TestTargetOf(t *testing.T) {
	t.Parallel()
	if got := TargetOf(estate.Target{Device: "file", Vsys: "vsys1"}); got != (Target{Device: "file", Vsys: "vsys1"}) {
		t.Errorf("file: %+v", got)
	}
	sn := &store.Snapshot{ID: "20260928T100000Z", Meta: store.Meta{TakenAt: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)}}
	if got := TargetOf(estate.Target{Device: "fw01", Vsys: "vsys1", Snapshot: sn}); got.Snapshot != sn.ID || got.TakenAt != "2026-09-28T10:00:00Z" {
		t.Errorf("snapshot: %+v", got)
	}
}

// A simulation's stages keep their fidelity, candidates and time.
func TestSimStages(t *testing.T) {
	t.Parallel()
	st := simulate.Stage{Slug: "zones", Name: "Zones", Fidelity: simulate.Exact, Detail: "d", Elapsed: 1500 * time.Microsecond}
	st.State.Candidates = 3
	got := SimStages([]simulate.Stage{st})
	if len(got) != 1 || got[0].Slug != "zones" || *got[0].Candidates != 3 || got[0].Fidelity.Level() != "exact" || got[0].ElapsedMS != 1.5 {
		t.Errorf("%+v", got)
	}
}
