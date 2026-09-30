package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/estate"
)

type fakeAnswer struct {
	results []string
	q       qualifiers
	status  error
}

func (f fakeAnswer) Command() string        { return "fake" }
func (f fakeAnswer) Input() any             { return map[string]string{"x": "y"} }
func (f fakeAnswer) Results() any           { return f.results }
func (f fakeAnswer) Qualifiers() qualifiers { return f.q }
func (f fakeAnswer) Text(t *textOut) error {
	for _, r := range f.results {
		fmt.Fprintln(t, r)
	}
	printQualifiers(t, f.q)
	return t.err
}

type statusAnswer struct{ fakeAnswer }

func (s statusAnswer) Status() error { return s.status }

func TestEmitRendersEachFormat(t *testing.T) {
	t.Parallel()
	ans := fakeAnswer{results: []string{"a"}, q: qualifiers{Holes: []estate.Hole{{Device: "fw1", Reason: "gone"}}}}
	var out bytes.Buffer
	a := newApp(&out, &bytes.Buffer{}, func(string) string { return "" }, func() time.Time { return time.Time{} })
	a.format = formatText
	if err := a.emit(ans); !errors.Is(err, errIncomplete) {
		t.Errorf("a hole must make the answer incomplete, got %v", err)
	}
	if got := out.String(); got != "a\nhole: fw1: gone\n\n" {
		t.Errorf("text = %q", got)
	}
	out.Reset()
	a.format = formatJSON
	_ = a.emit(fakeAnswer{})
	var env map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if string(env["results"]) != "[]" {
		t.Errorf("nil results must print as [], got %s", env["results"])
	}
}

func TestEmitLetsAnAnswerSetItsStatus(t *testing.T) {
	t.Parallel()
	a := newApp(&bytes.Buffer{}, &bytes.Buffer{}, func(string) string { return "" }, time.Now)
	a.format = formatText
	want := errors.New("x")
	if err := a.emit(statusAnswer{fakeAnswer{status: want}}); !errors.Is(err, want) {
		t.Errorf("got %v", err)
	}
}

func TestTextOutKeepsTheFirstWriteError(t *testing.T) {
	t.Parallel()
	to := &textOut{w: failWriter{}}
	fmt.Fprintln(to, "a")
	fmt.Fprintln(to, "b")
	if to.err == nil || !strings.Contains(to.err.Error(), "closed") {
		t.Errorf("err = %v", to.err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed pipe") }

// A stale-snapshot note is a warning; any other note is dim (spec §9.2). The note is
// built by estate, so a change of its wording breaks this test.
func TestStaleNotesWarn(t *testing.T) {
	t.Parallel()
	p := palette{on: true}
	stale := estate.StaleNote("2026-09-28T10-00-00Z", 50*time.Hour, 24*time.Hour)
	var b bytes.Buffer
	printNotes(&textOut{w: &b, pal: p}, estate.Target{Notes: []string{stale, "an HA pair"}})
	if want := "  " + p.warn("note: "+stale) + "\n  " + p.dim("note: an HA pair") + "\n"; b.String() != want {
		t.Errorf("got  %q\nwant %q", b.String(), want)
	}
}
