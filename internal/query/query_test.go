package query

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/estate"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/store"
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

// The qualifier constructors keep the reason's code, and JSON writes it
// (format 2). A composite's later parts are marked as parts.
func TestQualifiersCarryTheCode(t *testing.T) {
	t.Parallel()
	r := reason.New("note.snapshot-stale", "old")
	n, u := NoteOf("fw01", "vsys1", r), UnresolvedOf("fw01", "", r)
	if n.Code != r.Code || n.Note != "old" || u.Code != r.Code || u.Reason != "old" {
		t.Errorf("%+v %+v", n, u)
	}
	b, err := json.Marshal([]any{n, u})
	if err != nil || string(b) != `[{"device":"fw01","vsys":"vsys1","code":"note.snapshot-stale","text":"old"},{"device":"fw01","code":"note.snapshot-stale","text":"old"}]` {
		t.Errorf("%s %v", b, err)
	}
	parts := UnresolvedOfParts("fw01", "vsys1", simulate.Reasons{r, reason.New("gap.load-failed", "new")})
	if len(parts) != 2 || parts[0].Part || !parts[1].Part || parts[1].Code != "gap.load-failed" {
		t.Errorf("parts %+v", parts)
	}
	// A composite goes or stays whole: here the second is a copy of the first.
	un := dedupeUnresolved(append(append(parts, UnresolvedOf("fw01", "vsys1", r)), parts...))
	if len(un) != 3 {
		t.Errorf("dedupe %+v", un)
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

// DocOf gives the JSON form: the input block from the input, every list [] when
// empty, the summary only where the envelope has one.
func TestDocOfPrintsEmptyLists(t *testing.T) {
	t.Parallel()
	e := envelope[DiffInput, DiffResult]("snapshot diff", DiffInput{Selection: Selection{Device: []string{"fw01"}}, To: "2026-09-28"})
	b, err := json.Marshal(DocOf(e))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"format":2,"command":"snapshot diff","detail":"full","input":{"from":"","limit":0,"selection":{"device":["fw01"]},"to":"2026-09-28"},` +
		`"results":[],"holes":[],"unresolved":[],"notes":[]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

// Each input gives its command's input block.
func TestEchoes(t *testing.T) {
	t.Parallel()
	flow := simulate.Flow{Protocol: "tcp", DestPort: 443}
	sel := Selection{File: "f.xml"}
	for _, tc := range []struct {
		got  any
		want string
	}{
		{PolicyFileInput{Selection: sel, Simulated: flow}.Echo(), `"selection":{"file":"f.xml"}`},
		{PolicyInput{Device: "fw01", Router: "r1", At: "x", Simulated: flow}.Echo(), `{"mode":"path",`},
		{RoutingInput{Device: "fw01", RIB: true, Simulated: flow}.Echo(), `"rib":true`},
		{NATInput{Device: "fw01", FromZone: "z", FromInterface: "i", Simulated: flow}.Echo(), `"from_interface":"i","from_zone":"z"`},
		{SearchInput{Term: "198.18.1.10", Selection: sel}.Echo(), `"mode":"covers"`},
		{LookupInput{Name: "web", Kind: "address", Selection: sel}.Echo(), `"kind":"address","limit":0,"name":"web"`},
		{SearchInput{Term: "web", ResultLimit: ResultLimit{Limit: 5}}.Echo(), `"limit":5,`},
		{DiffInput{ResultLimit: ResultLimit{Limit: 2}}.Echo(), `"limit":2,`},
	} {
		b, err := json.Marshal(tc.got)
		if err != nil || !strings.Contains(string(b), tc.want) {
			t.Errorf("%T: %s %v, want %s", tc.got, b, err, tc.want)
		}
	}
}

// The merge of the pushed template adds template values and changes no local
// node (spec 2026-10-17 §2.5): for each name of firewall-lab.xml, search and
// lookup answer the same on the fixture and on its merge, the synthetic
// template copy of net-home included. The template's zone is found on the
// merge only.
func TestMergedAnswersEqualOnLocalNodes(t *testing.T) {
	t.Parallel()
	lab, merged := fixture("firewall-lab.xml"), fixture("firewall-lab-merged.xml")
	cfg, _, err := config.Load(lab)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	var walk func(el *config.Element)
	walk = func(el *config.Element) {
		if n := el.Attr("name"); n != "" && el.Name == "entry" {
			names = append(names, n)
		}
		for _, c := range el.Children {
			walk(c)
		}
	}
	walk(cfg.Root())
	if len(names) < 10 {
		t.Fatalf("names: %v", names)
	}
	answer := func(file, name string) string {
		s, err := Search(context.Background(), Env{}, SearchInput{Term: name, Selection: Selection{File: file}})
		if err != nil {
			t.Fatal(err)
		}
		l, err := Lookup(context.Background(), Env{}, LookupInput{Name: name, Selection: Selection{File: file}})
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal([]any{s.Results, s.Unresolved, s.Summary, l.Results, l.Unresolved, l.Summary})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, name := range names {
		if a, b := answer(lab, name), answer(merged, name); a != b {
			t.Errorf("%s: the answers differ\nfixture %s\nmerge   %s", name, a, b)
		}
	}
	zone := func(file string) int {
		s, err := Search(context.Background(), Env{}, SearchInput{Term: "tpl-zone", Selection: Selection{File: file}})
		if err != nil {
			t.Fatal(err)
		}
		return len(s.Results)
	}
	if zone(lab) != 0 || zone(merged) == 0 {
		t.Errorf("tpl-zone: %d findings on the fixture, %d on the merge", zone(lab), zone(merged))
	}
}
