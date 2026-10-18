package simulate

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/runlog"
)

type state struct {
	set  *roaring.Bitmap
	seen []string
}

func step(slug string, f Fidelity, keep ...uint32) Step[state] {
	return Step[state]{Name: "Stage " + slug, Slug: slug, Do: func(_ context.Context, s *state) (Outcome, error) {
		s.seen = append(s.seen, slug)
		if keep == nil {
			return Outcome{Fidelity: f, Detail: slug + " done"}, nil
		}
		s.set.And(roaring.BitmapOf(keep...))
		return Outcome{Fidelity: f, Detail: slug + " done", Candidates: s.set, Debug: []string{"kept " + slug}}, nil
	}}
}

func TestStagesRunInOrderAndRecordWhatTheyDid(t *testing.T) {
	t.Parallel()
	s := &state{set: roaring.BitmapOf(1, 2, 3, 4)}
	stages, err := Execute(context.Background(), "demo", s,
		[]Step[state]{step("a", Exact, 1, 2, 3), step("b", Inferred), step("c", NotEvaluated("application"), 2, 3)}, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(s.seen, ",") != "a,b,c" || len(stages) != 3 {
		t.Fatalf("seen %v, stages %d", s.seen, len(stages))
	}
	if stages[0].State.Candidates != 3 || stages[1].State.Candidates != 3 || stages[2].State.Candidates != 2 {
		t.Errorf("counts = %d %d %d; a stage that does not narrow carries the count forward",
			stages[0].State.Candidates, stages[1].State.Candidates, stages[2].State.Candidates)
	}
	if stages[1].Detail != "b done" || stages[0].Slug != "a" || stages[0].Name != "Stage a" {
		t.Errorf("stage = %+v", stages[1])
	}
	if got := Overall(stages).String(); got != "inferred; not evaluated: application" {
		t.Errorf("overall = %s", got)
	}
	if stages[0].State.Bitmap != nil {
		t.Error("bitmaps are kept only when asked")
	}
}

func TestKeptBitmapsAreSnapshots(t *testing.T) {
	t.Parallel()
	s := &state{set: roaring.BitmapOf(1, 2, 3)}
	stages, err := Execute(context.Background(), "demo", s, []Step[state]{step("a", Exact, 1, 2), step("b", Exact, 2)}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stages[0].State.Bitmap.GetCardinality() != 2 || stages[1].State.Bitmap.GetCardinality() != 1 {
		t.Error("a later stage changed an earlier stage's kept bitmap")
	}
}

// An undeclared fidelity is a failed run, surfaced as an error, never a panic.
func TestUndeclaredFidelityFailsTheRun(t *testing.T) {
	t.Parallel()
	s := &state{set: roaring.New()}
	stages, err := Execute(context.Background(), "demo", s, []Step[state]{step("a", Fidelity{}), step("b", Exact)}, false, nil)
	if err == nil || err.Error() != "demo/a: stage declared no fidelity" {
		t.Errorf("err = %v", err)
	}
	if len(stages) != 1 || stages[0].Err == nil || strings.Join(s.seen, ",") != "a" {
		t.Errorf("the run must stop at the failed stage: %+v %v", stages, s.seen)
	}
}

func TestAStepErrorIsWrapped(t *testing.T) {
	t.Parallel()
	boom := Step[state]{Slug: "x", Do: func(context.Context, *state) (Outcome, error) { return Outcome{}, errors.New("boom") }}
	_, err := Execute(context.Background(), "demo", &state{}, []Step[state]{boom, step("y", Exact)}, false, nil)
	if err == nil || err.Error() != "demo/x: boom" {
		t.Errorf("err = %v", err)
	}
}

func TestACancelledContextRunsNothing(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &state{}
	if _, err := Execute(ctx, "demo", s, []Step[state]{step("a", Exact)}, false, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if len(s.seen) != 0 {
		t.Error("a step ran after cancellation")
	}
}

// Each stage is one STEP line at info; what explains it is at debug.
func TestStagesAreLogged(t *testing.T) {
	t.Parallel()
	l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "sim", Level: runlog.Debug})
	if err != nil {
		t.Fatal(err)
	}
	bad := Step[state]{Slug: "z", Do: func(context.Context, *state) (Outcome, error) { return Outcome{}, errors.New("broke") }}
	gap := Step[state]{Slug: "u", Do: func(context.Context, *state) (Outcome, error) {
		return Outcome{Fidelity: under("gap"), Unresolved: []index.Unresolved{{Value: "v", Reason: "a gap"}}}, nil
	}}
	_, _ = Execute(context.Background(), "demo", &state{set: roaring.BitmapOf(1, 2)}, []Step[state]{step("a", Exact, 1), gap, bad}, false, l)
	(&Env{Log: l}).Stepf("hop%d: between stages", 1)
	(&Env{}).Stepf("no log, no line")
	_ = l.Close()
	b, _ := os.ReadFile(l.Path())
	for _, want := range []string{"[INFO] [STEP] demo/a: exact, 1 candidates", "[DEBUG] [STEP] demo/a: kept a", "[ERROR] [STEP] demo/z: failed: broke", "[INFO] [STEP] demo/u: unresolved: v: a gap", "[INFO] [STEP] hop1: between stages"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %q in:\n%s", want, b)
		}
	}
}

func TestEndpoint(t *testing.T) {
	t.Parallel()
	a := Addr(netip.MustParseAddr("10.0.0.1"))
	if a.String() != "10.0.0.1" || (Endpoint{Name: "x.example"}).String() != "x.example" || (Endpoint{}).String() != "" {
		t.Error("Endpoint.String")
	}
}
