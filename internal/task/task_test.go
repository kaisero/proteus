package task

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/runlog"
)

type counter struct{ n int }

func step(slug string, r Result, err error) Step[counter] {
	return Step[counter]{Name: slug, Slug: slug, Do: func(_ context.Context, c *counter) (Result, error) {
		c.n++
		return r, err
	}}
}

func TestRunRecordsEveryStepInOrder(t *testing.T) {
	t.Parallel()
	var seen []string
	c := &counter{}
	recs, err := Run(context.Background(), "fw1", c, []Step[counter]{
		step("a", Result{Detail: "one"}, nil),
		step("b", Result{Status: Partial, Notes: []reason.Reason{reason.New("note.ha-binding", "n")}}, nil),
	}, Options{OnStep: func(kind string, r Record) { seen = append(seen, kind+"/"+r.Slug+" "+string(r.Status)) }})
	if err != nil || c.n != 2 || len(recs) != 2 {
		t.Fatalf("err %v, ran %d, records %d", err, c.n, len(recs))
	}
	if recs[0].Status != OK || recs[0].Detail != "one" || recs[1].Status != Partial || recs[1].Notes[0].Text != "n" {
		t.Errorf("records = %+v", recs)
	}
	if strings.Join(seen, ",") != "fw1/a ok,fw1/b partial" {
		t.Errorf("OnStep saw %v", seen)
	}
}

func TestRunStopsAtTheFirstError(t *testing.T) {
	t.Parallel()
	c := &counter{}
	boom := errors.New("boom")
	var onStep []Record
	recs, err := Run(context.Background(), "fw1", c, []Step[counter]{
		step("a", Result{}, nil), step("b", Result{}, boom), step("c", Result{}, nil),
	}, Options{OnStep: func(_ string, r Record) { onStep = append(onStep, r) }})
	if !errors.Is(err, boom) || err.Error() != "fw1/b: boom" || c.n != 2 {
		t.Fatalf("err %v, ran %d", err, c.n)
	}
	if last := recs[len(recs)-1]; last.Status != Failed || !errors.Is(last.Err, boom) {
		t.Errorf("last record = %+v", last)
	}
	if len(onStep) != 2 {
		t.Fatalf("OnStep called %d times, want 2", len(onStep))
	}
	if last := onStep[len(onStep)-1]; last.Status != Failed || !errors.Is(last.Err, boom) {
		t.Errorf("OnStep last call = %+v", last)
	}
}

func TestRunStopsWhenCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	c := &counter{}
	recs, err := Run(ctx, "fw1", c, []Step[counter]{
		{Name: "a", Slug: "a", Do: func(context.Context, *counter) (Result, error) { cancel(); return Result{}, nil }},
		step("b", Result{}, nil),
	}, Options{})
	if !errors.Is(err, context.Canceled) || err.Error() != "fw1/b: context canceled" || len(recs) != 1 {
		t.Errorf("err %v, records %d", err, len(recs))
	}
}

func TestRunLogs(t *testing.T) {
	t.Parallel()
	l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "fetch", Level: runlog.Debug})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = Run(context.Background(), "fw1", &counter{}, []Step[counter]{
		step("a", Result{Detail: "done", Debug: []string{"why"}}, nil),
		step("b", Result{}, errors.New("boom")),
	}, Options{Log: l})
	_ = l.Close()
	b, _ := os.ReadFile(l.Path())
	for _, want := range []string{"[INFO] [STEP] fw1/a: ok ", " - done", "[DEBUG] [STEP] fw1/a: why", "[ERROR] [STEP] fw1/b: failed: boom"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("log misses %q:\n%s", want, b)
		}
	}
}
