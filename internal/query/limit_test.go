package query

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/simulate/pathlab"
	"github.com/kaisero/proteus/internal/store"
)

// twoLabs is fw01 and fw02, each with the lab configuration, their snapshots
// older than MaxAge: every target carries a stale note.
func twoLabs(t *testing.T) Env {
	t.Helper()
	l := newLab(t)
	l.fetch("fw01", fixture("firewall-lab.xml"))
	l.fetch("fw02", fixture("firewall-lab.xml"))
	env := l.env()
	env.MaxAge = time.Minute
	return env
}

// checkCut compares an answer cut at n with the same answer whole: the first
// n results in the same order, the rest counted in the summary, the answer
// line naming what narrows the question, and the qualifiers whole.
func checkCut[In, R any](t *testing.T, whole, cut Envelope[In, R], n int, narrow string) {
	t.Helper()
	all := len(whole.Results)
	if all <= n {
		t.Fatalf("the whole answer has %d results; the test needs more than %d", all, n)
	}
	if !reflect.DeepEqual(cut.Results, whole.Results[:n]) {
		t.Errorf("results: got %d, want the first %d of %d", len(cut.Results), n, all)
	}
	want := *whole.Summary
	want.Omitted = all - n
	want.Answer += fmt.Sprintf("; %d of %d shown, narrow by %s", n, all, narrow)
	if *cut.Summary != want || whole.Summary.Omitted != 0 {
		t.Errorf("summary %+v, want %+v (whole %+v)", *cut.Summary, want, *whole.Summary)
	}
	if !reflect.DeepEqual(cut.Holes, whole.Holes) || !reflect.DeepEqual(cut.Unresolved, whole.Unresolved) ||
		!reflect.DeepEqual(cut.Notes, whole.Notes) || !reflect.DeepEqual(cut.Read, whole.Read) {
		t.Errorf("qualifiers changed: holes %v, unresolved %v, notes %v", cut.Holes, cut.Unresolved, cut.Notes)
	}
}

// A limit keeps the first findings over every target, in the usual order:
// here it ends inside fw02's findings. Notes stay whole, fw02's too.
func TestSearchLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := twoLabs(t)
	in := SearchInput{Term: "198.18.10.100"}
	whole, err := Search(ctx, env, in)
	if err != nil {
		t.Fatal(err)
	}
	perTarget := whole.Summary.Found / 2
	if len(whole.Notes) != len(whole.Targets) || whole.Summary.With != 2 || perTarget < 1 {
		t.Fatalf("fixture: %+v, %d notes", whole.Summary, len(whole.Notes))
	}
	n := perTarget + 1
	in.Limit = n
	cut, err := Search(ctx, env, in)
	if err != nil {
		t.Fatal(err)
	}
	checkCut(t, whole, cut, n, "device, vsys or kind")
	if last := cut.Results[n-1]; last.Device != "fw02" {
		t.Errorf("the cut ends on %s, want fw02", last.Device)
	}
	if e := cut.Input.Echo(); e.Limit != n {
		t.Errorf("echo limit %d", e.Limit)
	}
	// A limit at or above the count, and none, keep every finding.
	for _, l := range []int{whole.Summary.Found, whole.Summary.Found + 1, 0} {
		in.Limit = l
		e, err := Search(ctx, env, in)
		if err != nil || !reflect.DeepEqual(e.Results, whole.Results) || e.Summary.Omitted != 0 || e.Summary.Answer != whole.Summary.Answer {
			t.Errorf("limit %d: %+v %v", l, e.Summary, err)
		}
	}
}

// A lookup's limit keeps the first cards over every target.
func TestLookupLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := twoLabs(t)
	whole, err := Lookup(ctx, env, LookupInput{Name: "dc01"})
	if err != nil || len(whole.Results) != 2 {
		t.Fatalf("fixture: %+v %v", whole.Summary, err)
	}
	cut, err := Lookup(ctx, env, LookupInput{Name: "dc01", ResultLimit: ResultLimit{Limit: 1}})
	if err != nil {
		t.Fatal(err)
	}
	checkCut(t, whole, cut, 1, "device or vsys")
	if cut.Results[0].Device != "fw01" || cut.Input.Echo().Limit != 1 {
		t.Errorf("%+v", cut.Results[0])
	}
}

// twoChanged is fw01 and fw02, each fetched with the lab configuration and
// then with the changed one; fw01's second snapshot comes from another
// serial. changedFW02 false fetches fw02 unchanged.
func twoChanged(t *testing.T, changedFW02 bool) Env {
	t.Helper()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01", Serial: "000000000001"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01", Serial: "000000000002"}, pathlab.Read(t, fixture("firewall-lab-changed.xml")))
	l.fetch("fw02", fixture("firewall-lab.xml"))
	if changedFW02 {
		l.fetch("fw02", fixture("firewall-lab-changed.xml"))
	} else {
		l.fetch("fw02", fixture("firewall-lab.xml"))
	}
	return l.env()
}

// diffShape is a diff's results as device/scope:changes kept.
func diffShape(e Envelope[DiffInput, DiffResult]) []string {
	var out []string
	for _, r := range e.Results {
		out = append(out, fmt.Sprintf("%s/%s:%d", r.Device, r.Scope, len(r.Changes)))
	}
	return out
}

// A diff counts single changes: found is every change, and the devices with
// and without one are counted apart.
func TestSnapshotDiffCountsChanges(t *testing.T) {
	t.Parallel()
	e, err := SnapshotDiff(context.Background(), twoChanged(t, false), DiffInput{})
	if err != nil {
		t.Fatal(err)
	}
	if s := e.Summary; s.Found != 4 || s.With != 1 || s.Without != 1 || s.Omitted != 0 || s.Answer != "1 with changes, 1 without, 0 holes" {
		t.Errorf("summary %+v", s)
	}
}

// A diff's limit keeps the first single changes over every scope and device.
// The scope where it falls keeps its first changes; its answer keeps the whole
// counts and says how many it shows, and so does its summary form. Later
// scopes drop out. The serial note and a hole stay whole.
func TestSnapshotDiffLimit(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := twoChanged(t, true)
	whole, err := SnapshotDiff(ctx, env, DiffInput{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(diffShape(whole), " "); got != "fw01/shared:0 fw01/vsys:vsys1:4 fw01/vsys:vsys2:0 fw02/shared:0 fw02/vsys:vsys1:4 fw02/vsys:vsys2:0" ||
		whole.Summary.Found != 8 || len(whole.Notes) != 1 {
		t.Fatalf("whole: %s %+v", got, whole.Summary)
	}
	for _, tc := range []struct {
		limit int
		shape string
	}{
		// The cut falls inside fw02's vsys1, past fw01's scopes.
		{5, "fw01/shared:0 fw01/vsys:vsys1:4 fw01/vsys:vsys2:0 fw02/shared:0 fw02/vsys:vsys1:1"},
		// It falls on the end of fw01's vsys1: that scope stays whole.
		{4, "fw01/shared:0 fw01/vsys:vsys1:4"},
		{1, "fw01/shared:0 fw01/vsys:vsys1:1"},
	} {
		e, err := SnapshotDiff(ctx, env, DiffInput{ResultLimit: ResultLimit{Limit: tc.limit}})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(diffShape(e), " "); got != tc.shape {
			t.Errorf("limit %d: %s, want %s", tc.limit, got, tc.shape)
		}
		want := *whole.Summary
		want.Omitted = 8 - tc.limit
		want.Answer += fmt.Sprintf("; %d of 8 shown, narrow by device", tc.limit)
		if *e.Summary != want || !reflect.DeepEqual(e.Notes, whole.Notes) || !reflect.DeepEqual(e.Holes, whole.Holes) || e.Input.Echo().Limit != tc.limit {
			t.Errorf("limit %d: summary %+v, notes %v", tc.limit, *e.Summary, e.Notes)
		}
		last := e.Results[len(e.Results)-1]
		for i, r := range e.Results {
			full := whole.Results[i]
			if !reflect.DeepEqual(r.Changes, full.Changes[:len(r.Changes)]) {
				t.Errorf("limit %d: %s/%s keeps changes out of order", tc.limit, r.Device, r.Scope)
			}
			wantAnswer := full.Answer
			if len(r.Changes) < len(full.Changes) {
				wantAnswer += fmt.Sprintf(" (%d of %d changes shown)", len(r.Changes), len(full.Changes))
			}
			fs := full.Summary()
			ws := DiffSummary{
				Answer: wantAnswer, Device: r.Device, From: r.From, To: r.To, Scope: r.Scope,
				Added: fs.Added, Removed: fs.Removed, Changed: fs.Changed,
			}
			if r.Answer != wantAnswer || r.Summary() != ws {
				t.Errorf("limit %d: %s answer %q, summary %+v", tc.limit, r.Scope, r.Answer, r.Summary())
			}
		}
		if tc.limit == 1 && last.Answer != "fw01/vsys:vsys1: 1 added, 1 removed, 2 changed (1 of 4 changes shown)" {
			t.Errorf("limit 1: %q", last.Answer)
		}
	}
	// A limit at or above the count keeps everything.
	if e, err := SnapshotDiff(ctx, env, DiffInput{ResultLimit: ResultLimit{Limit: 8}}); err != nil || len(e.Results) != 6 || e.Summary.Omitted != 0 {
		t.Errorf("limit 8: %v %+v", err, e.Summary)
	}

	// fw02 of diffLab has one snapshot: a hole, counted on the line.
	e, err := SnapshotDiff(ctx, diffLab(t), DiffInput{ResultLimit: ResultLimit{Limit: 1}})
	if err != nil || len(e.Holes) != 1 || len(e.Notes) != 1 ||
		e.Summary.Answer != fmt.Sprintf("1 with changes, 0 without, 1 holes; 1 of %d shown, narrow by device", e.Summary.Found) {
		t.Errorf("with a hole: %+v %v", e.Summary, err)
	}
}

// A limit below zero is a usage error in the words of each front end; zero is
// no limit.
func TestLimitBelowZero(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	file := Selection{File: fixture("firewall-lab.xml")}
	minus := ResultLimit{Limit: -1}
	_, err := Search(ctx, Env{}, SearchInput{Term: "dc01", Selection: file, ResultLimit: minus})
	usageOK(t, err, "--limit -1: want 1 or more")
	_, err = Lookup(ctx, Env{}, LookupInput{Name: "dc01", Selection: file, ResultLimit: minus})
	usageOK(t, err, "--limit -1: want 1 or more")
	_, err = SnapshotDiff(ctx, diffLab(t), DiffInput{ResultLimit: minus})
	usageOK(t, err, "--limit -1: want 1 or more")
	if u := minus.checkLimit(); u.ToolText != "limit -1: want 1 or more, or 0 for no limit" {
		t.Errorf("tool text %q", u.ToolText)
	}
}
