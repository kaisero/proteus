package simulate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestWeakestFollowsTheOrder(t *testing.T) {
	for _, tc := range []struct {
		in   []Fidelity
		want string
	}{
		{[]Fidelity{Exact, Exact}, "exact"},
		{[]Fidelity{Exact, OverMatch}, "overmatch"},
		{[]Fidelity{OverMatch, Inferred}, "inferred"},
		{[]Fidelity{Inferred, UnderMatch("x"), Exact}, "undermatch"},
		{nil, "undeclared"},
	} {
		if got := Weakest(tc.in...).Level(); got != tc.want {
			t.Errorf("Weakest(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// Not evaluating a dimension can only add candidates, so it is OverMatch, and a run
// that skips application is not reported as knowing nothing.
func TestNotEvaluatedIsOverMatchWithDimensions(t *testing.T) {
	f := NotEvaluated("application", "service")
	if f.Level() != "overmatch" || strings.Join(f.Skipped(), ",") != "application,service" {
		t.Errorf("got %s %v", f.Level(), f.Skipped())
	}
	w := Weakest(NotEvaluated("application"), Exact, NotEvaluated("application", "url category"))
	if strings.Join(w.Skipped(), ",") != "application,url category" {
		t.Errorf("dimensions must merge once each: %v", w.Skipped())
	}
	if Weakest(NotEvaluated("application"), Inferred).Level() != "inferred" {
		t.Error("inferred is weaker than a skipped dimension")
	}
}

func TestReasonsMerge(t *testing.T) {
	w := Weakest(UnderMatch("a"), UnderMatch("b"), UnderMatch("a"), OverMatchBecause("c"))
	if strings.Join(w.Reasons(), ";") != "a;b;c" {
		t.Errorf("reasons = %v", w.Reasons())
	}
	if !strings.HasPrefix(w.String(), "undermatch: a; b; c") {
		t.Errorf("String = %s", w)
	}
}

func TestDeclaredAndString(t *testing.T) {
	if (Fidelity{}).Declared() || !Exact.Declared() {
		t.Error("the zero value is undeclared")
	}
	for f, want := range map[string]string{
		Exact.String():                          "exact",
		Inferred.String():                       "inferred",
		NotEvaluated("application").String():    "overmatch; not evaluated: application",
		UnderMatch("a version gap").String():    "undermatch: a version gap",
		OverMatchBecause("predefined").String(): "overmatch: predefined",
	} {
		if f != want {
			t.Errorf("got %q, want %q", f, want)
		}
	}
}

func TestFidelityJSON(t *testing.T) {
	b, err := json.Marshal(Weakest(UnderMatch("x"), NotEvaluated("application")))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"level":"undermatch","reasons":["x"],"not_evaluated":["application"]}` {
		t.Errorf("json = %s", b)
	}
	b, _ = json.Marshal(Exact)
	if string(b) != `{"level":"exact"}` {
		t.Errorf("json = %s", b)
	}
}
