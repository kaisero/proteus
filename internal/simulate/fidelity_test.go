package simulate

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/reason"
)

// under and over are reasons for tests; their code is a valid one.
func under(text string) Fidelity { return UnderMatch(reason.New("gap.object-unresolved", text)) }
func over(text string) Fidelity  { return OverMatchBecause(reason.New("doubt.service-kept", text)) }

func TestWeakestFollowsTheOrder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   []Fidelity
		want string
	}{
		{[]Fidelity{Exact, Exact}, "exact"},
		{[]Fidelity{Exact, OverMatch}, "overmatch"},
		{[]Fidelity{OverMatch, Inferred}, "inferred"},
		{[]Fidelity{Inferred, under("x"), Exact}, "undermatch"},
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
	t.Parallel()
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
	t.Parallel()
	w := Weakest(under("a"), under("b"), under("a"), over("c"))
	if strings.Join(w.Reasons().Texts(), ";") != "a;b;c" {
		t.Errorf("reasons = %v", w.Reasons())
	}
	if !strings.HasPrefix(w.String(), "undermatch: a; b; c") {
		t.Errorf("String = %s", w)
	}
	// Only the undermatch reasons say what may be missing; c is an overmatch's.
	if strings.Join(w.UnderMatchReasons().Texts(), ";") != "a;b" {
		t.Errorf("undermatch reasons = %v", w.UnderMatchReasons())
	}
}

func TestDeclaredAndString(t *testing.T) {
	t.Parallel()
	if (Fidelity{}).Declared() || !Exact.Declared() {
		t.Error("the zero value is undeclared")
	}
	for f, want := range map[string]string{
		Exact.String():                       "exact",
		Inferred.String():                    "inferred",
		NotEvaluated("application").String(): "overmatch; not evaluated: application",
		under("a missing table").String():    "undermatch: a missing table",
		over("predefined").String():          "overmatch: predefined",
	} {
		if f != want {
			t.Errorf("got %q, want %q", f, want)
		}
	}
}

func TestFidelityJSON(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(Weakest(under("x"), NotEvaluated("application")))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"level":"undermatch","reasons":[{"code":"gap.object-unresolved","text":"x"}],"not_evaluated":["application"]}` {
		t.Errorf("json = %s", b)
	}
	b, _ = json.Marshal(Exact)
	if string(b) != `{"level":"exact"}` {
		t.Errorf("json = %s", b)
	}
}

// Every reason keeps its code through Weakest.
func TestReasonsKeepTheirCodes(t *testing.T) {
	t.Parallel()
	w := Weakest(under("a"), over("c"), NotEvaluated("application", "url category"))
	var codes []reason.Code
	for _, r := range w.Reasons() {
		codes = append(codes, r.Code)
	}
	if !slices.Equal(codes, []reason.Code{"gap.object-unresolved", "doubt.service-kept"}) {
		t.Errorf("codes = %v", codes)
	}
	want := []reason.Reason{
		{Code: "doubt.not-evaluated.application", Text: "application"},
		{Code: "doubt.not-evaluated.url", Text: "url category"},
	}
	if got := w.SkippedReasons(); !slices.Equal(got, want) {
		t.Errorf("skipped = %v", got)
	}
}

// Every dimension a stage skips has its own registered code (spec §12 C7).
func TestEveryDimensionHasACode(t *testing.T) {
	t.Parallel()
	dims := []string{
		"zones", "source zone", "destination zone", "service", "url category",
		"application", "user", "NAT", "policy-based forwarding",
	}
	if len(dimensionCodes) != len(dims) {
		t.Errorf("%d codes for %d dimensions", len(dimensionCodes), len(dims))
	}
	for _, d := range dims {
		if c := dimensionCodes[d]; !reason.Known(c) {
			t.Errorf("%s: code %q is not registered", d, c)
		}
	}
}

func TestReasonsList(t *testing.T) {
	t.Parallel()
	rs := Reasons{reason.New("doubt.edl", "a"), reason.New("doubt.region", "b")}
	if got := rs.Prefixed("source: "); got.Text() != "source: a; b" || got[1].Code != "doubt.region" {
		t.Errorf("prefixed = %v", got)
	}
	if rs[0].Text != "a" {
		t.Error("Prefixed changed its receiver")
	}
	if j := rs.Joined(); j != (reason.Reason{Code: "doubt.edl", Text: "a; b"}) {
		t.Errorf("joined = %v", j)
	}
	if j := (Reasons{}).Joined(); j != (reason.Reason{}) {
		t.Errorf("joined of none = %v", j)
	}
	if got := (Reasons{}).Prefixed("x"); len(got) != 0 {
		t.Errorf("prefixed of none = %v", got)
	}
	for _, tc := range []struct {
		in   Reasons
		want string
	}{{nil, "null"}, {Reasons{}, "[]"}, {rs, `[{"code":"doubt.edl","text":"a"},{"code":"doubt.region","text":"b"}]`}} {
		if b, err := json.Marshal(tc.in); err != nil || string(b) != tc.want {
			t.Errorf("json of %v = %s, %v", tc.in, b, err)
		}
	}
}

func TestMissingKeepsItsCode(t *testing.T) {
	t.Parallel()
	r := reason.New("gap.config-missing", "no configuration")
	m := NewMissing("fw01", r)
	if m.Device != "fw01" || m.Reason != r.Text || m.Why() != r {
		t.Errorf("missing = %+v", m)
	}
}

// Two reasons with one text read the same twice: they are one, and the first
// code stays.
func TestWeakestKeepsATextOnce(t *testing.T) {
	t.Parallel()
	a := UnderMatch(reason.New("gap.object-unresolved", "same"))
	b := UnderMatch(reason.New("gap.load-failed", "same"))
	got := Weakest(a, b)
	if rs := got.Reasons(); len(rs) != 1 || rs[0].Code != "gap.object-unresolved" {
		t.Errorf("reasons %v", rs)
	}
	if rs := got.UnderMatchReasons(); len(rs) != 1 {
		t.Errorf("under %v", rs)
	}
}

// A loader's coded error keeps the failure's kind.
func TestCodedError(t *testing.T) {
	t.Parallel()
	var err error = &CodedError{Reason: reason.New("gap.config-missing", "fw01/vsys1: no configuration")}
	var coded interface{ Code() reason.Code }
	if !errors.As(err, &coded) || coded.Code() != "gap.config-missing" || err.Error() != "fw01/vsys1: no configuration" {
		t.Errorf("%v", err)
	}
}

// A composite reason keeps its parts, each with its code, and reads as one: its
// text, its sameness in Weakest, and its group (spec 2026-10-09 §3.2).
func TestACompositeReasonKeepsItsParts(t *testing.T) {
	t.Parallel()
	a, b := reason.New("doubt.edl", "r at 1 may match first: source: external list (x)"), reason.New("doubt.region", "region (AT)")
	f := Weakest(UnderMatch(a, b), UnderMatch(a, b), UnderMatch(reason.New("gap.load-failed", "other")))
	if got := f.String(); got != "undermatch: r at 1 may match first: source: external list (x); region (AT); other" {
		t.Errorf("string = %s", got)
	}
	if g := f.UnderMatchGroups(); len(g) != 2 || len(g[0]) != 2 || g[0][1] != b {
		t.Errorf("groups = %v", g)
	}
	if rs := f.UnderMatchReasons(); len(rs) != 3 || rs[1].Code != "doubt.region" {
		t.Errorf("parts = %v", rs)
	}
	if u := UnderMatch(); u.Level() != "undermatch" || len(u.Reasons()) != 0 {
		t.Errorf("no reason: %v", u)
	}
}
