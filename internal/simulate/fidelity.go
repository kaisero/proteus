package simulate

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/reason"
)

// level orders how certain an output is, strongest first. The zero value is
// "undeclared", which the stepper refuses.
type level int

const (
	undeclared level = iota
	exact
	overMatch
	inferred
	underMatch
)

var levelNames = map[level]string{
	undeclared: "undeclared", exact: "exact", overMatch: "overmatch",
	inferred: "inferred", underMatch: "undermatch",
}

// Fidelity is how certain a stage's output is. Every stage declares one; a run's
// is the weakest of its stages', computed rather than asserted. Spec §11.2.
//
// The order, strongest first: Exact, OverMatch, Inferred, UnderMatch. OverMatch
// may hold more than the device would match, which is safe for a candidate set.
// Inferred came from data the device may not be using and can be wrong either way.
// UnderMatch may be missing matches, the most dangerous for a verdict.
type Fidelity struct {
	level level
	// why says why the output is weaker than exact, at any level; under holds
	// the reasons given at UnderMatch, a subset of why. Each entry is one
	// reason as given: one part, or the parts of a composite reason, which read
	// as one, joined with "; ".
	why   []Reasons
	under []Reasons
	skip  []reason.Reason // NotEvaluated: the dimensions skipped, as text with their codes
}

var (
	// Exact means the output is what the device would compute.
	Exact = Fidelity{level: exact}
	// OverMatch means the output may hold more than the device would match.
	OverMatch = Fidelity{level: overMatch}
	// Inferred means the output came from data the device may not be using, such as a zone
	// predicted from a forwarding table rather than read off the arrival interface.
	Inferred = Fidelity{level: inferred}
)

// UnderMatch declares that the output may be missing matches, and why: one
// reason, or the parts of a composite one, each with its own code.
func UnderMatch(rs ...reason.Reason) Fidelity {
	f := Fidelity{level: underMatch}
	if len(rs) > 0 {
		f.why, f.under = []Reasons{slices.Clone(rs)}, []Reasons{slices.Clone(rs)}
	}
	return f
}

// NotEvaluated declares that the stage skipped dimensions. Skipping a matching
// dimension can only leave extra rules in the candidate set, so it is OverMatch,
// naming what was skipped.
func NotEvaluated(dimensions ...string) Fidelity {
	var skip []reason.Reason
	for _, d := range dimensions {
		skip = append(skip, reason.New(dimensionCodes[d], d))
	}
	return Fidelity{level: overMatch, skip: skip}
}

// dimensionCodes gives each dimension a stage can skip its code (spec §12 C7). A
// dimension missing here fails every test that skips it.
var dimensionCodes = map[string]reason.Code{
	"zones":                   "doubt.not-evaluated.zones",
	"source zone":             "doubt.not-evaluated.source-zone",
	"destination zone":        "doubt.not-evaluated.destination-zone",
	"service":                 "doubt.not-evaluated.service",
	"url category":            "doubt.not-evaluated.url",
	"application":             "doubt.not-evaluated.application",
	"user":                    "doubt.not-evaluated.user",
	"NAT":                     "doubt.not-evaluated.nat",
	"policy-based forwarding": "doubt.not-evaluated.pbf",
}

// OverMatchBecause is OverMatch with a reason, such as the rules kept because a
// configuration cannot say whether they match.
func OverMatchBecause(r reason.Reason) Fidelity {
	return Fidelity{level: overMatch, why: []Reasons{{r}}}
}

// Declared reports whether the stage said anything at all.
func (f Fidelity) Declared() bool { return f.level != undeclared }

// Level names the level: exact, overmatch, inferred or undermatch.
func (f Fidelity) Level() string { return levelNames[f.level] }

// Skipped lists the dimensions not evaluated.
func (f Fidelity) Skipped() []string { return texts(f.skip) }

// SkippedReasons lists the dimensions not evaluated, each with its code.
func (f Fidelity) SkippedReasons() Reasons { return slices.Clone(f.skip) }

// Reasons lists why the output is weaker than exact, where a stage said.
func (f Fidelity) Reasons() Reasons { return flat(f.why) }

// UnderMatchReasons lists only the reasons given at UnderMatch: why matches may
// be missing. Weakest keeps the reasons of every level, so an undermatch can also
// carry an overmatch reason that says nothing about what is missing.
func (f Fidelity) UnderMatchReasons() Reasons { return flat(f.under) }

// UnderMatchGroups lists the reasons given at UnderMatch as given: each a
// reason, or the parts of a composite one.
func (f Fidelity) UnderMatchGroups() []Reasons {
	out := make([]Reasons, 0, len(f.under))
	for _, g := range f.under {
		out = append(out, slices.Clone(g))
	}
	return out
}

// flat lists the parts of every reason in order; nil for none.
func flat(gs []Reasons) Reasons {
	var out Reasons
	for _, g := range gs {
		out = append(out, g...)
	}
	return out
}

func (f Fidelity) String() string {
	s := f.Level()
	if len(f.why) > 0 {
		s += ": " + flat(f.why).Text()
	}
	if len(f.skip) > 0 {
		s += "; not evaluated: " + strings.Join(texts(f.skip), ", ")
	}
	return s
}

// texts lists the texts of rs, nil for none.
func texts(rs []reason.Reason) []string { return Reasons(rs).Texts() }

// sameText matches a reason with r's text: a composite's reads as its parts
// joined.
func sameText(r Reasons) func(Reasons) bool {
	return func(o Reasons) bool { return o.Text() == r.Text() }
}

// Weakest returns the weakest fidelity: the highest level, with every reason and
// skipped dimension of the inputs, each once. Nothing in is undeclared out.
func Weakest(fs ...Fidelity) Fidelity {
	var out Fidelity
	for _, f := range fs {
		if f.level > out.level {
			out.level = f.level
		}
		// Reasons are the same when their texts are: the text reads the
		// same twice, so the first code stays.
		for _, r := range f.why {
			if !slices.ContainsFunc(out.why, sameText(r)) {
				out.why = append(out.why, r)
			}
		}
		for _, r := range f.under {
			if !slices.ContainsFunc(out.under, sameText(r)) {
				out.under = append(out.under, r)
			}
		}
		for _, d := range f.skip {
			if !slices.Contains(out.skip, d) {
				out.skip = append(out.skip, d)
			}
		}
	}
	return out
}

// MarshalJSON writes {"level":…, "reasons":[{"code","text"}…],
// "not_evaluated":[…]}: each reason with its code, each skipped dimension by
// name (spec 2026-10-09 §3.2).
func (f Fidelity) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Level        string          `json:"level"`
		Reasons      []reason.Reason `json:"reasons,omitempty"`
		NotEvaluated []string        `json:"not_evaluated,omitempty"`
	}{f.Level(), flat(f.why), texts(f.skip)})
}
