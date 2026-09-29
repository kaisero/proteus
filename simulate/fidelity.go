package simulate

import (
	"encoding/json"
	"slices"
	"strings"
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
	level  level
	reason []string // UnderMatch: why matches may be missing
	skip   []string // NotEvaluated: the dimensions skipped
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

// UnderMatch declares that the output may be missing matches, and why.
func UnderMatch(reason string) Fidelity {
	return Fidelity{level: underMatch, reason: []string{reason}}
}

// NotEvaluated declares that the stage skipped dimensions. Skipping a matching
// dimension can only leave extra rules in the candidate set, so it is OverMatch,
// naming what was skipped.
func NotEvaluated(dimensions ...string) Fidelity {
	return Fidelity{level: overMatch, skip: dimensions}
}

// OverMatchBecause is OverMatch with a reason, such as the rules kept because a
// configuration cannot say whether they match.
func OverMatchBecause(reason string) Fidelity {
	return Fidelity{level: overMatch, reason: []string{reason}}
}

// Declared reports whether the stage said anything at all.
func (f Fidelity) Declared() bool { return f.level != undeclared }

// Level names the level: exact, overmatch, inferred or undermatch.
func (f Fidelity) Level() string { return levelNames[f.level] }

// Skipped lists the dimensions not evaluated.
func (f Fidelity) Skipped() []string { return append([]string{}, f.skip...) }

// Reasons lists why the output is weaker than exact, where a stage said.
func (f Fidelity) Reasons() []string { return append([]string{}, f.reason...) }

func (f Fidelity) String() string {
	s := f.Level()
	if len(f.reason) > 0 {
		s += ": " + strings.Join(f.reason, "; ")
	}
	if len(f.skip) > 0 {
		s += "; not evaluated: " + strings.Join(f.skip, ", ")
	}
	return s
}

// Weakest returns the weakest fidelity: the highest level, with every reason and
// skipped dimension of the inputs, each once. Nothing in is undeclared out.
func Weakest(fs ...Fidelity) Fidelity {
	var out Fidelity
	for _, f := range fs {
		if f.level > out.level {
			out.level = f.level
		}
		for _, r := range f.reason {
			if !slices.Contains(out.reason, r) {
				out.reason = append(out.reason, r)
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

// MarshalJSON writes {"level":…, "reasons":[…], "not_evaluated":[…]}.
func (f Fidelity) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Level        string   `json:"level"`
		Reasons      []string `json:"reasons,omitempty"`
		NotEvaluated []string `json:"not_evaluated,omitempty"`
	}{f.Level(), f.reason, f.skip})
}
