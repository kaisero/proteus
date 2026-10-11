package mcp

import (
	"encoding/json"
	"strings"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
)

// view is what the text content reads of an envelope, in either detail: the
// JSON both forms share.
type view struct {
	Summary *struct {
		Answer string `json:"answer"`
	} `json:"summary"`
	Results []struct {
		Answer   string `json:"answer"`
		Fidelity *struct {
			Level string `json:"level"`
		} `json:"fidelity"`
		Needs []query.Need `json:"needs"`
	} `json:"results"`
	Holes      []qualifier `json:"holes"`
	Unresolved []qualifier `json:"unresolved"`
	Notes      []qualifier `json:"notes"`
}

// qualifier is a hole, an unresolved entry or a note.
type qualifier struct {
	Device string      `json:"device"`
	Vsys   string      `json:"vsys"`
	Value  string      `json:"value"`
	Code   reason.Code `json:"code"`
	Text   string      `json:"text"`
}

// viewOf reads an envelope's JSON. The envelope is the query layer's own
// JSON form, which always writes; a failure leaves the view empty.
func viewOf(doc any) view {
	var v view
	if b, err := json.Marshal(doc); err == nil {
		_ = json.Unmarshal(b, &v)
	}
	return v
}

// answers are the answer lines: the summary's, then each result's.
func (v view) answers() []string {
	var out []string
	if v.Summary != nil {
		out = append(out, v.Summary.Answer)
	}
	for _, r := range v.Results {
		out = append(out, r.Answer)
	}
	return out
}

// maxVerdict is how many result lines the audit's verdict keeps after the
// summary line: a broad answer keeps its audit line short.
const maxVerdict = 20

// verdict is the audit's verdict: the summary line and the first 20 result
// lines, and the number of answer lines before the cut.
func (v view) verdict() ([]string, int) {
	all := v.answers()
	keep := maxVerdict
	if v.Summary != nil {
		keep++
	}
	return all[:min(keep, len(all))], len(all)
}

// codes are the reason codes of the holes, the unresolved entries and the
// notes, each once, in that order.
func (v view) codes() []reason.Code {
	var out []reason.Code
	seen := map[reason.Code]bool{}
	for _, qs := range [][]qualifier{v.Holes, v.Unresolved, v.Notes} {
		for _, q := range qs {
			if !seen[q.Code] {
				seen[q.Code] = true
				out = append(out, q.Code)
			}
		}
	}
	return out
}

// text is the text content of an answer, for a client that passes only text
// to the model (spec §4.5): per result its answer line, its fidelity level
// and each needs text; then each hole, unresolved entry and note.
func (v view) text() string {
	var b strings.Builder
	line := func(parts ...string) {
		b.WriteString(strings.Join(parts, ""))
		b.WriteByte('\n')
	}
	if v.Summary != nil {
		line(v.Summary.Answer)
	}
	for _, r := range v.Results {
		line(r.Answer)
		if r.Fidelity != nil {
			line("  fidelity: ", r.Fidelity.Level)
		}
		if r.Needs != nil && len(r.Needs) == 0 {
			// Held back, and no second call can change it.
			line("  needs: none; no input can decide this")
		}
		for _, n := range r.Needs {
			line("  needs ", n.Input, ": ", n.Text)
		}
	}
	if len(v.Results) == 0 && v.Summary == nil {
		line("no result")
	}
	for _, h := range v.Holes {
		line("hole: ", where(h), h.Text)
	}
	for _, u := range v.Unresolved {
		value := ""
		if u.Value != "" {
			value = u.Value + ": "
		}
		line("unresolved: ", where(u), value, u.Text)
	}
	for _, n := range v.Notes {
		line("note: ", where(n), n.Text)
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// where names a qualifier's device and vsys: "fw01/vsys1: ", "fw01: ", or
// nothing for the run as a whole.
func where(q qualifier) string {
	switch {
	case q.Device == "":
		return ""
	case q.Vsys == "":
		return q.Device + ": "
	}
	return q.Device + "/" + q.Vsys + ": "
}

// errorText is an error's text content: its code and text, the options and
// each needs text.
func errorText(e *toolError) string {
	lines := []string{string(e.Code) + ": " + e.Text}
	if len(e.Options) > 0 {
		lines = append(lines, "options: "+strings.Join(e.Options, ", "))
	}
	for _, n := range e.Needs {
		lines = append(lines, "needs "+n.Input+": "+n.Text)
	}
	return strings.Join(lines, "\n")
}
