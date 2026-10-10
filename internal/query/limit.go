package query

import "fmt"

// ResultLimit is the most results an answer of many keeps: search, lookup and
// snapshot diff. The command line's --limit and each MCP tool's limit set this
// one field. There is no default: zero keeps every result.
type ResultLimit struct {
	Limit int `json:"limit,omitempty" jsonschema:"keep only the first N results, in the answer's usual order; the summary's omitted counts the rest. No default: left out, every result is returned"`
}

// checkLimit refuses a limit below zero; zero is no limit.
func (l ResultLimit) checkLimit() *UsageError {
	if l.Limit < 0 {
		return usage(fmt.Sprintf("--limit %d: want 1 or more", l.Limit), fmt.Sprintf("limit %d: want 1 or more", l.Limit))
	}
	return nil
}

// cut keeps the first Limit results of a complete, sorted answer, across all
// its targets, and counts the rest in the summary. The answer line then says
// how many it shows and what narrows the question. Holes, unresolved entries
// and notes stay whole.
func cut[In, R any](e *Envelope[In, R], l ResultLimit, narrow string) {
	all := len(e.Results)
	if l.Limit == 0 || all <= l.Limit {
		return
	}
	e.Results = e.Results[:l.Limit]
	e.Summary.Omitted = all - l.Limit
	e.Summary.Answer += fmt.Sprintf("; %d of %d shown, narrow by %s", l.Limit, all, narrow)
}
