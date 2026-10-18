package query

import "fmt"

// ResultLimit is the most results an answer of many keeps: findings for
// search, cards for lookup, single changes for snapshot diff. The command
// line's --limit and each MCP tool's limit set this one field. There is no
// default: zero keeps every result.
type ResultLimit struct {
	Limit int `json:"limit,omitempty" jsonschema:"keep only the first N results, in the answer's usual order: findings for search, cards for lookup, single changes for snapshot_diff; the summary's omitted counts the rest. No default: left out, every result is returned"`
}

// checkLimit refuses a limit below zero. Here zero is the field's zero value,
// no limit. The front ends refuse a given 0 themselves, where it would read
// as a limit: the command line in checkLimit, MCP by its input schema.
func (l ResultLimit) checkLimit() *UsageError {
	if l.Limit < 0 {
		return usage(fmt.Sprintf("--limit %d: want 1 or more, or 0 for no limit", l.Limit),
			fmt.Sprintf("limit %d: want 1 or more, or 0 for no limit", l.Limit))
	}
	return nil
}

// cut keeps the first Limit results of a complete, sorted answer, across all
// its targets, and counts the rest in the summary. Holes, unresolved entries
// and notes stay whole.
func cut[In, R any](e *Envelope[In, R], l ResultLimit, narrow string) {
	all := len(e.Results)
	if l.Limit == 0 || all <= l.Limit {
		return
	}
	e.Results = e.Results[:l.Limit]
	leftOut(e.Summary, l.Limit, all, narrow)
}

// leftOut records in the summary that an answer shows shown of its all
// results: omitted counts the rest, and the answer line says how many it
// shows and what narrows the question.
func leftOut(s *Summary, shown, all int, narrow string) {
	s.Omitted = all - shown
	s.Answer += fmt.Sprintf("; %d of %d shown, narrow by %s", shown, all, narrow)
}
