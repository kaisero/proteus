package fetch

import "github.com/okaiser/proteus/internal/reason"

// Outcome is what happened to one document.
type Outcome struct {
	Name  string
	Bytes int
	Err   error
}

// Result is one device's fetch: the documents that arrived and what happened to
// every document asked for.
type Result struct {
	Device   string
	Host     string
	Docs     map[string][]byte
	Outcomes []Outcome
	System   System
	// FetchedFrom is the host that answered when it is not the device's own: the
	// active peer of a device found passive (the ha step).
	FetchedFrom string
	// Notes say what a reader of the snapshot should know, such as an HA state that
	// was not followed.
	Notes []reason.Reason
}

// OK reports whether a document arrived.
func (r Result) OK(name string) bool {
	for _, o := range r.Outcomes {
		if o.Name == name {
			return o.Err == nil
		}
	}
	return false
}
