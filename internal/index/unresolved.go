package index

import (
	"fmt"

	"github.com/kaisero/proteus/internal/reason"
)

// Unresolved records something a lookup could not evaluate, and why.
//
// A lookup that returns rules alongside a non-empty Unresolved list has given an
// incomplete answer. This type exists so that incompleteness cannot be mistaken
// for absence: measured on the fw01 configuration, asking for a URL value returned
// nine of ten rules and omitted the only rule naming it, because the nine carry
// "category any" and nothing reported that the URL itself was never evaluated.
type Unresolved struct {
	// Value is what was asked about: a query value, or the object whose contents
	// could not be determined.
	Value string `json:"value"`
	// Kind is the schema object kind involved, empty when the value named no kind.
	Kind string `json:"kind"`
	// Code names the kind of reason.
	Code reason.Code `json:"code"`
	// Reason says why the evaluation could not be completed.
	Reason string `json:"text"`
}

// NewUnresolved returns an entry for value and kind with r's code and text.
func NewUnresolved(value, kind string, r reason.Reason) Unresolved {
	return Unresolved{Value: value, Kind: kind, Reason: r.Text, Code: r.Code}
}

// Why returns the entry's code and text as one reason.
func (u Unresolved) Why() reason.Reason { return reason.Reason{Code: u.Code, Text: u.Reason} }

func (u Unresolved) String() string {
	if u.Kind == "" {
		return fmt.Sprintf("%s: %s", u.Value, u.Reason)
	}
	return fmt.Sprintf("%s (%s): %s", u.Value, u.Kind, u.Reason)
}
