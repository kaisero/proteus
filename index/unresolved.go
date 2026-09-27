package index

import "fmt"

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
	Value string
	// Kind is the schema object kind involved, empty when the value named no kind.
	Kind string
	// Reason says why the evaluation could not be completed.
	Reason string
}

func (u Unresolved) String() string {
	if u.Kind == "" {
		return fmt.Sprintf("%s: %s", u.Value, u.Reason)
	}
	return fmt.Sprintf("%s (%s): %s", u.Value, u.Kind, u.Reason)
}
