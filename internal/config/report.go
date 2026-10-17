package config

import "fmt"

// Untyped is one element the model could not type, kept so nothing is lost.
// See AGENTS.md R3.
type Untyped struct {
	XPath string // where it was found
}

// Report accompanies a load. It records what the model could not type, so a
// configuration from a newer release still loads and nothing is lost.
type Report struct {
	Untyped []Untyped
}

// HasUnknown reports whether anything went untyped.
func (r Report) HasUnknown() bool { return len(r.Untyped) > 0 }

func (r Report) String() string {
	s := "no untyped elements"
	if r.HasUnknown() {
		s = fmt.Sprintf("%d untyped elements, first at %s", len(r.Untyped), r.Untyped[0].XPath)
	}
	return s
}
