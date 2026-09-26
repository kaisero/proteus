package config

import "fmt"

// Untyped is one element the model could not type, kept so nothing is lost.
// See AGENTS.md R3.
type Untyped struct {
	XPath  string // where it was found
	Digest string // the digest version that did not describe it
}

// Report accompanies a load. It records what the model could not type, so a
// configuration from a newer patch release still loads and the gap stays visible.
type Report struct {
	Untyped []Untyped
}

// HasUnknown reports whether anything went untyped.
func (r Report) HasUnknown() bool { return len(r.Untyped) > 0 }

func (r Report) String() string {
	if !r.HasUnknown() {
		return "no untyped elements"
	}
	return fmt.Sprintf("%d untyped elements, first at %s", len(r.Untyped), r.Untyped[0].XPath)
}
