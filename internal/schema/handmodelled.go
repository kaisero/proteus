package schema

// HandModel records a config node the schema does not describe, so it must be
// modelled by hand. See AGENTS.md R8.
type HandModel struct {
	Path   string // the config xpath
	Reason string // why the schema does not describe it
	Owner  string // the Go package that models it
}

// handModelled is the complete list. Adding an entry is a deliberate act: every
// other field in the library comes from the schema (R1).
//
// It is empty. The registry and its check stay, so the next entry is declared
// rather than slipped in.
var handModelled = []HandModel{}

// HandModelled returns the registered hand-modelled nodes.
func HandModelled() []HandModel {
	out := make([]HandModel, len(handModelled))
	copy(out, handModelled)
	return out
}
