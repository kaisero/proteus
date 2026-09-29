package resolve

import (
	"slices"

	"github.com/okaiser/proteus/internal/config"
)

// ObjectKinds returns every object kind a configuration can define under a scope and
// that some reference field can name, sorted.
//
// Both halves come from the schema (AGENTS.md R1): FieldKinds says which kinds any
// field may name, and KindContainer says where a kind sits under a scope. A kind
// with no container, such as a predefined category, cannot be defined here.
func ObjectKinds(cfg *config.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, kinds := range cfg.FieldKinds("") {
		for _, k := range kinds {
			if seen[k] {
				continue
			}
			seen[k] = true
			if cfg.KindContainer(k) != nil {
				out = append(out, k)
			}
		}
	}
	slices.Sort(out)
	return out
}
