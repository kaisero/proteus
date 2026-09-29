package estate

import (
	"sort"

	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// Simulations maps a kind name to its simulation. The registry lives here, a layer
// above simulate, so simulate imports neither its implementations nor the registry
// (spec §11.5). A new kind is one entry, and the command gives it a subcommand.
var Simulations = map[string]simulate.Simulation{
	securitypolicy.Kind: securitypolicy.Simulation{},
	routing.Kind:        routing.Simulation{},
	nat.Kind:            nat.Simulation{},
}

// Kinds lists the registered simulation kinds, sorted.
func Kinds() []string {
	out := make([]string, 0, len(Simulations))
	for k := range Simulations {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
