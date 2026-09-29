package routing

import (
	"context"

	"github.com/okaiser/panos-analyst/simulate"
)

// pbf checks the hop's policy-based forwarding rules. Not yet: Task 9.
func pbf(_ context.Context, _ *state) (simulate.Outcome, error) {
	return simulate.Outcome{Fidelity: simulate.NotEvaluated("policy-based forwarding")}, nil
}

// nat checks the hop's NAT rules. Not yet: Task 9.
func nat(_ context.Context, s *state) (simulate.Outcome, error) {
	if s.done {
		return ended, nil
	}
	return simulate.Outcome{Fidelity: simulate.NotEvaluated("NAT")}, nil
}
