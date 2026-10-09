package query

import (
	"context"

	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/routing"
)

// RoutingInput is simulate routing: the path a packet takes across the
// inventory's firewalls (spec 2026-09-27 §17).
type RoutingInput struct {
	// Source is an address or an FQDN; "" starts the path on Device with no
	// source.
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	// Port decides NAT and PBF rules that name a service: 443 or tcp/443.
	Port string `json:"port,omitempty"`
	// Device names the start, Router its logical router.
	Device string `json:"device,omitempty"`
	Router string `json:"router,omitempty"`
	At     string `json:"at,omitempty"`
	// RIB lists the routing table's other routes to the destination per hop.
	RIB   bool `json:"rib,omitempty"`
	NoDNS bool `json:"no_dns,omitempty"`
	// Simulated is the flow as simulated; see PolicyInput.
	Simulated simulate.Flow `json:"-"`
}

// Validate holds routing's input rules: a source or a start device, and a port
// that parses.
func (in RoutingInput) Validate() *UsageError {
	if in.Source == "" && in.Device == "" {
		return usage("give a source, or a start device with --device", "give source, or a start device")
	}
	_, u := in.flow().flow()
	return u
}

// flow is routing's flow as asked: TCP unless the port names another protocol.
func (in RoutingInput) flow() FlowInput {
	return FlowInput{Source: in.Source, Destination: in.Destination, Protocol: "tcp", Port: in.Port, NoDNS: in.NoDNS}
}

// RoutingResult is simulate routing's result: the path, and the run's fidelity
// and stages. Run is the native run, for a renderer.
type RoutingResult struct {
	Answer string `json:"answer"`
	Needs  []Need `json:"needs,omitzero"`
	routing.Path
	Fidelity simulate.Fidelity `json:"fidelity"`
	Stages   []Stage           `json:"stages"`

	Run simulate.Run `json:"-"`
}

// Routing traces the path. A start only the caller can choose is a
// *simulate.ChoiceError; a start device that cannot be read is a hole, and the
// answer has no result.
func Routing(ctx context.Context, env Env, in RoutingInput) (Envelope[RoutingInput, RoutingResult], error) {
	var none Envelope[RoutingInput, RoutingResult]
	if u := in.Validate(); u != nil {
		return none, u
	}
	if env.Inventory == nil {
		return none, errNoInventory
	}
	if in.Device != "" {
		if _, err := env.Inventory.Select([]string{in.Device}, nil); err != nil {
			return none, usageOf(err, err.Error(), "")
		}
	}
	flow, _ := in.flow().flow()
	if err := endpoints(ctx, env, &flow, in.Source, in.Destination, in.NoDNS); err != nil {
		return none, err
	}
	es, err := openEstate(env, in.At)
	if err != nil {
		return none, err
	}
	sim := es.simEnv(env)
	sim.Resolve = nil // routing resolves only the endpoints, above
	params := map[string]string{"device": in.Device, "router": in.Router}
	if in.RIB {
		params["rib"] = "true"
	}
	env.Log.Infof(runlog.TagStep, "routing %s -> %s, start %q", flow.Source, flow.Destination, in.Device)
	run, holes, err := runEstate(ctx, routing.Simulation{}, sim, simulate.Input{Flow: flow, Params: params})
	if err != nil {
		return none, err
	}
	in.Simulated = flow
	e := envelope[RoutingInput, RoutingResult]("simulate "+routing.Kind, in)
	e.Holes = holes
	if len(holes) > 0 {
		return e, nil
	}
	path, _ := run.Output.(routing.Path)
	env.Log.Infof(runlog.TagStep, "routing: %s, fidelity %s", path.Outcome, run.Fidelity)
	e.Results = []RoutingResult{{Answer: RoutingAnswer(path), Needs: routingNeeds(flow, path, run.Fidelity), Path: path, Fidelity: run.Fidelity, Stages: SimStages(run.Stages), Run: run}}
	e.Unresolved = dedupeUnresolved(runUnresolved(run, run.Device, "", false))
	for _, h := range path.Hops {
		e.Notes = append(e.Notes, runNotes(h.Device, h.Notes)...)
	}
	e.Notes = append(e.Notes, runNotes(run.Device, path.Notes)...)
	return e, nil
}
