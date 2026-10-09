package query

import (
	"cmp"
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
	Source      string `json:"source,omitempty" jsonschema:"an address or a host name; empty starts on device without a source"`
	Destination string `json:"destination" jsonschema:"an address or a host name; a host name is resolved and its first IPv4 address traced"`
	// Protocol is the flow's protocol; empty is tcp. A port given as tcp/443
	// names its own.
	Protocol string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp or sctp; empty for tcp; a port such as udp/53 names its own"`
	// Port decides NAT and PBF rules that name a service: 443 or tcp/443.
	Port string `json:"port,omitempty" jsonschema:"the destination port, 443 or tcp/443; it decides NAT and PBF rules that name a service"`
	// Device names the start, Router its logical router.
	Device string `json:"device,omitempty" jsonschema:"the firewall the path starts on"`
	Router string `json:"router,omitempty" jsonschema:"the start's logical router; needs device"`
	At     string `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; empty for the latest"`
	// RIB lists the routing table's other routes to the destination per hop.
	RIB   bool `json:"rib,omitempty" jsonschema:"list the routing table's other routes to the destination per hop"`
	NoDNS bool `json:"no_dns,omitempty" jsonschema:"leave a host name unresolved"`
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

// flow is routing's flow as asked: TCP unless the protocol or the port names
// another one.
func (in RoutingInput) flow() FlowInput {
	return FlowInput{Source: in.Source, Destination: in.Destination, Protocol: cmp.Or(in.Protocol, "tcp"), Port: in.Port, NoDNS: in.NoDNS}
}

// RoutingResult is simulate routing's result: the path, and the run's fidelity
// and stages. Run is the native run, for a renderer.
type RoutingResult struct {
	Answer string `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Needs  []Need `json:"needs,omitzero" jsonschema:"present when the result is held back: the inputs a second call can give to change it; empty when none helps"`
	routing.Path
	Fidelity simulate.Fidelity `json:"fidelity" jsonschema:"how certain the result is: exact, overmatch, inferred or undermatch, with the reasons; never report undermatch or inferred as a firm answer"`
	Stages   []Stage           `json:"stages" jsonschema:"the run's stages: what each one did, its fidelity and its candidate count"`

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
