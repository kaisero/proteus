package query

import (
	"context"
	"time"

	"github.com/kaisero/proteus/internal/runlog"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/nat"
)

// NATInput is simulate nat: one firewall, a flow, and optionally the ingress
// (spec 2026-09-27 §18 N8).
type NATInput struct {
	// Flow is the packet. A source of "" or "-" is any source. The flow's zones
	// are not read: FromZone or FromInterface sets the ingress, and the stored
	// forwarding table gives the rest.
	Flow FlowInput `json:"flow" jsonschema:"the packet; a source of \"\" or \"-\" is any source"`
	// Device is the firewall; Router its logical router when it has several.
	Device        string `json:"device" jsonschema:"the firewall"`
	Router        string `json:"router,omitempty" jsonschema:"its logical router when it has several"`
	FromZone      string `json:"from_zone,omitempty" jsonschema:"the ingress zone; excludes from_interface"`
	FromInterface string `json:"from_interface,omitempty" jsonschema:"the ingress interface; excludes from_zone"`
	At            string `json:"at,omitempty" jsonschema:"read the newest snapshot at or before this time; empty for the latest"`
	// Simulated is the flow as simulated; see PolicyInput.
	Simulated simulate.Flow `json:"-"`
}

// Validate holds NAT's input rules: a device, at most one of the ingress zone
// and interface, and ports that parse.
func (in NATInput) Validate() *UsageError {
	if in.Device == "" {
		return usage("give the firewall with --device", "give device")
	}
	if in.FromZone != "" && in.FromInterface != "" {
		return usage("--from-zone and --from-interface exclude each other", "from_zone and from_interface exclude each other")
	}
	_, u := in.Flow.flow()
	return u
}

// NATResult is simulate nat's result: the matching rule and the translated
// packet, and the run's fidelity and stages. Run and TakenAt are the native run
// and the snapshot's time, for a renderer.
type NATResult struct {
	Answer string `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Needs  []Need `json:"needs,omitzero" jsonschema:"present when the result is held back: the inputs a second call can give to change it; empty when none helps"`
	nat.Result
	Fidelity simulate.Fidelity `json:"fidelity" jsonschema:"how certain the result is: exact, overmatch, inferred or undermatch, with the reasons; never report undermatch or inferred as a firm answer"`
	Stages   []Stage           `json:"stages" jsonschema:"the run's stages: what each one did, its fidelity and its candidate count"`

	Run     simulate.Run `json:"-"`
	TakenAt time.Time    `json:"-"`
}

// NAT names the NAT rule a packet hits on one firewall and the packet after
// translation. A device that cannot be read is a hole, and the answer has no
// result; a choice only the caller can make is a *simulate.ChoiceError.
func NAT(ctx context.Context, env Env, in NATInput) (Envelope[NATInput, NATResult], error) {
	var none Envelope[NATInput, NATResult]
	if u := in.Validate(); u != nil {
		return none, u
	}
	if env.Inventory == nil {
		return none, errNoInventory
	}
	if _, err := env.Inventory.Select([]string{in.Device}, nil); err != nil {
		return none, usageOf(err, err.Error(), "")
	}
	flow, _ := in.Flow.flow()
	flow.FromZone, flow.ToZone = "", ""
	src := in.Flow.Source
	if src == "-" {
		src = "" // any source
	}
	if err := endpoints(ctx, env, &flow, src, in.Flow.Destination, in.Flow.NoDNS); err != nil {
		return none, err
	}
	es, err := openEstate(env, in.At)
	if err != nil {
		return none, err
	}
	sim := es.simEnv(env)
	if in.Flow.NoDNS {
		sim.Resolve = nil
	}
	params := map[string]string{"device": in.Device, "router": in.Router, "from-zone": in.FromZone, "from-interface": in.FromInterface}
	env.Log.Infof(runlog.TagStep, "nat %s -> %s on %s", flow.Source, flow.Destination, in.Device)
	run, holes, err := runEstate(ctx, nat.Simulation{}, sim, simulate.Input{Flow: flow, Params: params})
	if err != nil {
		return none, err
	}
	in.Simulated = flow
	e := envelope[NATInput, NATResult]("simulate "+nat.Kind, in)
	e.Holes, e.Read = holes, es.network.Read()
	if len(holes) > 0 {
		return e, nil
	}
	res, _ := run.Output.(nat.Result)
	env.Log.Infof(runlog.TagStep, "nat: fidelity %s", run.Fidelity)
	e.Unresolved = dedupeUnresolved(runUnresolved(run, run.Device, run.Vsys, true))
	d, _ := es.network.Device(run.Device)
	e.Notes = runNotes(run.Device, append(append(append(simulate.Reasons{}, run.Notes...), d.Notes...), res.Notes...))
	e.Results = []NATResult{{Answer: NATAnswer(res, run.Input.Flow), Needs: natNeeds(run.Input.Flow, res, run.Fidelity), Result: res, Fidelity: run.Fidelity, Stages: SimStages(run.Stages), Run: run, TakenAt: d.TakenAt}}
	return e, nil
}
