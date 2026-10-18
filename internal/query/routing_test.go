package query

import (
	"context"
	"errors"
	"testing"

	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/pathlab"
	"github.com/kaisero/proteus/internal/simulate/routing"
)

// The lab path crosses fw02 and fw01; the result keeps the native run.
func TestRoutingAcrossTheLab(t *testing.T) {
	t.Parallel()
	in := RoutingInput{Source: pathlab.Source, Destination: pathlab.Destination, Port: "udp/53", RIB: true}
	e, err := Routing(context.Background(), labEnv(t, pathlab.FW01, pathlab.FW02), in)
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	r := e.Results[0]
	if e.Command != "simulate routing" || len(r.Hops) != 2 || r.Hops[0].Device != pathlab.FW02 || r.Run.Kind != routing.Kind ||
		len(r.Stages) != len(r.Run.Stages) || e.Input.Simulated.Protocol != "udp" || e.Input.Simulated.DestPort != 53 {
		t.Errorf("%+v", r)
	}
}

// A protocol without a port reaches the flow; a port with its own protocol
// wins over it, and none is tcp.
func TestRoutingTakesAProtocolWithoutAPort(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ protocol, port, want string }{
		{"udp", "", "udp"}, {"udp", "tcp/443", "tcp"}, {"", "", "tcp"},
	} {
		in := RoutingInput{Source: pathlab.Source, Destination: pathlab.Destination, Protocol: tc.protocol, Port: tc.port}
		e, err := Routing(context.Background(), labEnv(t, pathlab.FW01, pathlab.FW02), in)
		if err != nil || e.Input.Simulated.Protocol != tc.want {
			t.Errorf("%+v: %q, %v", tc, e.Input.Simulated.Protocol, err)
		}
	}
}

// A start device without a snapshot is a hole, and there is no result.
func TestRoutingFromAHole(t *testing.T) {
	t.Parallel()
	in := RoutingInput{Destination: pathlab.Destination, Device: pathlab.FW02}
	e, err := Routing(context.Background(), labEnv(t, pathlab.FW01), in)
	if err != nil || len(e.Results) != 0 || len(e.Holes) != 1 || e.Holes[0].Device != pathlab.FW02 {
		t.Errorf("%+v %v", e, err)
	}
}

// A start only the caller can choose is a choice error.
func TestRoutingLeavesAChoiceToTheCaller(t *testing.T) {
	t.Parallel()
	in := RoutingInput{Source: "198.18.1.10", Destination: "8.8.8.8", Device: pathlab.FW01}
	_, err := Routing(context.Background(), labEnv(t, pathlab.FW01, pathlab.FW02), in)
	if c, ok := errors.AsType[*simulate.ChoiceError](err); !ok || c.Kind != simulate.ChoiceRouter {
		t.Errorf("%v", err)
	}
}

// Routing refuses a question without a start, a bad port, an unknown device, a
// bad time and a name without an address.
func TestRoutingInputRules(t *testing.T) {
	t.Parallel()
	env := labEnv(t, pathlab.FW01)
	for _, tc := range []struct {
		in   RoutingInput
		want string
	}{
		{RoutingInput{Destination: "1.1.1.1"}, "give a source, or a start device with --device"},
		{RoutingInput{Source: "1.1.1.1", Destination: "2.2.2.2", Port: "https"}, `--port "https"`},
		{RoutingInput{Destination: "1.1.1.1", Device: "fw09"}, `no device named "fw09"`},
		{RoutingInput{Destination: "1.1.1.1", Device: pathlab.FW01, At: "tuesday"}, `--at "tuesday"`},
		{RoutingInput{Destination: "gone.example.test", Device: pathlab.FW01}, "gone.example.test resolved to no address"},
		{RoutingInput{Source: "gone.example.test", Destination: "1.1.1.1"}, "gone.example.test resolved to no address"},
		{RoutingInput{Source: "10.0.0.0/8", Destination: "1.1.1.1"}, "is a network"},
		{RoutingInput{Source: "1.1.1.1", Destination: "10.0.0.0/8"}, "is a network"},
	} {
		_, err := Routing(context.Background(), env, tc.in)
		usageOK(t, err, tc.want)
	}
	if _, err := Routing(context.Background(), Env{}, RoutingInput{Destination: "1.1.1.1", Device: pathlab.FW01}); !errors.Is(err, errNoInventory) {
		t.Errorf("no inventory: %v", err)
	}
	env.Store = nil
	if _, err := Routing(context.Background(), env, RoutingInput{Destination: "1.1.1.1", Device: pathlab.FW01}); !errors.Is(err, errNoStore) {
		t.Errorf("no store: %v", err)
	}
}
