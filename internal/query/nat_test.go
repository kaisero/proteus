package query

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/estate"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/nat"
)

// natEnv is fw01 with the NAT fixture.
func natEnv(t *testing.T) Env {
	t.Helper()
	l := newLab(t)
	l.fetch("fw01", fixture("firewall-nat.xml"))
	return l.env()
}

// The port forward fw01 applies (spec 2026-09-27 §18.5 traffic test 1): the
// result keeps the native run and the snapshot's time.
func TestNATPortForward(t *testing.T) {
	t.Parallel()
	in := NATInput{
		Flow:   FlowInput{Source: "198.18.1.10", Destination: "198.18.250.10", Protocol: "tcp", Port: "8443"},
		Device: "fw01", Router: "default", FromZone: "transport",
	}
	e, err := NAT(context.Background(), natEnv(t), in)
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	r := e.Results[0]
	if e.Command != "simulate nat" || r.Rule == nil || r.Destination == nil || r.Run.Kind != nat.Kind ||
		!r.TakenAt.Equal(clock) || len(r.Stages) != len(r.Run.Stages) || r.Fidelity.Level() != "exact" {
		t.Errorf("%+v", r)
	}
	if e.Input.Simulated.DestPort != 8443 || e.Input.Simulated.FromZone != "" {
		t.Errorf("simulated: %+v", e.Input.Simulated)
	}
}

// Any source is "-"; the flow's own zones are not NAT's input.
func TestNATTakesAnySource(t *testing.T) {
	t.Parallel()
	in := NATInput{
		Flow:   FlowInput{Source: "-", Destination: "198.18.250.10", Protocol: "tcp", Port: "8443", FromZone: "ignored"},
		Device: "fw01", Router: "default", FromZone: "transport",
	}
	e, err := NAT(context.Background(), natEnv(t), in)
	if src := e.Input.Simulated.Source; err != nil || len(e.Results) != 1 || src.Name != "" || len(src.Addrs) != 0 {
		t.Errorf("%+v %v", e.Input.Simulated, err)
	}
}

// A device without a snapshot is a hole; a router left open is a choice.
func TestNATHoleAndChoice(t *testing.T) {
	t.Parallel()
	in := NATInput{Flow: FlowInput{Source: "198.18.1.10", Destination: "8.8.8.8"}, Device: "fw02"}
	e, err := NAT(context.Background(), natEnv(t), in)
	if err != nil || len(e.Results) != 0 || len(e.Holes) != 1 || e.Holes[0].Device != "fw02" {
		t.Errorf("hole: %+v %v", e, err)
	}
	in.Device = "fw01"
	_, err = NAT(context.Background(), natEnv(t), in)
	if c, ok := errors.AsType[*simulate.ChoiceError](err); !ok || c.Kind != simulate.ChoiceRouter {
		t.Errorf("choice: %v", err)
	}
}

// NAT refuses a question without a device, with both ingress flags, or with a
// bad port, an unknown device or a name without an address.
func TestNATInputRules(t *testing.T) {
	t.Parallel()
	env := natEnv(t)
	flow := FlowInput{Source: "1.1.1.1", Destination: "2.2.2.2"}
	for _, tc := range []struct {
		in   NATInput
		want string
	}{
		{NATInput{Flow: flow}, "give the firewall with --device"},
		{NATInput{Flow: flow, Device: "fw01", FromZone: "a", FromInterface: "b"}, "--from-zone and --from-interface exclude each other"},
		{NATInput{Flow: FlowInput{Source: "1.1.1.1", Destination: "2.2.2.2", SourcePort: -1}, Device: "fw01"}, "--source-port -1 is not a port"},
		{NATInput{Flow: flow, Device: "fw09"}, `no device named "fw09"`},
		{NATInput{Flow: flow, Device: "fw01", At: "x"}, `--at "x"`},
		{NATInput{Flow: FlowInput{Destination: "gone.example.test"}, Device: "fw01"}, "resolved to no address"},
	} {
		_, err := NAT(context.Background(), env, tc.in)
		usageOK(t, err, tc.want)
	}
	if _, err := NAT(context.Background(), Env{}, NATInput{Flow: flow, Device: "fw01"}); !errors.Is(err, errNoInventory) {
		t.Errorf("no inventory: %v", err)
	}
}

// A hop the store cannot give keeps the hole's kind, not a generic load failure.
func TestStoreLoaderKeepsTheHoleCode(t *testing.T) {
	t.Parallel()
	st := newLab(t).st
	load := storeLoader(st, estate.When{}, estate.NewNetwork(st, nil, estate.When{}), false, false)
	_, err := load("fw01", "vsys1")
	var coded *simulate.CodedError
	if !errors.As(err, &coded) || coded.Code() != "gap.snapshot-missing" || !strings.HasPrefix(err.Error(), "fw01/vsys1: ") {
		t.Errorf("%v (%T)", err, err)
	}
}
