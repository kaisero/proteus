package pathlab_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

func labFlow() simulate.Flow {
	return simulate.Flow{
		Source:      simulate.Addr(netip.MustParseAddr(pathlab.Source)),
		Destination: simulate.Addr(netip.MustParseAddr(pathlab.Destination)),
	}
}

func path(t *testing.T, e *simulate.Env) routing.Path {
	t.Helper()
	run, err := routing.Simulation{}.Run(context.Background(), e, simulate.Input{Flow: labFlow()})
	if err != nil {
		t.Fatal(err)
	}
	return run.Output.(routing.Path)
}

// check runs the security check on one hop with the hop's zones.
func check(t *testing.T, e *simulate.Env, h routing.Hop) securitypolicy.Verdict {
	t.Helper()
	run, err := securitypolicy.Simulation{}.Run(context.Background(), e,
		simulate.Input{Device: h.Device, Vsys: h.Vsys, Flow: h.Flow})
	if err != nil {
		t.Fatal(err)
	}
	return run.Output.(securitypolicy.Verdict)
}

// The lab flow crosses fw02 home -> labor, then fw01 transport -> server, and
// interzone-default denies it on each hop.
func TestTheLabFlowIsDeniedByTheDefaultRule(t *testing.T) {
	t.Parallel()
	e := pathlab.Env(t, pathlab.Defaults{})
	p := path(t, e)
	var trail []string
	for _, h := range p.Hops {
		trail = append(trail, fmt.Sprintf("%s/%s(%s->%s)", h.Device, h.Vsys, h.Flow.FromZone, h.Flow.ToZone))
	}
	if got := strings.Join(trail, " "); p.Outcome != routing.Delivered || got != "fw02/vsys1(home->labor) fw01/vsys1(transport->server)" {
		t.Fatalf("path = %s, %s", got, p.Outcome)
	}
	for _, h := range p.Hops {
		v := check(t, e, h)
		if v.Rule != nil || v.Default != pathlab.Interzone || v.DefaultAction != "deny" || v.DefaultSource != "built-in" {
			t.Errorf("%s: rule %v, default %s (%s), %s", h.Device, v.Rule, v.Default, v.DefaultAction, v.DefaultSource)
		}
	}
}

// Each variant overrides the default rule that decides on hop 1.
func TestTheVariantsOverrideTheDefaultRule(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"local only":     "allow, local",
		"pushed only":    "reset-both, pushed",
		"both equal":     "allow, local",
		"both different": "undecided",
		"no action":      "deny, local",
	}
	if len(pathlab.Variants) != len(want) {
		t.Fatalf("%d variants, %d expected answers", len(pathlab.Variants), len(want))
	}
	for _, c := range pathlab.Variants {
		e := pathlab.Env(t, c.Defaults)
		v := check(t, e, path(t, e).Hops[0])
		got := v.DefaultAction + ", " + v.DefaultSource
		if v.Default == "" {
			got = "undecided"
		}
		if got != want[c.Name] {
			t.Errorf("%s: got %q, want %q", c.Name, got, want[c.Name])
		}
	}
}

func TestAnUnknownDeviceIsAnError(t *testing.T) {
	t.Parallel()
	e := pathlab.Env(t, pathlab.Defaults{})
	if _, err := e.Network.Device("fw03"); err == nil {
		t.Error("fw03 has data")
	}
	if _, err := e.Load("fw03", "vsys1"); err == nil {
		t.Error("fw03 has a configuration")
	}
	if _, err := e.Load(pathlab.FW01, "vsys9"); err == nil {
		t.Error("fw01 has vsys9")
	}
}
