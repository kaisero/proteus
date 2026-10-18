package pathpolicy

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/testconfig"
)

// Review focus 2, D13: a hop whose content data lacks the flow's application
// is undecided. Its reason names the device and the content version; the check
// returns no error, so the path goes on as for any undecided hop.
func TestAHopWithoutTheApplicationIsUndecided(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "apps.xml.gz")
	testconfig.Content(t, path)
	data, err := appid.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	base := lab{}.env(t)
	e := *base
	e.Load = func(device, vsys string) (simulate.Target, error) {
		tg, err := base.Load(device, vsys)
		tg.Providers.Apps = data
		return tg, err
	}
	f := input(pathlab.Destination).Flow
	f.FromZone, f.ToZone, f.Application = "home", "labor", "sssl"
	r, err := Security{}.Evaluate(context.Background(), &e, routing.Hop{Device: pathlab.FW02, Vsys: "vsys1"}, f)
	if err != nil {
		t.Fatalf("an error: %v", err)
	}
	if r.Verdict != Undecided || len(r.Reason) != 1 || r.Reason[0].Code != "doubt.application-unknown" {
		t.Fatalf("result %+v", r)
	}
	if text := r.Reason[0].Text; !strings.HasPrefix(text, pathlab.FW02+": ") || !strings.Contains(text, "8000-1000") || !strings.Contains(text, "ssl") {
		t.Errorf("text %q", text)
	}
	if r.Fidelity.Level() != "undermatch" || r.Fidelity.UnderMatchReasons()[0].Code != "doubt.application-unknown" {
		t.Errorf("fidelity %s", r.Fidelity)
	}
	// A known application runs the check.
	f.Application = "SSL"
	if r, err := (Security{}).Evaluate(context.Background(), &e, routing.Hop{Device: pathlab.FW02, Vsys: "vsys1"}, f); err != nil || r.Security == nil {
		t.Errorf("ssl: %+v, %v", r, err)
	}
}

// PD12: match-user is a decision stage of the check. A hop with no user and
// a known-user rule is inferred (spec 2026-10-17 §5.4, SG5).
func TestMatchUserIsADecisionStage(t *testing.T) {
	t.Parallel()
	data := identity.New(identity.File{Format: identity.Format, Users: []identity.User{{Name: `example.com\alice`}}})
	e := lab{
		config: map[string][]byte{pathlab.FW01: userRuleOn(t, "known-user")},
		users:  map[string]*identity.Data{pathlab.FW01: data},
	}.env(t)
	f := input(pathlab.Destination).Flow
	f.FromZone, f.ToZone = "transport", "server"
	r, err := Security{}.Evaluate(context.Background(), e, routing.Hop{Device: pathlab.FW01, Vsys: "vsys1"}, f)
	if err != nil {
		t.Fatal(err)
	}
	if r.Verdict != Stop || r.Rule != "interzone-default" || r.Fidelity.Level() != "inferred" {
		t.Errorf("%s %s, fidelity %s", r.Verdict, r.Rule, r.Fidelity)
	}
	if !slices.Contains(decisionStages, "match-user") {
		t.Errorf("decision stages %v", decisionStages)
	}
}
