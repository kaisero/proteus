package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
)

func labFlow() FlowInput {
	return FlowInput{Source: pathlab.Source, Destination: pathlab.Destination, Protocol: "tcp", Port: "443"}
}

// The lab flow is traced across both firewalls and denied by fw02's interzone
// default rule; the envelope carries the flow as simulated and the native answer.
func TestPolicyAlongThePath(t *testing.T) {
	t.Parallel()
	env := labEnv(t, pathlab.FW01, pathlab.FW02)
	e, err := Policy(context.Background(), env, PolicyInput{Flow: labFlow()})
	if err != nil {
		t.Fatal(err)
	}
	if e.Command != "simulate policy" || e.Detail != "full" || e.Format != FormatVersion || len(e.Results) != 1 {
		t.Fatalf("envelope: %+v", e)
	}
	r := e.Results[0]
	if r.Mode != "path" || r.Verdict != "denied" || len(r.Hops) != 2 || r.At == nil || r.At.Hop != 1 || r.At.Rule != "interzone-default" ||
		r.Result.Verdict != pathpolicy.VerdictDenied || len(r.RunStages) == 0 || len(r.Stages) != len(r.RunStages) {
		t.Errorf("result: %s at %+v, %d hops", r.Verdict, r.At, len(r.Hops))
	}
	if in := e.Input.Simulated; in.Source.String() != pathlab.Source || in.DestPort != 443 || in.Protocol != "tcp" {
		t.Errorf("simulated flow: %+v", in)
	}
	if len(e.Holes) != 0 || len(e.Unresolved) != 0 {
		t.Errorf("qualifiers: %+v %+v", e.Holes, e.Unresolved)
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"checks":{"security":{`) || strings.Contains(string(b), "RunStages") {
		t.Errorf("JSON: %v %s", err, b)
	}
}

// A start device without a snapshot is a hole, and the path answers with no
// result.
func TestPolicyWithAHoleHasNoResult(t *testing.T) {
	t.Parallel()
	e, err := Policy(context.Background(), labEnv(t, pathlab.FW01), PolicyInput{Flow: labFlow()})
	if err != nil || len(e.Results) != 0 || len(e.Holes) == 0 || e.Holes[0].Device != pathlab.FW02 || e.Input.Simulated.DestPort != 443 {
		t.Errorf("%+v %v", e, err)
	}
}

// A start only the user can choose is a choice error, with what is chosen.
func TestPolicyLeavesAChoiceToTheCaller(t *testing.T) {
	t.Parallel()
	in := PolicyInput{Flow: FlowInput{Source: "198.18.1.10", Destination: "8.8.8.8"}, Device: pathlab.FW01}
	_, err := Policy(context.Background(), labEnv(t, pathlab.FW01, pathlab.FW02), in)
	if c, ok := errors.AsType[*simulate.ChoiceError](err); !ok || c.Kind != simulate.ChoiceRouter {
		t.Errorf("%v", err)
	}
}

// An FQDN traces its first IPv4 address, which moves to the front; one without
// an IPv4 address cannot be traced.
func TestPolicyTracesAnFQDNsFirstIPv4Address(t *testing.T) {
	t.Parallel()
	env := labEnv(t, pathlab.FW01, pathlab.FW02)
	env.Resolve = resolver(map[string][]string{"web.example.test": {"2001:db8::1", pathlab.Destination}, "v6.example.test": {"2001:db8::2"}})
	in := PolicyInput{Flow: labFlow()}
	in.Flow.Destination = "WEB.example.test"
	e, err := Policy(context.Background(), env, in)
	if err != nil || e.Input.Simulated.Destination.Name != "web.example.test" || e.Input.Simulated.Destination.Addrs[0].String() != pathlab.Destination {
		t.Errorf("%+v %v", e.Input.Simulated.Destination, err)
	}
	in.Flow.Destination = "v6.example.test"
	_, err = Policy(context.Background(), env, in)
	usageOK(t, err, "path mode needs an address for v6.example.test")
	in.Flow.NoDNS = true
	_, err = Policy(context.Background(), env, in)
	usageOK(t, err, "path mode needs an address for v6.example.test")
}

// Path mode refuses what it does not take; each refusal says it without a flag
// for a tool.
func TestPolicyInputRules(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   PolicyInput
		want string
	}{
		{PolicyInput{Vsys: []string{"vsys1"}}, "--vsys selects a vsys, but path mode checks every firewall and vsys on the path; use --file"},
		{PolicyInput{Label: []string{"site=s1"}}, "--label selects devices"},
		{PolicyInput{Flow: FlowInput{FromZone: "a"}}, "--from-zone: the path gives the zones"},
		{PolicyInput{Flow: FlowInput{ToZone: "a"}}, "--to-zone: the path gives the zones"},
		{PolicyInput{Router: "default"}, "--router needs --device"},
		{PolicyInput{Flow: FlowInput{Port: "https"}}, `--port "https": want 443 or tcp/443`},
		{PolicyInput{Flow: FlowInput{SourcePort: 70000}}, "--source-port 70000 is not a port"},
	} {
		usageOK(t, tc.in.Validate(), tc.want)
		_, err := Policy(context.Background(), Env{}, tc.in)
		usageOK(t, err, tc.want)
	}
	env := labEnv(t, pathlab.FW01)
	for _, tc := range []struct {
		in   PolicyInput
		want string
	}{
		{PolicyInput{Flow: labFlow(), Device: "fw09"}, `no device named "fw09"`},
		{PolicyInput{Flow: labFlow(), At: "tuesday"}, `--at "tuesday"`},
		{PolicyInput{Flow: FlowInput{Source: "10.0.0.0/8", Destination: "1.1.1.1"}}, "is a network, not an endpoint"},
		{PolicyInput{Flow: FlowInput{Source: "1.1.1.1", Destination: "nowhere"}}, "is neither an address nor an FQDN"},
	} {
		_, err := Policy(context.Background(), env, tc.in)
		usageOK(t, err, tc.want)
	}
}

// A query refuses an env without what it reads.
func TestPolicyNeedsTheEstate(t *testing.T) {
	t.Parallel()
	if _, err := Policy(context.Background(), Env{}, PolicyInput{Flow: labFlow()}); !errors.Is(err, errNoInventory) {
		t.Errorf("no inventory: %v", err)
	}
	env := labEnv(t)
	env.Store = nil
	if _, err := Policy(context.Background(), env, PolicyInput{Flow: labFlow()}); !errors.Is(err, errNoStore) {
		t.Errorf("no store: %v", err)
	}
	env = labEnv(t, pathlab.FW01, pathlab.FW02)
	env.Users = func() (index.UserDirectory, error) { return nil, errors.New("PROTEUS_USERS: unreadable") }
	if _, err := Policy(context.Background(), env, PolicyInput{Flow: labFlow()}); err == nil || err.Error() != "PROTEUS_USERS: unreadable" {
		t.Errorf("users: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Policy(ctx, labEnv(t, pathlab.FW01, pathlab.FW02), PolicyInput{Flow: labFlow()}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// One configuration file: the zones derived, one result with the native verdict.
func TestPolicyFile(t *testing.T) {
	t.Parallel()
	in := PolicyFileInput{
		Flow:      FlowInput{Source: "10.2.0.5", Destination: "10.1.0.5", Protocol: "tcp", Port: "443"},
		Selection: Selection{File: fixture("firewall-ruletype.xml"), Vsys: []string{"vsys1"}},
	}
	e, err := PolicyFile(context.Background(), Env{}, in)
	if err != nil || len(e.Results) != 1 || len(e.Targets) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	r := e.Results[0]
	if r.Kind != "policy" || r.Target.Vsys != "vsys1" || r.From.Vsys != "vsys1" || r.Run.Kind != "policy" ||
		r.Verdict == "" || len(r.Stages) == 0 || e.Command != "simulate policy" || e.Input.Simulated.DestPort != 443 {
		t.Errorf("result: %+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil || strings.Contains(string(b), `"Run"`) || !strings.Contains(string(b), `"target":{"device"`) {
		t.Errorf("JSON: %v %s", err, b)
	}
	// A vsys the file does not have is a hole: no result.
	in.Selection.Vsys = []string{"vsys9"}
	if e, err := PolicyFile(context.Background(), Env{}, in); err != nil || len(e.Results) != 0 || len(e.Holes) != 1 {
		t.Errorf("vsys9: %+v %v", e, err)
	}
	in.Selection.Vsys = nil
	_, err = PolicyFile(context.Background(), Env{}, in)
	usageOK(t, err, "vsys; select one with --vsys")
	in.Selection.Vsys = []string{"vsys1"}
	env := Env{Users: func() (index.UserDirectory, error) { return nil, errors.New("PROTEUS_USERS: unreadable") }}
	if _, err := PolicyFile(context.Background(), env, in); err == nil || !strings.Contains(err.Error(), "PROTEUS_USERS") {
		t.Errorf("users: %v", err)
	}
	in.Selection.File = fixture("absent.xml")
	if _, err := PolicyFile(context.Background(), Env{}, in); err == nil {
		t.Error("an absent file is read")
	}
}

// An FQDN on a file is simulated even when it resolves to nothing; with --no-dns
// it is not resolved at all.
func TestPolicyFileResolvesNames(t *testing.T) {
	t.Parallel()
	in := PolicyFileInput{
		Flow:      FlowInput{Source: "10.2.0.5", Destination: "app.example.test", Protocol: "tcp"},
		Selection: Selection{File: fixture("firewall-ruletype.xml"), Vsys: []string{"vsys1"}},
	}
	env := Env{Resolve: resolver(map[string][]string{"app.example.test": {"::ffff:10.1.0.5"}})}
	e, err := PolicyFile(context.Background(), env, in)
	if d := e.Input.Simulated.Destination; err != nil || !d.Resolved || d.Addrs[0].String() != "10.1.0.5" {
		t.Errorf("resolved: %+v %v", d, err)
	}
	in.Flow.Destination = "gone.example.test"
	if e, err = PolicyFile(context.Background(), env, in); err != nil || e.Input.Simulated.Destination.Resolved {
		t.Errorf("unresolved: %+v %v", e.Input.Simulated.Destination, err)
	}
	in.Flow.NoDNS = true
	if e, err = PolicyFile(context.Background(), env, in); err != nil || len(e.Input.Simulated.Destination.Addrs) != 0 {
		t.Errorf("no dns: %+v %v", e.Input.Simulated.Destination, err)
	}
	in.Flow.NoDNS = false
	if e, err = PolicyFile(context.Background(), Env{}, in); err != nil || e.Input.Simulated.Destination.Resolved {
		t.Errorf("no resolver: %+v %v", e.Input.Simulated.Destination, err)
	}
}

// File mode refuses the store's selectors, a router and a lone zone.
func TestPolicyFileInputRules(t *testing.T) {
	t.Parallel()
	file := Selection{File: fixture("firewall-zones.xml")}
	with := func(f func(*PolicyFileInput)) PolicyFileInput {
		in := PolicyFileInput{Flow: FlowInput{Source: "1.1.1.1", Destination: "2.2.2.2"}, Selection: file}
		f(&in)
		return in
	}
	for _, tc := range []struct {
		in   PolicyFileInput
		want string
	}{
		{PolicyFileInput{}, "give a configuration file with --file"},
		{with(func(in *PolicyFileInput) { in.Selection.Device = []string{"fw01"} }), "--device selects from the store; --file reads one configuration"},
		{with(func(in *PolicyFileInput) { in.Selection.Label = []string{"a=b"} }), "--label selects from the store"},
		{with(func(in *PolicyFileInput) { in.Selection.At = "2026-01-01" }), "--at selects from the store"},
		{with(func(in *PolicyFileInput) { in.Selection.Fresh = true }), "--fresh selects from the store"},
		{with(func(in *PolicyFileInput) { in.Router = "default" }), "--router picks the start router of --device"},
		{with(func(in *PolicyFileInput) { in.Flow.FromZone = "dmz" }), "--from-zone and --to-zone go together"},
		{with(func(in *PolicyFileInput) { in.Flow.Port = "x/y" }), `--port "x/y"`},
		{with(func(in *PolicyFileInput) { in.Flow.Source = "10.0.0.0/8" }), "is a network"},
		{with(func(in *PolicyFileInput) { in.Flow.Destination = "nowhere" }), "neither an address nor an FQDN"},
	} {
		_, err := PolicyFile(context.Background(), Env{}, tc.in)
		usageOK(t, err, tc.want)
	}
}

// Format 1 prints a note's text, not its code: two notes that print the same are
// one.
func TestPathNotesDropTheSameText(t *testing.T) {
	t.Parallel()
	res := pathpolicy.Result{Notes: simulate.Reasons{reason.New("note.ha-peer", "same"), reason.New("note.ha-binding", "same")}}
	if got := pathNotes(res); len(got) != 1 || got[0].Code != "note.ha-peer" {
		t.Errorf("%+v", got)
	}
}

// A point without its hop names no hop, and is still unresolved.
func TestPathUnresolvedWithoutAHop(t *testing.T) {
	t.Parallel()
	r := pathpolicy.Result{Verdict: pathpolicy.VerdictUndecided, At: &pathpolicy.Point{Hop: 0, Check: "routing", Reason: reason.New("path.unresolved", "no hop")}}
	if un := pathUnresolved(r, nil); len(un) != 1 || un[0].Reason != "no hop" || un[0].Code != "path.unresolved" {
		t.Errorf("unresolved: %+v", un)
	}
	if _, ok := PointHop(r); ok {
		t.Error("hop 0 exists")
	}
}

// Checks marshal in list order.
func TestChecksMarshalInOrder(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(Checks{{Name: "security"}, {Name: "nat"}})
	if err != nil || !strings.HasPrefix(string(b), `{"security":{`) || !strings.Contains(string(b), `},"nat":{`) {
		t.Errorf("%v %s", err, b)
	}
	if !slices.Equal(nonNil(nil), []string{}) {
		t.Error("nonNil")
	}
}

// A hop whose default rules differ between the local and the pushed rulebase is
// undecided: an unresolved entry, and the verdict undecided.
func TestPolicyUndecidedHopIsUnresolved(t *testing.T) {
	t.Parallel()
	differ := pathlab.Defaults{Local: pathlab.Entry(pathlab.Interzone, "allow"), Pushed: pathlab.Entry(pathlab.Interzone, "deny")}
	l := newLab(t)
	l.fetch(pathlab.FW01, pathlab.ConfigFile(pathlab.FW01))
	l.fetch(pathlab.FW02, pathlab.ConfigPath(t, pathlab.FW02, differ))
	in := PolicyInput{Flow: labFlow()}
	in.Flow.NoDNS = true
	e, err := Policy(context.Background(), l.env(), in)
	if err != nil || len(e.Results) != 1 || e.Results[0].Verdict != "undecided" || len(e.Unresolved) == 0 || e.Unresolved[0].Device != pathlab.FW02 {
		t.Errorf("%+v %+v %v", e.Results, e.Unresolved, err)
	}
}

// A rule that decides on a file names itself and its candidates.
func TestPolicyFileWithADecidingRule(t *testing.T) {
	t.Parallel()
	in := PolicyFileInput{
		Flow:      FlowInput{Source: "10.1.0.5", Destination: "10.2.0.5", Protocol: "tcp", Port: "tcp/443"},
		Selection: Selection{File: fixture("firewall-zones.xml"), Vsys: []string{"vsys1"}},
	}
	e, err := PolicyFile(context.Background(), Env{}, in)
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	r := e.Results[0]
	if r.FirstMatch == nil || r.Rule != r.FirstMatch.Name || len(r.Candidates) == 0 || r.Check.Rule == nil {
		t.Errorf("%+v", r.Security)
	}
}

// A file read with an older schema is a note on its target, and the answer keeps it.
func TestPolicyFileNotesAVersionGap(t *testing.T) {
	t.Parallel()
	b := bytes.Replace(pathlab.Read(t, fixture("firewall-zones.xml")), []byte(`<config version="11.2.0"`), []byte(`<config version="12.2.0"`), 1)
	file := filepath.Join(t.TempDir(), "newer.xml")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	in := PolicyFileInput{
		Flow:      FlowInput{Source: "10.1.0.5", Destination: "10.2.0.5", Protocol: "tcp", Port: "443"},
		Selection: Selection{File: file, Vsys: []string{"vsys1"}},
	}
	e, err := PolicyFile(context.Background(), Env{}, in)
	if err != nil || len(e.Notes) != 1 || e.Notes[0].Code != "gap.version" || len(e.Unresolved) != 0 {
		t.Errorf("notes %+v, unresolved %+v, %v", e.Notes, e.Unresolved, err)
	}
}
