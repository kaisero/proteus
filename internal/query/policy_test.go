package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

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
		{PolicyInput{Flow: FlowInput{Destination: "2.2.2.2", Port: "https"}}, `--port "https": want 443 or tcp/443`},
		{PolicyInput{Flow: FlowInput{Destination: "2.2.2.2", SourcePort: 70000}}, "--source-port 70000 is not a port"},
		{PolicyInput{Flow: FlowInput{Source: "1.1.1.1", Destination: " "}}, "give a destination"},
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
	// Identity data that does not load is no error: the answer is as
	// without it, with a note (spec 2026-10-17 §4.2, PD11).
	user := in
	user.Flow.User = `example.com\alice`
	if e, err := PolicyFile(context.Background(), Env{Identity: failingIdentity{}}, user); err != nil || len(e.Results) != 1 || !hasNote(e.Notes, "gap.no-user-directory") {
		t.Errorf("identity: %v, notes %+v", err, e.Notes)
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

// Two notes with one text read the same twice: they are one.
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
	r := pathpolicy.Result{Verdict: pathpolicy.VerdictUndecided, At: &pathpolicy.Point{Hop: 0, Check: "routing", Reason: simulate.Reasons{reason.New("path.unresolved", "no hop")}}}
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
	if !slices.Equal(nonNil[string](nil), []string{}) {
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

// A file of another PAN-OS version answers as the 11.2 file does, with no note.
func TestPolicyFileOfAnotherVersionHasNoNote(t *testing.T) {
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
	if err != nil || len(e.Notes) != 0 || len(e.Unresolved) != 0 {
		t.Errorf("notes %+v, unresolved %+v, %v", e.Notes, e.Unresolved, err)
	}
}

// The resolver's first IPv4 address goes in front, the rest keep their order,
// and an alias's canonical name becomes a note (C2, C3). File mode checks that
// first address and names the others.
func TestEndpointOrdersAndNamesTheAlias(t *testing.T) {
	t.Parallel()
	env := Env{
		Resolve: resolver(map[string][]string{"app.example.test": {"2001:db8::1", "10.1.0.5", "2001:db8::2", "10.1.0.6"}}),
		CanonicalName: func(_ context.Context, name string) (string, error) {
			if name == "app.example.test" {
				return "App.CDN.example.test.", nil
			}
			return "", errors.New("no such host")
		},
	}
	ep, err := endpoint(context.Background(), env, "APP.example.test", false)
	if err != nil || fmt.Sprint(ep.Addrs) != "[10.1.0.5 2001:db8::1 2001:db8::2 10.1.0.6]" || ep.Canonical != "app.cdn.example.test" {
		t.Errorf("endpoint = %+v, %v", ep, err)
	}
	same := env
	same.CanonicalName = func(context.Context, string) (string, error) { return "app.example.test.", nil }
	if ep, _ := endpoint(context.Background(), same, "app.example.test", false); ep.Canonical != "" {
		t.Errorf("the name itself is no alias: %q", ep.Canonical)
	}
	failing := env
	failing.Resolve = resolver(map[string][]string{"other.example.test": {"10.1.0.7"}})
	if ep, _ := endpoint(context.Background(), failing, "other.example.test", false); ep.Canonical != "" || !ep.Resolved {
		t.Errorf("a failed canonical lookup gives none: %+v", ep)
	}
	in := PolicyFileInput{
		Flow:      FlowInput{Source: "10.2.0.5", Destination: "app.example.test", Protocol: "tcp"},
		Selection: Selection{File: fixture("firewall-ruletype.xml"), Vsys: []string{"vsys1"}},
	}
	e, err := PolicyFile(context.Background(), env, in)
	var codes []string
	for _, n := range e.Notes {
		codes = append(codes, string(n.Code))
	}
	// File mode checks the first address, as path mode does (D1b), and names
	// the others in a note.
	if err != nil || !slices.Equal(codes, []string{"dns.canonical-name", "dns.other-addresses"}) ||
		e.Notes[1].Note != "app.example.test resolved to 4 addresses; checked 10.1.0.5, not 2001:db8::1, 2001:db8::2, 10.1.0.6" {
		t.Errorf("file notes: %+v %v", e.Notes, err)
	}
	if len(e.Results) != 1 || fmt.Sprint(e.Results[0].Run.Input.Flow.Destination.Addrs) != "[10.1.0.5]" ||
		len(e.Input.Simulated.Destination.Addrs) != 4 {
		t.Errorf("checked %+v, simulated %+v", e.Results, e.Input.Simulated.Destination)
	}
}

// A source host name is cut to its first address too: from inside only, the
// derived zones are one on each side and inter-inside decides; the note names
// the other address (D1b).
func TestFileModeChecksTheFirstSourceAddress(t *testing.T) {
	t.Parallel()
	env := Env{Resolve: resolver(map[string][]string{"two.example.test": {"10.1.0.5", "10.3.0.5"}})}
	e, err := PolicyFile(context.Background(), env, PolicyFileInput{
		Flow:      FlowInput{Source: "two.example.test", Destination: "10.2.0.5", Protocol: "tcp", Port: "443"},
		Selection: Selection{File: fixture("firewall-ruletype.xml"), Vsys: []string{"vsys1"}},
	})
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	r := e.Results[0]
	if fmt.Sprint(r.Run.Input.Flow.Source.Addrs) != "[10.1.0.5]" || r.Verdict != "stop" || r.Answer != "first match: inter-inside (deny)" {
		t.Errorf("checked %v: %s, %s", r.Run.Input.Flow.Source.Addrs, r.Verdict, r.Answer)
	}
	if len(e.Notes) != 1 || e.Notes[0].Code != "dns.other-addresses" ||
		e.Notes[0].Note != "two.example.test resolved to 2 addresses; checked 10.1.0.5, not 10.3.0.5" {
		t.Errorf("notes %+v", e.Notes)
	}
}

// A lookup that fails because the call ended is the call's error, not a name
// with no address.
func TestEndpointStopsWhenTheCallEnds(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	env := Env{Resolve: func(ctx context.Context, _ string) ([]netip.Addr, error) {
		cancel()
		return nil, ctx.Err()
	}}
	if _, err := endpoint(ctx, env, "app.example.test", false); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the call's", err)
	}
}

// The system resolver answers localhost from the hosts file.
func TestSystemResolve(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	if as, err := SystemResolve(ctx, "localhost"); err != nil || len(as) == 0 {
		t.Skipf("no local resolver: %v %v", as, err)
	}
}

// Every question needs its subject: a destination, a search term, a name. The
// command line always gives one; another caller may not.
func TestAnEmptySubjectIsAUsageError(t *testing.T) {
	t.Parallel()
	file := Selection{File: fixture("firewall-zones.xml")}
	usageOK(t, PolicyFileInput{Flow: FlowInput{Source: "1.1.1.1"}, Selection: file}.Validate(), "give a destination")
	usageOK(t, RoutingInput{Source: "1.1.1.1"}.Validate(), "give a destination")
	usageOK(t, NATInput{Device: "fw01", Flow: FlowInput{Source: "-"}}.Validate(), "give a destination")
	usageOK(t, SearchInput{Selection: file}.Validate(), "give a search term")
	usageOK(t, LookupInput{Name: "  ", Selection: file}.Validate(), "give a name to look up")
}

// A given zone the vsys does not define is a usage error that lists the vsys's
// zones (C15). With several vsys selected, a vsys without it is a hole and the
// others answer; with none defining it, the error lists each.
func TestFileModeRefusesAnUndefinedZone(t *testing.T) {
	t.Parallel()
	ask := func(from, to string, vsys ...string) (Envelope[PolicyFileInput, SecurityResult], error) {
		return PolicyFile(context.Background(), Env{}, PolicyFileInput{
			Flow:      FlowInput{Source: "10.3.0.5", Destination: "10.1.0.5", Protocol: "tcp", Port: "443", FromZone: from, ToZone: to},
			Selection: Selection{File: fixture("firewall-ruletype.xml"), Vsys: vsys},
		})
	}
	_, err := ask("nowhere", "inside", "vsys1")
	u, ok := errors.AsType[*UsageError](err)
	if !ok || u.Text != "--from-zone nowhere is not a zone of vsys1 (its zones: dmz, inside, out)" ||
		u.ToolText != "from_zone nowhere is not a zone of vsys1 (its zones: dmz, inside, out)" {
		t.Errorf("one vsys: %v", err)
	}
	_, err = ask("out", "nowhere", "vsys1", "vsys2")
	if u, ok := errors.AsType[*UsageError](err); !ok ||
		u.Text != "no selected vsys defines the given zones: --to-zone nowhere is not a zone of vsys1 (its zones: dmz, inside, out); "+
			"--from-zone out is not a zone of vsys2 (its zones: dmz, inside)" ||
		u.ToolText != "no selected vsys defines the given zones: to_zone nowhere is not a zone of vsys1 (its zones: dmz, inside, out); "+
			"from_zone out is not a zone of vsys2 (its zones: dmz, inside)" {
		t.Errorf("no vsys: %v", err)
	}
	// vsys2 has no zone out: a hole; vsys1 answers.
	e, err := ask("out", "dmz", "vsys1", "vsys2")
	if err != nil || len(e.Results) != 1 || e.Results[0].Answer != "first match: universal-out (allow)" {
		t.Fatalf("%+v %v", e.Results, err)
	}
	if len(e.Holes) != 1 || e.Holes[0].Vsys != "vsys2" || e.Holes[0].Code != "zone.undefined" ||
		e.Holes[0].Reason != "not checked: the from zone out is not a zone of vsys2 (its zones: dmz, inside)" {
		t.Errorf("holes %+v", e.Holes)
	}
}
