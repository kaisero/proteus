package pathpolicy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// network is simulate.Network over fixed data. A device named in gone is
// unavailable, as a device with no usable snapshot is.
type network struct {
	data map[string]simulate.DeviceData
	gone string
}

func (n network) Devices() []string { return pathlab.Devices }

func (n network) Device(name string) (simulate.DeviceData, error) {
	if name == n.gone {
		return simulate.DeviceData{}, &simulate.UnavailableError{Missing: []simulate.Missing{{Device: name, Reason: name + " has no snapshot"}}}
	}
	d, ok := n.data[name]
	if !ok {
		return d, fmt.Errorf("no device %q", name)
	}
	return d, nil
}

// labNet is the fixture's operational data; fw01 loses its default route when
// noDefault is set, so a destination beyond it has no route there.
func labNet(t *testing.T, noDefault bool) network {
	t.Helper()
	n := network{data: map[string]simulate.DeviceData{}}
	for _, dev := range pathlab.Devices {
		d := pathlab.Device(t, dev)
		if noDefault && dev == pathlab.FW01 {
			d.FIB = slices.DeleteFunc(d.FIB, func(r resolve.FIBRoute) bool { return r.Destination.Bits() == 0 })
		}
		n.data[dev] = d
	}
	return n
}

// lab is the path fixture with one configuration per device: the base with
// default rule overrides, unless config names other bytes.
type lab struct {
	defaults map[string]pathlab.Defaults // by device
	config   map[string][]byte           // by device; wins over defaults
	net      simulate.Network
	fail     string // a device whose configuration cannot be read
	quiet    bool   // the loader gives no notes, not even a version gap
	// predefined puts the device's predefined services (testdata/predefined)
	// next to each configuration.
	predefined bool
}

func (l lab) env(t *testing.T) *simulate.Env {
	t.Helper()
	paths := map[string]string{}
	for _, dev := range pathlab.Devices {
		b, ok := l.config[dev]
		if !ok {
			b = pathlab.Config(t, dev, l.defaults[dev])
		}
		dir := t.TempDir()
		paths[dev] = filepath.Join(dir, dev+".xml")
		if err := os.WriteFile(paths[dev], b, 0o600); err != nil {
			t.Fatal(err)
		}
		if l.predefined {
			p := pathlab.Read(t, filepath.Join(filepath.Dir(pathlab.ConfigFile(dev)), "..", "predefined", config.PredefinedFile))
			if err := os.WriteFile(filepath.Join(dir, config.PredefinedFile), p, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if l.net == nil {
		l.net = labNet(t, false)
	}
	load := func(device, vsys string) (simulate.Target, error) {
		if device == l.fail {
			return simulate.Target{}, errors.New("snapshot unreadable")
		}
		cfg, rep, err := config.Load(paths[device])
		if err != nil {
			return simulate.Target{}, err
		}
		set := index.NewSet(cfg)
		sc := config.Scope{Sort: config.ScopeVsys, Name: vsys}
		if _, err := set.Index(sc, resolve.Security); err != nil {
			return simulate.Target{}, err
		}
		var notes simulate.Reasons
		if rep.VersionGap != "" && !l.quiet {
			notes = append(notes, reason.New("gap.version", rep.VersionGap))
		}
		return simulate.Target{Config: cfg, Indexes: set.Provider(sc), Notes: notes}, nil
	}
	return &simulate.Env{Network: l.net, Load: load}
}

// both is the same overrides on both devices.
func both(d pathlab.Defaults) map[string]pathlab.Defaults {
	return map[string]pathlab.Defaults{pathlab.FW01: d, pathlab.FW02: d}
}

var allowAll = both(pathlab.Defaults{Local: pathlab.Entry(pathlab.Interzone, "allow")})

// withRule is a device's base configuration with one security rule from home to
// labor.
func withRule(t *testing.T, device, name, action string) []byte {
	t.Helper()
	rule := `<rulebase><security><rules><entry name="` + name + `">` +
		`<from><member>home</member></from><to><member>labor</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<source-user><member>any</member></source-user><application><member>any</member></application>` +
		`<service><member>any</member></service><action>` + action + `</action></entry></rules></security></rulebase>`
	return bytes.Replace(pathlab.Config(t, device, pathlab.Defaults{}), []byte("</zone>"), []byte("</zone>"+rule), 1)
}

func input(dst string) simulate.Input {
	return simulate.Input{Flow: simulate.Flow{
		Source:      simulate.Addr(netip.MustParseAddr(pathlab.Source)),
		Destination: simulate.Addr(netip.MustParseAddr(dst)),
	}}
}

func runLab(t *testing.T, l lab, dst string) Result {
	t.Helper()
	res, stages, err := Run(context.Background(), l.env(t), input(dst))
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range stages {
		if st.Slug != "place" && !strings.HasPrefix(st.Slug, "hop") {
			t.Errorf("a stage that is not routing's: %s", st.Slug)
		}
	}
	return res
}

// summary is a result in one line: verdict, point, and each hop's checks.
func summary(r Result) string {
	s := string(r.Verdict)
	if r.At != nil {
		s += fmt.Sprintf(" at %d %s %s (%s)", r.At.Hop, r.At.Check, r.At.Rule, r.At.Reason.Text())
	}
	for _, h := range r.Hops {
		s += fmt.Sprintf(" | %d %s/%s", h.Index, h.Routing.Device, h.Routing.Vsys)
		for _, c := range h.Checks {
			s += fmt.Sprintf(" %s=%s", c.Name, c.Verdict)
			if c.Rule != "" {
				s += ":" + c.Rule
			}
		}
		if len(h.Doubts) > 0 {
			s += " doubts=" + h.Doubts.Text()
		}
		if h.AfterDeny {
			s += " after-deny"
		}
	}
	return s
}

// The path fixture end to end: interzone-default denies the lab flow on fw02,
// the first hop, and fw01 is still evaluated, after the deny.
func TestThePathFixtureIsDeniedAtTheFirstHop(t *testing.T) {
	t.Parallel()
	r := runLab(t, lab{}, pathlab.Destination)
	want := "denied at 1 security interzone-default (default rule interzone-default (deny), built-in)" +
		" | 1 fw02/vsys1 security=stop:interzone-default" +
		" | 2 fw01/vsys1 security=stop:interzone-default after-deny"
	if got := summary(r); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if r.Path.Outcome != routing.Delivered || r.Fidelity.Level() != "exact" || len(r.Holes) != 0 || len(r.Notes) != 0 {
		t.Errorf("outcome %s, fidelity %s, holes %v, notes %v", r.Path.Outcome, r.Fidelity, r.Holes, r.Notes)
	}
	c := r.Hops[0].Checks[0]
	if c.Security == nil || c.Security.Zones.Source != "path" || !slices.Equal(c.Security.Zones.From, []string{"home"}) ||
		!slices.Equal(c.Security.Zones.To, []string{"labor"}) || c.Fidelity.Level() != "exact" || !slices.Equal(slugs(c.Stages), securitypolicy.Simulation{}.Stages()) {
		t.Errorf("hop 1 check: %+v", c)
	}
}

// The fixture's variants: the default rule's overrides on each device, and rules.
func TestThePathFixtureVariants(t *testing.T) {
	t.Parallel()
	differ := pathlab.Defaults{Local: pathlab.Entry(pathlab.Interzone, "allow"), Pushed: pathlab.Entry(pathlab.Interzone, "deny")}
	disagree := "local and pushed default rules disagree; precedence not verified"
	for _, c := range []struct {
		name string
		lab  lab
		want string
	}{
		{
			"allowed by local overrides on both",
			lab{defaults: allowAll},
			"allowed | 1 fw02/vsys1 security=pass:interzone-default | 2 fw01/vsys1 security=pass:interzone-default",
		},
		{
			"undecided on both: the overrides disagree",
			lab{defaults: both(differ)},
			"undecided at 1 security  (" + disagree + ") | 1 fw02/vsys1 security=undecided | 2 fw01/vsys1 security=undecided",
		},
		{
			"undecided, then a deny (E7)",
			lab{defaults: map[string]pathlab.Defaults{pathlab.FW02: differ}},
			"undecided at 1 security  (" + disagree + ") | 1 fw02/vsys1 security=undecided | 2 fw01/vsys1 security=stop:interzone-default",
		},
		{
			"a pass, then a deny",
			lab{defaults: map[string]pathlab.Defaults{pathlab.FW02: {Local: pathlab.Entry(pathlab.Interzone, "allow")}}},
			"denied at 2 security interzone-default (default rule interzone-default (deny), built-in) | 1 fw02/vsys1 security=pass:interzone-default | 2 fw01/vsys1 security=stop:interzone-default",
		},
		{
			"denied by a rule",
			lab{config: map[string][]byte{pathlab.FW02: withRule(t, pathlab.FW02, "block-home", "drop")}},
			"denied at 1 security block-home (rule block-home (drop)) | 1 fw02/vsys1 security=stop:block-home | 2 fw01/vsys1 security=stop:interzone-default after-deny",
		},
		{
			"allowed by a rule, then the default allows",
			lab{config: map[string][]byte{pathlab.FW02: withRule(t, pathlab.FW02, "home-out", "allow")}, defaults: allowAll},
			"allowed | 1 fw02/vsys1 security=pass:home-out | 2 fw01/vsys1 security=pass:interzone-default",
		},
	} {
		r := runLab(t, c.lab, pathlab.Destination)
		if got := summary(r); got != c.want {
			t.Errorf("%s:\ngot  %s\nwant %s", c.name, got, c.want)
		}
	}
	r := runLab(t, lab{defaults: map[string]pathlab.Defaults{pathlab.FW02: differ}}, pathlab.Destination)
	if want := "a later hop denies: hop 2 (fw01 vsys1), default rule interzone-default (deny), built-in"; !slices.Equal(r.Notes, simulate.Reasons{reason.New("note.later-deny", want)}) {
		t.Errorf("E7 note: %v", r.Notes)
	}
	// Undecided at 1 bounds the fidelity: hop 2's exact check does not raise it.
	if r.Fidelity.Level() != "undermatch" || !strings.Contains(r.Fidelity.String(), disagree) {
		t.Errorf("fidelity %s", r.Fidelity)
	}
}

// withNAT is fw02 with the default rules allowing and two NAT rules from home
// to labor that translate nothing: nat-https names service-https, which only
// the device's predefined services define, above nat-any.
func withNAT(t *testing.T) []byte {
	t.Helper()
	entry := func(name, service string) string {
		return `<entry name="` + name + `"><from><member>home</member></from><to><member>labor</member></to>` +
			`<source><member>any</member></source><destination><member>any</member></destination>` +
			`<service>` + service + `</service></entry>`
	}
	b := pathlab.Config(t, pathlab.FW02, pathlab.Defaults{Local: pathlab.Entry(pathlab.Interzone, "allow")})
	return bytes.Replace(b, []byte("<rulebase>"), []byte("<rulebase><nat><rules>"+entry("nat-https", "service-https")+entry("nat-any", "any")+"</rules></nat>"), 1)
}

// A NAT rule that may match instead of the one routing applied leaves the hop
// undecided, as a security rule in doubt does (C3, E20); the hop's doubt names
// the rule with routing's code and text. With the predefined services stored,
// the rule matches for sure and the same flow decides (lab L4b).
func TestANATDoubtLeavesThePathUndecided(t *testing.T) {
	t.Parallel()
	in := input(pathlab.Destination)
	in.Flow.Protocol, in.Flow.DestPort = "tcp", 443
	ask := func(predefined bool) Result {
		l := lab{config: map[string][]byte{pathlab.FW02: withNAT(t)}, defaults: allowAll, predefined: predefined}
		r, _, err := Run(context.Background(), l.env(t), in)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := ask(false)
	doubt := "path.nat-undermatch: nat rule nat-https may match instead: " +
		"service service-https is not defined in the configuration (a predefined service?); the snapshot holds no predefined services; " +
		"a fetch with this release stores them when the device returns them"
	if r.Verdict != VerdictUndecided || r.At == nil || r.At.Hop != 1 || r.At.Check != checkRouting ||
		!slices.Equal(codeTexts(r.Hops[0].Doubts), []string{doubt}) || r.Fidelity.Level() != "undermatch" {
		t.Errorf("without the predefined services: %s, doubts %v, fidelity %s", summary(r), codeTexts(r.Hops[0].Doubts), r.Fidelity)
	}
	if !slices.Contains(codeTexts(r.Hops[0].Routing.Notes), doubt) {
		t.Errorf("routing's note: %v", codeTexts(r.Hops[0].Routing.Notes))
	}
	r = ask(true)
	if want := "allowed | 1 fw02/vsys1 security=pass:interzone-default | 2 fw01/vsys1 security=pass:interzone-default"; summary(r) != want ||
		len(r.Hops[0].Doubts) != 0 || len(r.Hops[0].Routing.NATDoubts) != 0 {
		t.Errorf("with the predefined services:\ngot  %s\nwant %s", summary(r), want)
	}
	if !slices.ContainsFunc(r.Hops[0].Routing.Notes, func(n reason.Reason) bool {
		return n.Code == "note.nat-applied" && strings.HasPrefix(n.Text, "nat rule nat-https ")
	}) {
		t.Errorf("nat-https applies: %v", codeTexts(r.Hops[0].Routing.Notes))
	}
}

// A version gap lowers the hop's check to inferred; the hop still decides (E25).
func TestAVersionGapIsInferredNotUndecided(t *testing.T) {
	t.Parallel()
	b := pathlab.Config(t, pathlab.FW02, pathlab.Defaults{})
	b = bytes.Replace(b, []byte(`version="11.2.0"`), []byte(`version="12.2.0"`), 1)
	// The check names the gap once, whether the loader's notes carry it or not.
	for _, quiet := range []bool{false, true} {
		r := runLab(t, lab{config: map[string][]byte{pathlab.FW02: b}, quiet: quiet}, pathlab.Destination)
		c := r.Hops[0].Checks[0]
		if r.Verdict != VerdictDenied || c.Verdict != Stop || c.Fidelity.Level() != "inferred" || r.Fidelity.Level() != "inferred" {
			t.Errorf("verdict %s, hop 1 %s %s, run %s", r.Verdict, c.Verdict, c.Fidelity, r.Fidelity)
		}
		if len(c.Notes) != 1 || !strings.Contains(c.Notes[0].Text, "12.2.0") {
			t.Errorf("the gap stays a note: %v", c.Notes)
		}
		if c2 := r.Hops[1].Checks[0]; c2.Fidelity.Level() != "exact" || len(c2.Notes) != 0 {
			t.Errorf("fw01 has no gap: %s %v", c2.Fidelity, c2.Notes)
		}
	}
}

// The ends of a path: no route, a local address, a loop (spec §4.8, §5.1).
func TestTheEndsOfAPath(t *testing.T) {
	t.Parallel()
	dropped := reason.New("path.no-route", "dropped by routing before security policy")
	for _, c := range []struct {
		name, dst string
		lab       lab
		want      string
		notes     []string
	}{
		{
			"no route on fw01", "198.18.30.5",
			lab{defaults: allowAll, net: labNet(t, true)},
			"denied at 2 routing  (dropped on fw01: no route to 198.18.30.5) | 1 fw02/vsys1 security=pass:interzone-default | 2 fw01/vsys1 security=not-evaluated",
			nil,
		},
		{
			"a local address of fw02", "198.18.1.1",
			lab{},
			"allowed | 1 fw02/vsys1 security=pass:intrazone-default",
			[]string{noteLocal},
		},
		{
			"a loop back to fw02", "198.18.30.5",
			lab{defaults: allowAll},
			"undecided at 2 routing  (loop: fw02 -> fw01 -> fw02) | 1 fw02/vsys1 security=pass:interzone-default | 2 fw01/vsys1 security=pass:intrazone-default",
			nil,
		},
	} {
		r := runLab(t, c.lab, c.dst)
		if got := summary(r); got != c.want || !slices.Equal(r.Notes.Texts(), c.notes) {
			t.Errorf("%s:\ngot  %s %v\nwant %s %v", c.name, got, r.Notes, c.want, c.notes)
		}
		if last := r.Hops[len(r.Hops)-1]; last.Checks[0].Verdict == NotEvaluated && !slices.Equal(last.Checks[0].Reason, simulate.Reasons{dropped}) {
			t.Errorf("%s: reason %q", c.name, last.Checks[0].Reason)
		}
	}
}

// A hop routing dropped carries the path's end code on each check it did not
// evaluate, not a code of its own.
func TestADroppedHopCarriesTheEndCode(t *testing.T) {
	t.Parallel()
	r := runLab(t, lab{defaults: allowAll, net: labNet(t, true)}, "198.18.30.5")
	last := r.Hops[len(r.Hops)-1]
	if r.Path.Outcome != routing.Dropped || r.Path.EndCode != "path.no-route" {
		t.Fatalf("path %s %s", r.Path.Outcome, r.Path.EndCode)
	}
	for _, c := range last.Checks {
		if c.Verdict != NotEvaluated || c.Reason[0].Code != r.Path.EndCode {
			t.Errorf("%s: %s %+v", c.Name, c.Verdict, c.Reason)
		}
	}
}

// A configuration that cannot be read is a hole, once, and leaves its hop
// undecided (spec §4.7).
func TestAnUnreadableConfigurationIsAHole(t *testing.T) {
	t.Parallel()
	r := runLab(t, lab{defaults: allowAll, fail: pathlab.FW01}, pathlab.Destination)
	why := "the configuration of fw01 vsys1 cannot be read: snapshot unreadable"
	want := "undecided at 2 routing  (" + why + ") | 1 fw02/vsys1 security=pass:interzone-default | 2 fw01/vsys1 security=undecided doubts=" + why
	if got := summary(r); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if !slices.Equal(r.Holes, []simulate.Missing{{Device: pathlab.FW01, Reason: why, Code: "gap.load-failed"}}) {
		t.Errorf("holes %v", r.Holes)
	}
}

// Routing's errors return unchanged; a check's error other than missing data
// stops the run.
func TestErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := lab{}.env(t)
	in := input(pathlab.Destination)
	in.Flow.Source = simulate.Endpoint{}
	if _, _, err := Run(ctx, e, in); !isType[*simulate.ChoiceError](err) {
		t.Errorf("no source and no start: %v", err)
	}
	gone := lab{net: network{gone: pathlab.FW02}}.env(t)
	in = input(pathlab.Destination)
	in.Params = map[string]string{"device": pathlab.FW02}
	if _, _, err := Run(ctx, gone, in); !isType[*simulate.UnavailableError](err) {
		t.Errorf("an unavailable start: %v", err)
	}
	if _, _, err := Run(ctx, &simulate.Env{Load: e.Load}, input(pathlab.Destination)); err == nil || isType[*simulate.ChoiceError](err) {
		t.Errorf("no network: %v", err)
	}
	if _, _, err := Run(ctx, &simulate.Env{Network: e.Network}, input(pathlab.Destination)); err == nil {
		t.Error("no loader")
	}
	boom := errors.New("boom")
	if _, _, err := run(ctx, e, input(pathlab.Destination), []Check{fake{err: boom}}); !errors.Is(err, boom) {
		t.Errorf("a check's error: %v", err)
	}
	miss := &simulate.UnavailableError{Missing: []simulate.Missing{{Device: "fw02", Reason: "gone"}}}
	r, _, err := run(ctx, e, input(pathlab.Destination), []Check{fake{r: CheckResult{Name: "fake", Verdict: Undecided, Reason: simulate.Reasons{reason.New("gap.load-failed", "gone")}}, err: miss}})
	if err != nil || len(r.Holes) != 1 || r.Verdict != VerdictUndecided || r.At.Check != "fake" {
		t.Errorf("a check's missing data: %v, %v, %+v", err, r.Holes, r.At)
	}
}

func isType[T error](err error) bool {
	_, ok := errors.AsType[T](err)
	return ok
}

// fake is a check with a fixed answer.
type fake struct {
	r   CheckResult
	err error
}

func (f fake) Name() string { return "fake" }

func (f fake) Evaluate(context.Context, *simulate.Env, routing.Hop, simulate.Flow) (CheckResult, error) {
	return f.r, f.err
}

// The security check on its own: what it does not evaluate, and an error of the
// policy run after the hop's configuration loaded.
func TestTheSecurityCheck(t *testing.T) {
	t.Parallel()
	e := lab{}.env(t)
	h := routing.Hop{Device: pathlab.FW02, Vsys: "vsys1"}
	f := input(pathlab.Destination).Flow
	r, err := Security{}.Evaluate(context.Background(), e, h, f)
	if err != nil || r.Verdict != NotEvaluated || !r.Fidelity.Declared() || r.Name != "security" || r.Reason[0].Code != "zone.missing" {
		t.Errorf("no zones: %+v, %v", r, err)
	}
	if r, _ := (Security{}).Evaluate(context.Background(), e, routing.Hop{Device: pathlab.FW02}, f); r.Reason[0].Code != "zone.vsys-unknown" {
		t.Errorf("no vsys: %+v", r)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancelling := *e
	cancelling.Load = func(device, vsys string) (simulate.Target, error) {
		cancel()
		return e.Load(device, vsys)
	}
	f.FromZone, f.ToZone = "home", "labor"
	if _, err := (Security{}).Evaluate(ctx, &cancelling, h, f); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled run: %v", err)
	}
	nilCfg := *e
	nilCfg.Load = func(string, string) (simulate.Target, error) { return simulate.Target{}, nil }
	r, err = Security{}.Evaluate(context.Background(), &nilCfg, h, f)
	if !isType[*simulate.UnavailableError](err) || r.Verdict != Undecided || r.Fidelity.Level() != "undermatch" ||
		!slices.Equal(r.Reason, simulate.Reasons{reason.New("gap.config-missing", "the configuration of fw02 vsys1 cannot be read: no configuration")}) {
		t.Errorf("no configuration: %+v, %v", r, err)
	}
}

// Each endpoint keeps the address routing traced, the first, and its FQDN name.
func TestTheCheckKeepsTheTracedAddress(t *testing.T) {
	t.Parallel()
	a, b := netip.MustParseAddr("198.18.10.100"), netip.MustParseAddr("203.0.113.9")
	f := simulate.Flow{
		Source:      simulate.Addr(netip.MustParseAddr(pathlab.Source)),
		Destination: simulate.Endpoint{Name: "srv.example.com", Addrs: []netip.Addr{a, b}, Resolved: true},
	}
	got := f.FirstAddresses()
	if d := got.Destination; d.Name != "srv.example.com" || !slices.Equal(d.Addrs, []netip.Addr{a}) || !d.Resolved {
		t.Errorf("destination %+v", d)
	}
	if len(f.Destination.Addrs) != 2 || len(got.Source.Addrs) != 1 {
		t.Errorf("the input changed: %+v", f)
	}
	// The run with an FQDN destination checks the traced address on each hop.
	l := lab{}
	in := input(pathlab.Destination)
	in.Flow.Destination = f.Destination
	r, _, err := Run(context.Background(), l.env(t), in)
	if err != nil || r.Verdict != VerdictDenied {
		t.Fatalf("%v, %s", err, summary(r))
	}
	if d := r.Hops[0].Checks[0].Stages[1]; d.Slug != "resolve-destination" || d.Fidelity.Level() != "inferred" {
		t.Errorf("the resolved FQDN is inferred: %s %s", d.Slug, d.Fidelity)
	}
}

// slugs are the stages' slugs, in order.
func slugs(stages []simulate.Stage) []string {
	out := make([]string, len(stages))
	for i, st := range stages {
		out[i] = st.Slug
	}
	return out
}

// Run reads each hop's target once, though the zone check, the security check
// and securitypolicy each ask for it.
func TestEachTargetLoadsOnce(t *testing.T) {
	t.Parallel()
	env := lab{}.env(t)
	loads := map[string]int{}
	load := env.Load
	env.Load = func(device, vsys string) (simulate.Target, error) {
		loads[device+"/"+vsys]++
		return load(device, vsys)
	}
	if _, _, err := Run(context.Background(), env, input(pathlab.Destination)); err != nil {
		t.Fatal(err)
	}
	for k, n := range loads {
		if n != 1 {
			t.Errorf("%s loaded %d times", k, n)
		}
	}
	if len(loads) != 2 {
		t.Errorf("loads = %v", loads)
	}
}
