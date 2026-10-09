package pathpolicy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/simulate/routing"
)

// check is a security check result with a verdict; a stop or pass names rule r.
func check(v HopVerdict, f simulate.Fidelity) CheckResult {
	c := CheckResult{Name: checkSecurity, Verdict: v, Reason: reason.New("verdict.rule", string(v)+" reason"), Fidelity: f}
	if v == Pass || v == Stop {
		c.Rule = "r-" + string(v)
	}
	return c
}

// hops builds synthetic hops: each spec is the checks' verdicts, comma separated,
// and "doubt" for a hop the path leaves undecided.
func hops(specs ...string) []Hop {
	var out []Hop
	for i, s := range specs {
		h := Hop{Index: i + 1, Routing: routing.Hop{Device: fmt.Sprintf("fw%d", i+1), Vsys: "vsys1"}}
		for _, v := range strings.Split(s, ",") {
			if v == "doubt" {
				h.Doubts = append(h.Doubts, reason.New("path.ecmp", "ECMP: 1 other next hops not followed"))
				h.Checks = append(h.Checks, check(Pass, simulate.Exact))
				continue
			}
			h.Checks = append(h.Checks, check(HopVerdict(v), simulate.Exact))
		}
		out = append(out, h)
	}
	return out
}

func folded(outcome routing.Outcome, hs []Hop) Result {
	r := Result{Path: routing.Path{Outcome: outcome, End: "end of " + string(outcome), EndCode: "path.loop"}, Hops: hs}
	fold(&r, simulate.Exact)
	return r
}

// Every row of spec §5.1 and §5.2.
func TestFold(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		outcome routing.Outcome
		hops    []string
		want    string
		after   []int    // hops that carry AfterDeny
		notes   []string // beyond none
	}{
		// §5.2
		{"pass, pass, delivered", routing.Delivered, []string{"pass", "pass"}, "allowed", nil, nil},
		{"pass, stop, pass", routing.Delivered, []string{"pass", "stop", "pass"}, "denied at 2 security r-stop (stop reason)", []int{3}, nil},
		{
			"undecided, stop", routing.Delivered,
			[]string{"undecided", "stop"},
			"undecided at 1 security  (undecided reason)", nil,
			[]string{"a later hop denies: hop 2 (fw2 vsys1), stop reason"},
		},
		{"pass, pass, left-estate", routing.LeftEstate, []string{"pass", "pass"}, "undecided at 2 routing  (end of left-estate)", nil, nil},
		{"pass, no route", routing.Dropped, []string{"pass", "not-evaluated"}, "denied at 2 routing  (end of dropped)", nil, nil},
		{"stop (default deny)", routing.Delivered, []string{"stop"}, "denied at 1 security r-stop (stop reason)", nil, nil},
		{"pass with ECMP on hop 1", routing.Delivered, []string{"doubt"}, "undecided at 1 routing  (ECMP: 1 other next hops not followed)", nil, nil},
		{"undecided and stop on hop 1", routing.Delivered, []string{"stop,undecided"}, "undecided at 1 security  (undecided reason)", nil, nil},
		// §5.1, the rows the examples leave out
		{"undecided, nothing later stops", routing.Delivered, []string{"undecided", "pass"}, "undecided at 1 security  (undecided reason)", nil, nil},
		{
			"undecided, stop, stop: only the first later stop is named", routing.Delivered,
			[]string{"undecided", "stop", "stop"},
			"undecided at 1 security  (undecided reason)",
			[]int{3},
			[]string{"a later hop denies: hop 2 (fw2 vsys1), stop reason"},
		},
		{"stop, then undecided", routing.Delivered, []string{"stop", "undecided"}, "denied at 1 security r-stop (stop reason)", []int{2}, nil},
		{"left by interface", routing.LeftByInterface, []string{"pass"}, "undecided at 1 routing  (end of left-by-interface)", nil, nil},
		{"loop", routing.Loop, []string{"pass", "pass"}, "undecided at 2 routing  (end of loop)", nil, nil},
		{"too long", routing.TooLong, []string{"pass"}, "undecided at 1 routing  (end of too-long)", nil, nil},
		{"unresolved", routing.Unresolved, []string{"pass"}, "undecided at 1 routing  (end of unresolved)", nil, nil},
		{"local", routing.Local, []string{"pass"}, "allowed", nil, []string{noteLocal}},
		{"a stop on a dropped path", routing.Dropped, []string{"stop", "not-evaluated"}, "denied at 1 security r-stop (stop reason)", []int{2}, nil},
	} {
		r := folded(c.outcome, hops(c.hops...))
		got := string(r.Verdict)
		if r.At != nil {
			got += fmt.Sprintf(" at %d %s %s (%s)", r.At.Hop, r.At.Check, r.At.Rule, r.At.Reason.Text)
		}
		var after []int
		for _, h := range r.Hops {
			if h.AfterDeny {
				after = append(after, h.Index)
			}
		}
		if got != c.want || !slices.Equal(after, c.after) || !slices.Equal(r.Notes, c.notes) {
			t.Errorf("%s:\ngot  %s, after %v, notes %v\nwant %s, after %v, notes %v", c.name, got, after, r.Notes, c.want, c.after, c.notes)
		}
	}
}

// The fidelity is the weakest of routing's and of the checks up to the point;
// checks after it do not lower it (spec §5.3).
func TestFoldFidelity(t *testing.T) {
	t.Parallel()
	hs := hops("pass", "stop", "pass")
	hs[0].Checks[0].Fidelity = simulate.OverMatchBecause(reason.New("doubt.service-kept", "hop 1"))
	hs[2].Checks[0].Fidelity = simulate.UnderMatch(reason.New("gap.object-unresolved", "hop 3"))
	r := Result{Path: routing.Path{Outcome: routing.Delivered}, Hops: hs}
	fold(&r, simulate.Inferred)
	if got := r.Fidelity.String(); got != "inferred: hop 1" {
		t.Errorf("up to the stop: %s", got)
	}
	hs = hops("pass", "pass")
	hs[1].Checks[0].Fidelity = simulate.Inferred
	r = folded(routing.Delivered, hs)
	if r.Fidelity.Level() != "inferred" {
		t.Errorf("allowed: every hop counts: %s", r.Fidelity)
	}
	// A hop undecided by its path is undermatch, though its check said exact.
	r = folded(routing.Delivered, hops("doubt", "pass"))
	if got := r.Fidelity.String(); r.Verdict != VerdictUndecided || got != "undermatch: ECMP: 1 other next hops not followed" {
		t.Errorf("a doubt up to the point: %s %s", r.Verdict, got)
	}
}

// Hidden firewalls give a note; the verdict does not change (spec E17).
func TestHiddenFirewallsAreANote(t *testing.T) {
	t.Parallel()
	r := Result{Path: routing.Path{Outcome: routing.Delivered, Hidden: []string{"fw9 (Layer 2 or virtual wire)"}}, Hops: hops("pass")}
	fold(&r, simulate.Exact)
	if r.Verdict != VerdictAllowed || !slices.Equal(r.Notes, []string{"firewalls that may sit on the path unseen are not checked: fw9 (Layer 2 or virtual wire)"}) {
		t.Errorf("%s %v", r.Verdict, r.Notes)
	}
}

// Every row of spec §4.5.
func TestPathDoubts(t *testing.T) {
	t.Parallel()
	stage := func(n int, name string, f simulate.Fidelity) simulate.Stage {
		return simulate.Stage{Slug: fmt.Sprintf("hop%d/%s", n, name), Fidelity: f}
	}
	two := []routing.Hop{{Device: "fw02"}, {Device: "fw01"}}
	for _, c := range []struct {
		name   string
		path   routing.Path
		n      int
		stages []simulate.Stage
		doubts []string
		capped bool
	}{
		{"connected start, nothing on the path", routing.Path{Hops: two}, 1, []simulate.Stage{stage(1, "pbf", simulate.Exact), stage(1, "nat", simulate.Exact)}, nil, false},
		{
			"ECMP",
			routing.Path{Hops: []routing.Hop{{ECMP: []routing.NotFollowed{{NextHop: "a"}, {NextHop: "b"}}}}},
			1, nil,
			[]string{"path.ecmp: ECMP: 2 other next hops not followed"},
			false,
		},
		{"a PBF rule can match", routing.Path{Hops: []routing.Hop{{PBF: []string{"to-isp2"}}}}, 1, nil, []string{"path.pbf: PBF rule to-isp2 can redirect the flow"}, false},
		{"PBF stage undermatch", routing.Path{Hops: two}, 2, []simulate.Stage{stage(2, "pbf", simulate.UnderMatch(reason.New("gap.object-unresolved", "pbf: an unresolved address")))}, []string{"gap.object-unresolved: pbf: an unresolved address"}, false},
		{"PBF stage inferred: no effect beyond the stage", routing.Path{Hops: two}, 2, []simulate.Stage{stage(2, "pbf", simulate.Inferred)}, nil, false},
		{"NAT stage undermatch", routing.Path{Hops: two}, 2, []simulate.Stage{stage(2, "nat", simulate.UnderMatch(reason.New("gap.nat-static", "nat: a rule in doubt")))}, []string{"gap.nat-static: nat: a rule in doubt"}, false},
		{"NAT stage inferred", routing.Path{Hops: two}, 2, []simulate.Stage{stage(2, "nat", simulate.Inferred)}, nil, true},
		{"another hop's stage", routing.Path{Hops: two}, 1, []simulate.Stage{stage(2, "nat", simulate.UnderMatch(reason.New("gap.nat-static", "hop 2")))}, nil, false},
		{
			"start by a default route",
			routing.Path{Hops: two, StartVia: netip.MustParsePrefix("0.0.0.0/0")},
			1, nil,
			[]string{"path.start-default-route: the ingress is a guess from a default route"},
			false,
		},
		{"start by a route", routing.Path{Hops: two, StartVia: netip.MustParsePrefix("198.18.0.0/15")}, 1, nil, nil, true},
		{"the start route on hop 2: no effect", routing.Path{Hops: two, StartVia: netip.MustParsePrefix("0.0.0.0/0")}, 2, nil, nil, false},
	} {
		doubts, caps := pathDoubts(c.path, c.n, c.stages)
		capped := len(caps) > 0 && simulate.Weakest(caps...).Level() == "inferred"
		if !slices.Equal(codeTexts(doubts), c.doubts) || capped != c.capped {
			t.Errorf("%s: doubts %q, caps %v; want %q, capped %v", c.name, doubts, caps, c.doubts, c.capped)
		}
	}
}

// Every rule of spec §4.4.
func TestZoneDoubts(t *testing.T) {
	t.Parallel()
	e := lab{}.env(t)
	hop := func(vsys, from, to string, placeholder bool) routing.Hop {
		return routing.Hop{Device: pathlab.FW02, Vsys: vsys, Flow: simulate.Flow{FromZone: from, ToZone: to}, ZonePlaceholder: placeholder}
	}
	for _, c := range []struct {
		name   string
		env    *simulate.Env
		hop    routing.Hop
		doubts []string
		holes  int
	}{
		{"both zones defined", e, hop("vsys1", "home", "labor", false), nil, 0},
		{"vsys unknown", e, hop("", "home", "labor", false), []string{"zone.vsys-unknown: vsys unknown"}, 0},
		{"placeholder", e, hop("vsys1", "external", "labor", true), []string{"zone.placeholder: the zone names are placeholders: no external zone joins these vsys in the configuration"}, 0},
		{"no egress zone", e, hop("vsys1", "home", "", false), []string{"zone.missing: routing found no egress zone"}, 0},
		{"no zone at all", e, hop("vsys1", "", "", false), []string{"zone.missing: routing found no ingress zone", "zone.missing: routing found no egress zone"}, 0},
		{"one undefined", e, hop("vsys1", "home", "wan", false), []string{"zone.undefined: zone wan is not defined in vsys1"}, 0},
		{"the same undefined zone, once", e, hop("vsys1", "wan", "wan", false), []string{"zone.undefined: zone wan is not defined in vsys1"}, 0},
		{
			"an unreadable configuration", lab{fail: pathlab.FW02}.env(t), hop("vsys1", "home", "labor", false),
			[]string{"gap.load-failed: the configuration of fw02 vsys1 cannot be read: snapshot unreadable"},
			1,
		},
	} {
		doubts, holes := zoneDoubts(c.env, c.hop)
		if !slices.Equal(codeTexts(doubts), c.doubts) || len(holes) != c.holes {
			t.Errorf("%s: %q, %v; want %q, %d holes", c.name, doubts, holes, c.doubts, c.holes)
		}
	}
}

// A target without an index is no configuration either.
func TestLoadNeedsAnIndex(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load(pathlab.ConfigFile(pathlab.FW02))
	if err != nil {
		t.Fatal(err)
	}
	e := &simulate.Env{Load: func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg}, nil }}
	if _, m := load(e, routing.Hop{Device: pathlab.FW02, Vsys: "vsys1"}); m == nil || !strings.HasSuffix(m.Reason, "no configuration") || m.Code != "gap.config-missing" {
		t.Errorf("%v", m)
	}
	idx, err := index.For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
	if err != nil {
		t.Fatal(err)
	}
	e.Load = func(string, string) (simulate.Target, error) { return simulate.Target{Config: cfg, Index: idx}, nil }
	if _, m := load(e, routing.Hop{Device: pathlab.FW02, Vsys: "vsys1"}); m != nil {
		t.Errorf("%v", m)
	}
}

// A routing end's reason is routing's end line without its column padding.
func TestARoutingEndReadsAsASentence(t *testing.T) {
	t.Parallel()
	r := Result{Path: routing.Path{
		Outcome: routing.LeftEstate, End: "192.168.0.1   leaves the estate (not in the inventory)", EndCode: "path.left-estate",
	}, Hops: hops("pass")}
	fold(&r, simulate.Exact)
	if r.At == nil || r.At.Reason != reason.New("path.left-estate", "192.168.0.1 leaves the estate (not in the inventory)") {
		t.Errorf("point: %+v", r.At)
	}
}

// codeTexts lists reasons as "code: text".
func codeTexts(rs simulate.Reasons) []string {
	var out []string
	for _, r := range rs {
		out = append(out, string(r.Code)+": "+r.Text)
	}
	return out
}
