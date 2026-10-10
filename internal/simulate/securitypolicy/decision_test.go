package securitypolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// The decision tree of spec §4.7, on the doubt fixture, read with its own schema
// and with an older one (spec E25). The first three flows follow the device checks
// on fw02 (2026-10-08).
func TestDecision(t *testing.T) {
	t.Parallel()
	gapped := gappedDoubt(t)
	flow := func(src, dst, from, to, proto string, port uint16) simulate.Flow {
		return simulate.Flow{Source: ep(src), Destination: ep(dst), FromZone: from, ToZone: to, Protocol: proto, DestPort: port}
	}
	for _, c := range []struct {
		name     string
		flow     simulate.Flow
		outcome  Outcome
		reason   string
		code     reason.Code
		fidelity string // the first-match stage's
	}{
		{
			"the first candidate is certain",
			flow("198.18.1.68", "192.0.2.1", "home", "wan", "udp", 443),
			Stop, "rule block-udp-443 (deny)", "verdict.rule", "exact",
		},
		{
			"earlier candidates in doubt share the action",
			flow("198.18.1.10", "192.0.2.9", "home", "wan", "tcp", 443),
			Pass, "rule internet (allow)", "verdict.rule",
			"overmatch: earlier candidates in doubt share the action allow: app-one, app-two; not evaluated: application",
		},
		{
			"no candidate: the default rule",
			flow("198.19.0.254", "198.18.1.10", "labor", "home", "tcp", 22),
			Stop, "default rule interzone-default (deny), built-in", "verdict.default", "exact",
		},
		{
			"an earlier candidate in doubt has another action",
			flow("10.0.0.5", "203.0.113.5", "dmz", "wan", "tcp", 443),
			Undecided, `dmz-user (deny) at position 7 may match first: user not evaluated (corp\alice)`, "doubt.not-evaluated.user",
			`undermatch: dmz-user (deny) at position 7 may match first: user not evaluated (corp\alice); not evaluated: application, user`,
		},
		{
			"candidates in doubt share the default's action",
			flow("198.19.0.254", "10.2.0.5", "labor", "dmz", "tcp", 443),
			Stop, "default rule interzone-default (deny), built-in", "verdict.default",
			"overmatch: earlier candidates in doubt share the action deny: labor-app; not evaluated: application",
		},
		{
			"a candidate in doubt has another action than the default",
			flow("10.0.0.5", "192.0.2.9", "home", "wan", "tcp", 443),
			Undecided, "app-one (allow) at position 3 may match first: service application-default", "doubt.service-application-default",
			"undermatch: app-one (allow) at position 3 may match first: service application-default; not evaluated: application",
		},
		{
			"every candidate in doubt, and no default without known zones",
			flow("10.0.0.5", "192.0.2.9", "nowhere", "wan", "tcp", 443),
			Undecided, "the default rule depends on the zones", "default.zones-unknown",
			"undermatch: the default rule depends on the zones; not evaluated: application",
		},
	} {
		for _, e := range []*simulate.Env{env(t, "firewall-doubt.xml", false), envPath(t, gapped, false)} {
			r, v := run(t, e, c.flow)
			got, why := v.Decision()
			fm := stage(r, "first-match")
			if got != c.outcome || why.Text() != c.reason || why[0].Code != c.code || fm.Fidelity.String() != c.fidelity {
				t.Errorf("%s: %s, %q, first-match %s\nwant %s, %q, %s\n(%s)", c.name, got, why, fm.Fidelity, c.outcome, c.reason, c.fidelity, fm.Detail)
			}
			for _, st := range r.Stages {
				if len(st.Unresolved) > 0 {
					t.Errorf("%s: %s has unresolved %v", c.name, st.Slug, st.Unresolved)
				}
			}
		}
	}
	// The gap makes the run inferred, never more certain.
	r, _ := run(t, envPath(t, gapped, false), flow("198.18.1.68", "192.0.2.1", "home", "wan", "udp", 443))
	if r.Fidelity.Level() != "inferred" {
		t.Errorf("a version gap is inferred: %s", r.Fidelity)
	}
}

// gappedDoubt writes the doubt fixture as PAN-OS 12.2, which this build reads with
// the 11.2 schema, and returns its path.
func gappedDoubt(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../../../testdata/config/firewall-doubt.xml")
	if err != nil {
		t.Fatal(err)
	}
	gapped := filepath.Join(t.TempDir(), "doubt-12.2.xml")
	doc := strings.Replace(string(src), `version="11.2.0" urldb="paloaltonetworks" detail-version="11.2.5"`,
		`version="12.2.0" urldb="paloaltonetworks" detail-version="12.2.3"`, 1)
	if err := os.WriteFile(gapped, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return gapped
}

func TestDecisionOfAVerdict(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		v       Verdict
		outcome Outcome
		code    reason.Code
		reason  string
	}{
		{Verdict{}, Undecided, "default.none", "no rule decides"},
		{Verdict{Rule: &resolve.Rule{Name: "r", Action: "reset-both"}}, Stop, "verdict.rule", "rule r (reset-both)"},
		{Verdict{Rule: &resolve.Rule{Name: "r", Action: "allow"}}, Pass, "verdict.rule", "rule r (allow)"},
		{Verdict{Rule: &resolve.Rule{Name: "r", Action: "maybe"}}, Undecided, "doubt.invalid-action", "rule r (maybe) is not a security rule action"},
		{
			Verdict{Rule: &resolve.Rule{Name: "r", Action: "allow"}, Undecided: simulate.Reasons{reason.New("doubt.application", "doubt")}},
			Undecided, "doubt.application", "doubt",
		},
		{Verdict{Default: "intrazone-default", DefaultAction: "allow", DefaultSource: "local"}, Pass, "verdict.default", "default rule intrazone-default (allow), local"},
		{Verdict{Default: "intrazone-default", DefaultAction: "maybe", DefaultSource: "local"}, Undecided, "default.invalid-action", "default rule intrazone-default (maybe), local is not a security rule action"},
	} {
		if got, why := c.v.Decision(); got != c.outcome || why.Text() != c.reason || why[0].Code != c.code {
			t.Errorf("%+v: %s, %q; want %s, %q", c.v, got, why, c.outcome, c.reason)
		}
	}
}

// A stage that may be missing matches leaves the flow undecided, whatever a later
// rule says: the rule the device hits may be among those missed (spec §4.7). A
// version gap alone is inferred, so the flow stays decided (E25).
func TestAnUndermatchLeavesTheFlowUndecided(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name    string
		env     *simulate.Env
		flow    simulate.Flow
		outcome Outcome
		reason  string
	}{
		{
			"an FQDN that resolves to no address",
			env(t, "firewall-simulate.xml", false),
			simulate.Flow{Source: ep("10.0.0.1"), Destination: simulate.Endpoint{Name: "www.example.com"}},
			Undecided, "www.example.com resolved to no address",
		},
		{
			"an object the configuration cannot resolve",
			env(t, "firewall-urlcat-edge.xml", false),
			simulate.Flow{Source: ep("10.0.0.1"), Destination: ep("10.0.0.2"), URL: "good.example.com"},
			Undecided, "a Category Match category lists predefined URL categories, whose contents are in the PAN-DB cloud",
		},
		{
			"a version gap alone",
			envPath(t, gappedDoubt(t), false),
			simulate.Flow{Source: ep("198.18.1.68"), Destination: ep("192.0.2.1"), FromZone: "home", ToZone: "wan", Protocol: "udp", DestPort: 443},
			Stop, "rule block-udp-443 (deny)",
		},
	} {
		r, v := run(t, c.env, c.flow)
		got, why := v.Decision()
		if got != c.outcome || !strings.HasPrefix(why.Text(), c.reason) || strings.Contains(why.Text(), "kept rules") {
			t.Errorf("%s: %s, %q; want %s, %q (fidelity %s)", c.name, got, why, c.outcome, c.reason, r.Fidelity)
		}
		if got == Undecided && r.Fidelity.Level() != "undermatch" {
			t.Errorf("%s: fidelity %s", c.name, r.Fidelity)
		}
	}
}

// An undecided reason names only what may be missing: an overmatch reason of the
// same stage stays out of it.
func TestUndermatchedKeepsOnlyUndermatchReasons(t *testing.T) {
	t.Parallel()
	stages := []simulate.Stage{
		{Slug: "match-service", Fidelity: simulate.OverMatchBecause(reason.New("doubt.service-kept", "kept rules whose service is application-default"))},
		{Slug: "match-url", Fidelity: simulate.Weakest(
			simulate.OverMatchBecause(reason.New("doubt.category-undefined",
				"kept rules naming a category the configuration does not define, such as a PAN-DB category: r1")),
			simulate.UnderMatch(reason.New("gap.category-match", "cat-x cannot be matched")),
			simulate.UnderMatch(reason.New("gap.object-unresolved", "y is unknown")))},
	}
	// Several undermatch reasons stay parts, each with its code.
	if got := undermatched(stages); !slices.Equal(got, simulate.Reasons{
		reason.New("gap.category-match", "cat-x cannot be matched"), reason.New("gap.object-unresolved", "y is unknown"),
	}) {
		t.Errorf("undermatched = %q", got)
	}
}

// Format 2 writes undecided as its parts, each with its code, and leaves it out
// when the flow is decided.
func TestVerdictJSONWritesUndecidedParts(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(Verdict{Undecided: simulate.Reasons{reason.New("default.none", "no rule decides")}})
	if err != nil || !strings.Contains(string(b), `"undecided":[{"code":"default.none","text":"no rule decides"}]`) {
		t.Errorf("%s %v", b, err)
	}
	b, err = json.Marshal(Verdict{Default: "intrazone-default"})
	if err != nil || strings.Contains(string(b), "undecided") || !strings.Contains(string(b), `"default":"intrazone-default"`) {
		t.Errorf("%s %v", b, err)
	}
}
