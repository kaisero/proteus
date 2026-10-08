package securitypolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate"
)

// The decision tree of spec §4.7, on the doubt fixture, read with its own schema
// and with an older one (spec E25). The first three flows follow the device checks
// on fw02 (2026-10-08).
func TestDecision(t *testing.T) {
	t.Parallel()
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
	flow := func(src, dst, from, to, proto string, port uint16) simulate.Flow {
		return simulate.Flow{Source: ep(src), Destination: ep(dst), FromZone: from, ToZone: to, Protocol: proto, DestPort: port}
	}
	for _, c := range []struct {
		name     string
		flow     simulate.Flow
		outcome  Outcome
		reason   string
		fidelity string // the first-match stage's
	}{
		{
			"the first candidate is certain",
			flow("198.18.1.68", "192.0.2.1", "home", "wan", "udp", 443),
			Stop, "rule block-udp-443 (deny)", "exact",
		},
		{
			"earlier candidates in doubt share the action",
			flow("198.18.1.10", "192.0.2.9", "home", "wan", "tcp", 443),
			Pass, "rule internet (allow)",
			"overmatch: earlier candidates in doubt share the action allow: app-one, app-two; not evaluated: application",
		},
		{
			"no candidate: the default rule",
			flow("198.19.0.254", "198.18.1.10", "labor", "home", "tcp", 22),
			Stop, "default rule interzone-default (deny), built-in", "exact",
		},
		{
			"an earlier candidate in doubt has another action",
			flow("10.0.0.5", "203.0.113.5", "dmz", "wan", "tcp", 443),
			Undecided, `dmz-user (deny) at position 7 may match first: user not evaluated (corp\alice)`,
			`undermatch: dmz-user (deny) at position 7 may match first: user not evaluated (corp\alice); not evaluated: application, user`,
		},
		{
			"candidates in doubt share the default's action",
			flow("198.19.0.254", "10.2.0.5", "labor", "dmz", "tcp", 443),
			Stop, "default rule interzone-default (deny), built-in",
			"overmatch: earlier candidates in doubt share the action deny: labor-app; not evaluated: application",
		},
		{
			"a candidate in doubt has another action than the default",
			flow("10.0.0.5", "192.0.2.9", "home", "wan", "tcp", 443),
			Undecided, "app-one (allow) at position 3 may match first: service application-default",
			"undermatch: app-one (allow) at position 3 may match first: service application-default; not evaluated: application",
		},
		{
			"every candidate in doubt, and no default without known zones",
			flow("10.0.0.5", "192.0.2.9", "nowhere", "wan", "tcp", 443),
			Undecided, "the default rule depends on the zones",
			"undermatch: the default rule depends on the zones; not evaluated: application",
		},
	} {
		for _, e := range []*simulate.Env{env(t, "firewall-doubt.xml", false), envPath(t, gapped, false)} {
			r, v := run(t, e, c.flow)
			got, why := v.Decision()
			fm := stage(r, "first-match")
			if got != c.outcome || why != c.reason || fm.Fidelity.String() != c.fidelity {
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

func TestDecisionOfAVerdict(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		v       Verdict
		outcome Outcome
		reason  string
	}{
		{Verdict{}, Undecided, "no rule decides"},
		{Verdict{Rule: &resolve.Rule{Name: "r", Action: "reset-both"}}, Stop, "rule r (reset-both)"},
		{Verdict{Rule: &resolve.Rule{Name: "r", Action: "allow"}}, Pass, "rule r (allow)"},
		{Verdict{Rule: &resolve.Rule{Name: "r", Action: "maybe"}}, Undecided, "rule r (maybe) is not a security rule action"},
		{Verdict{Rule: &resolve.Rule{Name: "r", Action: "allow"}, Undecided: "doubt"}, Undecided, "doubt"},
		{Verdict{Default: "intrazone-default", DefaultAction: "allow", DefaultSource: "local"}, Pass, "default rule intrazone-default (allow), local"},
	} {
		if got, why := c.v.Decision(); got != c.outcome || why != c.reason {
			t.Errorf("%+v: %s, %q; want %s, %q", c.v, got, why, c.outcome, c.reason)
		}
	}
}
