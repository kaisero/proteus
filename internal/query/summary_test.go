package query

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/simulate/pathlab"
)

// summaryJSON is an envelope's summary results as JSON.
func summaryJSON[In, R, S any](t *testing.T, e Envelope[In, R], f func(R) S) string {
	t.Helper()
	s := Summarize(e, f)
	if s.Detail != DetailSummary || len(s.Results) != len(e.Results) {
		t.Fatalf("detail %s, %d results of %d", s.Detail, len(s.Results), len(e.Results))
	}
	b, err := json.Marshal(s.Results)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Each summary keeps the answer, drops the long parts, and prints its lists as
// [] when empty (spec 2026-10-09 §3.5, U5).
func TestSummaries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	check := func(name, got string, has, hasNot []string) {
		t.Helper()
		for _, h := range has {
			if !strings.Contains(got, h) {
				t.Errorf("%s: no %s in %s", name, h, got)
			}
		}
		for _, h := range hasNot {
			if strings.Contains(got, h) {
				t.Errorf("%s: %s in %s", name, h, got)
			}
		}
	}

	pe, err := Policy(ctx, labEnv(t, pathlab.FW01, pathlab.FW02), PolicyInput{Flow: labFlow()})
	if err != nil {
		t.Fatal(err)
	}
	check("path", summaryJSON(t, pe, PathResult.Summary), []string{`"answer":"denied at hop`, `"hops":[{"index":1`, `"route":"`, `"checks":[`},
		[]string{`"stages"`, `"candidates"`, `"lookups"`, `"in":`})

	fe, err := PolicyFile(ctx, Env{}, PolicyFileInput{
		Flow:      FlowInput{Source: "10.1.0.5", Destination: "10.2.0.5", Protocol: "tcp", Port: "443"},
		Selection: Selection{File: fixture("firewall-zones.xml")},
	})
	if err != nil {
		t.Fatal(err)
	}
	check("file", summaryJSON(t, fe, SecurityResult.Summary), []string{`"answer":"first match: from-inside (allow)"`, `"doubts":[]`, `"target":`},
		[]string{`"candidates"`, `"stages"`, `"needs"`})

	ne, err := NAT(ctx, natEnv(t), NATInput{
		Flow:   FlowInput{Source: "198.18.1.10", Destination: "198.18.250.10", Protocol: "tcp", Port: "8443"},
		Device: "fw01", Router: "default", FromZone: "transport",
	})
	if err != nil {
		t.Fatal(err)
	}
	check("nat", summaryJSON(t, ne, NATResult.Summary), []string{`"rule":"t-dnat-port"`, `"doubts":[]`, `"destination":{`},
		[]string{`"excluded"`, `"pre_nat"`, `"stages"`})
	none := ne.Results[0]
	none.Rule = nil
	if s := none.Summary(); s.Rule != "" {
		t.Errorf("no rule: %+v", s)
	}

	re, err := Routing(ctx, natEnv(t), RoutingInput{Source: "198.18.1.10", Destination: "198.18.250.10", Port: "8443", Device: "fw01", Router: "default"})
	if err != nil {
		t.Fatal(err)
	}
	check("routing", summaryJSON(t, re, RoutingResult.Summary), []string{`"hops":[{"device":"fw01"`, `"end_code":"`},
		[]string{`"lookups"`, `"stages"`, `"checks"`})

	se, err := Search(ctx, Env{}, SearchInput{Term: "10.124.0.1", Selection: Selection{File: fixture("firewall-multivsys.xml")}})
	if err != nil {
		t.Fatal(err)
	}
	check("search", summaryJSON(t, se, Finding.Summary), []string{`"answer":"file/vsys1: address corp-dc-vienna"`, `"field":"destination"`}, []string{`"path"`})

	le, err := Lookup(ctx, Env{}, LookupInput{Name: "branch-to-dc", Selection: Selection{File: fixture("firewall-lookup.xml")}})
	if err != nil {
		t.Fatal(err)
	}
	check("lookup", summaryJSON(t, le, LookupResult.Summary), []string{`"kind":"security-rule","name":"branch-to-dc"`}, []string{`"card"`})

	de, err := SnapshotDiff(ctx, diffLab(t), DiffInput{})
	if err != nil {
		t.Fatal(err)
	}
	check("diff", summaryJSON(t, de, DiffResult.Summary), []string{`"added":`, `"removed":`, `"changed":`}, []string{`"changes"`})
}

// A hop without a route, or one whose route has no next hop address, still
// names what it has.
func TestRouteOf(t *testing.T) {
	t.Parallel()
	re, err := Routing(context.Background(), natEnv(t), RoutingInput{Source: "198.18.1.10", Destination: "198.18.250.10", Port: "8443", Device: "fw01", Router: "default"})
	if err != nil || len(re.Results) != 1 {
		t.Fatalf("%+v %v", re, err)
	}
	h := re.Results[0].Hops[0]
	if routeOf(h) == "" {
		t.Errorf("a hop with a route: %+v", h.Lookups)
	}
	h.Lookups = nil
	if routeOf(h) != "" {
		t.Error("a hop without a route")
	}
}
