package query

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// codePattern finds every reason code in a result's JSON.
var codePattern = regexp.MustCompile(`"code":"([^"]+)"`)

// codes is the set of reason codes a result carries, needs left out.
func codes(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range codePattern.FindAllStringSubmatch(string(b), -1) {
		if c := m[1]; !slices.Contains(out, c) && c[:6] != "input." {
			out = append(out, c)
		}
	}
	slices.Sort(out)
	return out
}

// needCodes are a result's need codes, in order; nil when it has no needs key.
func needCodes(ns []Need) []string {
	if ns == nil {
		return nil
	}
	out := []string{}
	for _, n := range ns {
		out = append(out, string(n.Code)+" "+n.Input)
	}
	return out
}

// file asks simulate policy on firewall-doubt.xml: from home to wan, or with
// dmz true from dmz to wan.
func file(t *testing.T, dmz bool, f FlowInput) SecurityResult {
	t.Helper()
	f.Source, f.Destination, f.FromZone, f.ToZone = "198.18.1.68", "203.0.113.5", "home", "wan"
	if dmz {
		f.Source, f.FromZone = "10.0.0.5", "dmz"
	}
	e, err := PolicyFile(context.Background(), Env{}, PolicyFileInput{Flow: f, Selection: Selection{File: fixture("firewall-doubt.xml")}})
	if err != nil || len(e.Results) != 1 {
		t.Fatalf("%+v %v", e, err)
	}
	return e.Results[0]
}

// Each row of spec 2026-10-09 §3.4 (C11 drops path.pbf-no-port): the needs a
// held-back answer lists, and that giving them changes the reason set.
func TestNeedsRows(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		dmz         bool
		ask, second FlowInput // second gives the needs; unused when there are none
		want        []string
	}{
		{"service without a port, udp", false, FlowInput{Protocol: "udp"}, FlowInput{Protocol: "udp", Port: "443"}, []string{"input.port port"}},
		{
			"service without a port or a protocol", false,
			FlowInput{},
			FlowInput{Port: "udp/443"},
			[]string{"input.protocol protocol", "input.port port"},
		},
		{"icmp never needs a port", false, FlowInput{Protocol: "icmp"}, FlowInput{}, []string{}},
		{
			"category without a URL", true,
			FlowInput{Protocol: "tcp", Port: "443"},
			FlowInput{Protocol: "tcp", Port: "443", URL: "shop.example.com"},
			[]string{"input.url url"},
		},
		{"a PAN-DB category needs nothing", true, FlowInput{Protocol: "tcp", Port: "443", URL: "other.example.com"}, FlowInput{}, []string{}},
		{"a user needs nothing", true, FlowInput{Protocol: "tcp", Port: "443", URL: "other.example.com", User: `corp\alice`}, FlowInput{}, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := file(t, tc.dmz, tc.ask)
			if r.Verdict != "undecided" {
				t.Fatalf("verdict %s: %s", r.Verdict, r.Answer)
			}
			if got := needCodes(r.Needs); !slices.Equal(got, tc.want) {
				t.Fatalf("needs %v, want %v (%s)", got, tc.want, r.Answer)
			}
			for _, n := range r.Needs {
				if n.Text == "" || strings.Contains(n.Text, "--") {
					t.Errorf("need text %q", n.Text)
				}
			}
			if len(tc.want) == 0 {
				return
			}
			again := file(t, tc.dmz, tc.second)
			if slices.Equal(codes(t, r), codes(t, again)) {
				t.Errorf("the reason set did not change: %v", codes(t, r))
			}
		})
	}
}

// A decided answer has no needs key; the rule a port decides is named.
func TestNeedsOnlyHeldBack(t *testing.T) {
	t.Parallel()
	r := file(t, false, FlowInput{Protocol: "udp", Port: "443"})
	if r.Verdict == "undecided" || r.Needs != nil {
		t.Errorf("%s: %+v", r.Verdict, r.Needs)
	}
	r = file(t, false, FlowInput{Protocol: "udp"})
	if len(r.Needs) != 1 || r.Needs[0].Text != "give the destination port; it decides the service of rules block-udp-443, app-one, app-two" {
		t.Errorf("%+v", r.Needs)
	}
}

// path.nat-no-port: a NAT rule that names a service needs the port, on simulate
// nat and on the routing hop that applies NAT; the port changes the reasons.
func TestNeedsNATPort(t *testing.T) {
	t.Parallel()
	ask := func(port string) NATResult {
		e, err := NAT(context.Background(), natEnv(t), NATInput{
			Flow:   FlowInput{Source: "198.18.1.10", Destination: "198.18.250.10", Protocol: "tcp", Port: port},
			Device: "fw01", Router: "default", FromZone: "transport",
		})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	r := ask("")
	if got := needCodes(r.Needs); !slices.Equal(got, []string{"input.port port"}) ||
		r.Needs[0].Text != "give the destination port; it decides the service of NAT rule t-dnat-port" {
		t.Errorf("nat needs %+v", r.Needs)
	}
	if again := ask("8443"); slices.Equal(codes(t, r), codes(t, again)) || again.Needs != nil {
		t.Errorf("nat with a port: %v, needs %+v", codes(t, again), again.Needs)
	}

	route := func(port string) RoutingResult {
		e, err := Routing(context.Background(), natEnv(t), RoutingInput{
			Source: "198.18.1.10", Destination: "198.18.250.10", Port: port, Device: "fw01", Router: "default",
		})
		if err != nil || len(e.Results) != 1 {
			t.Fatalf("%+v %v", e, err)
		}
		return e.Results[0]
	}
	rr := route("")
	if got := needCodes(rr.Needs); !slices.Equal(got, []string{"input.port port"}) {
		t.Errorf("routing needs %+v", rr.Needs)
	}
	if again := route("8443"); slices.Equal(codes(t, rr), codes(t, again)) {
		t.Errorf("routing with a port: %v", codes(t, again))
	}
}
