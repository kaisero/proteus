package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
)

// clock is when the first snapshot is taken; the questions run an hour later.
var clock = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

// devices are the inventory's devices, the tools' device enum.
var devices = []string{pathlab.FW01, pathlab.FW02}

// fixture is a configuration file of the repository's test data.
func fixture(name string) string { return filepath.Join("..", "..", "testdata", "config", name) }

// snap is a snapshot to store: a device and its configuration file.
type snap struct{ device, config string }

// labEnv is a store holding the snapshots in order, a minute apart, each with
// the path lab's interfaces and forwarding table, and an inventory of fw01
// and fw02.
func labEnv(t *testing.T, snaps ...snap) query.Env {
	t.Helper()
	now := clock
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st = st.WithClock(func() time.Time { return now })
	for i, s := range snaps {
		docs := map[string][]byte{
			store.ConfigDoc:     pathlab.Read(t, s.config),
			store.InterfacesDoc: pathlab.Read(t, pathlab.OpdataFile(s.device+"-interface-all.xml")),
			store.FIBDoc:        pathlab.Read(t, pathlab.OpdataFile(s.device+"-advanced-routing-fib.xml")),
		}
		meta := store.Meta{Device: s.device, Host: s.device + ".example.test", Serial: "00000000000" + string(rune('1'+i))}
		if _, err := st.Write(meta, docs, 20); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	inv, err := inventory.Parse(strings.NewReader("version: 1\ndevices:\n" +
		"  - name: fw01\n    host: fw01.example.test\n" +
		"  - name: fw02\n    host: fw02.example.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	return query.Env{Store: st, Inventory: inv, Now: func() time.Time { return clock.Add(time.Hour) }, MaxAge: 24 * time.Hour}
}

// connect serves the tools over env through in-memory transports and returns
// the client's session.
func connect(t *testing.T, env query.Env) *sdk.ClientSession {
	t.Helper()
	ctx := context.Background()
	s := sdk.NewServer(&sdk.Implementation{Name: "proteus", Version: "test"}, nil)
	if err := tools(s, env, devices); err != nil {
		t.Fatal(err)
	}
	ct, st := sdk.NewInMemoryTransports()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "client", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close(); _ = ss.Wait() })
	return cs
}

// plain is v as JSON values, each stage's elapsed time zeroed: the one value
// two runs of a question do not share.
func plain(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	var zero func(any)
	zero = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, e := range v {
				if k == "elapsed_ms" {
					v[k] = 0.0
				}
				zero(e)
			}
		case []any:
			for _, e := range v {
				zero(e)
			}
		}
	}
	zero(out)
	return out
}

// The SDK proof (spec §3.6, D4): every question, served as a tool with the
// generated schemas, answers through the SDK on the fixtures, in summary and
// in full, also with empty results and with holes only. The SDK accepts each
// output against its schema, and the structured content is the query layer's
// envelope.
func TestTheSDKAcceptsEveryAnswer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	holes := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)})
	lab := labEnv(t, snap{pathlab.FW01, fixture("firewall-lab.xml")})
	natLab := labEnv(t, snap{pathlab.FW01, fixture("firewall-nat.xml")})
	diff := labEnv(t, snap{pathlab.FW01, fixture("firewall-lab.xml")}, snap{pathlab.FW01, fixture("firewall-lab-changed.xml")},
		snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	labFlow := query.FlowInput{Source: pathlab.Source, Destination: pathlab.Destination, Protocol: "tcp", Port: "443"}
	for _, tc := range []struct {
		name  string
		env   query.Env
		tool  string
		args  map[string]any
		want  func(detail string) output
		empty bool // no results
	}{
		{
			"policy along the path", path, "simulate_policy",
			map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "protocol": "tcp", "port": 443},
			func(d string) output {
				e, err := query.Policy(ctx, path, query.PolicyInput{Flow: labFlow})
				return answer(e, err, d, query.PathResult.Summary)
			}, false,
		},
		{
			"policy with holes only", holes, "simulate_policy",
			map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "protocol": "tcp", "port": 443},
			func(d string) output {
				e, err := query.Policy(ctx, holes, query.PolicyInput{Flow: labFlow})
				return answer(e, err, d, query.PathResult.Summary)
			}, true,
		},
		{
			"routing", path, "simulate_routing",
			map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "port": 443},
			func(d string) output {
				e, err := query.Routing(ctx, path, query.RoutingInput{Source: pathlab.Source, Destination: pathlab.Destination, Port: "443"})
				return answer(e, err, d, query.RoutingResult.Summary)
			}, false,
		},
		{
			"nat", natLab, "simulate_nat",
			map[string]any{"source": "198.18.1.10", "destination": "198.18.250.10", "port": 8443, "device": "fw01", "router": "default"},
			func(d string) output {
				e, err := query.NAT(ctx, natLab, query.NATInput{
					Flow: query.FlowInput{Source: "198.18.1.10", Destination: "198.18.250.10", Protocol: "tcp", Port: "8443"}, Device: "fw01", Router: "default",
				})
				return answer(e, err, d, query.NATResult.Summary)
			}, false,
		},
		{
			"nat with a hole", natLab, "simulate_nat",
			map[string]any{"destination": "198.18.250.10", "device": "fw02"},
			func(d string) output {
				e, err := query.NAT(ctx, natLab, query.NATInput{Flow: query.FlowInput{Destination: "198.18.250.10", Protocol: "tcp"}, Device: "fw02"})
				return answer(e, err, d, query.NATResult.Summary)
			}, true,
		},
		{
			"search", lab, "search",
			map[string]any{"value": "198.18.10.100"},
			func(d string) output {
				e, err := query.Search(ctx, lab, query.SearchInput{Term: "198.18.10.100"})
				return answer(e, err, d, query.Finding.Summary)
			}, false,
		},
		{
			"search without a finding", lab, "search",
			map[string]any{"value": "no-such-name"},
			func(d string) output {
				e, err := query.Search(ctx, lab, query.SearchInput{Term: "no-such-name"})
				return answer(e, err, d, query.Finding.Summary)
			}, true,
		},
		{
			"lookup", lab, "lookup",
			map[string]any{"name": "dc01", "device": []string{"fw01"}},
			func(d string) output {
				e, err := query.Lookup(ctx, lab, query.LookupInput{Name: "dc01", Selection: query.Selection{Device: []string{"fw01"}}})
				return answer(e, err, d, query.LookupResult.Summary)
			}, false,
		},
		{
			"snapshot diff", diff, "snapshot_diff",
			map[string]any{"device": "fw01"},
			func(d string) output {
				e, err := query.SnapshotDiff(ctx, diff, query.DiffInput{Selection: query.Selection{Device: []string{"fw01"}}})
				return answer(e, err, d, query.DiffResult.Summary)
			}, false,
		},
		{
			"snapshot diff of one snapshot", diff, "snapshot_diff",
			map[string]any{"device": "fw02"},
			func(d string) output {
				e, err := query.SnapshotDiff(ctx, diff, query.DiffInput{Selection: query.Selection{Device: []string{"fw02"}}})
				return answer(e, err, d, query.DiffResult.Summary)
			}, true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs := connect(t, tc.env)
			for _, detail := range []string{query.DetailSummary, query.DetailFull} {
				args := map[string]any{"detail": detail}
				for k, v := range tc.args {
					args[k] = v
				}
				res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: tc.tool, Arguments: args})
				if err != nil {
					t.Fatalf("%s: the SDK refused the answer: %v", detail, err)
				}
				if res.IsError {
					t.Fatalf("%s: tool error %s", detail, text(res))
				}
				want := tc.want(detail)
				if want.Error != nil {
					t.Fatalf("%s: the query failed: %+v", detail, want.Error)
				}
				got := plain(t, res.StructuredContent)
				if !reflect.DeepEqual(got, plain(t, want)) {
					t.Errorf("%s: structured content differs from the query's envelope\ngot  %v\nwant %v", detail, got, plain(t, want))
				}
				env, _ := got.(map[string]any)["envelope"].(map[string]any)
				results, _ := env["results"].([]any)
				holes, _ := env["holes"].([]any)
				if env["detail"] != detail || (len(results) == 0) != tc.empty || tc.empty && tc.tool != "search" && len(holes) == 0 {
					t.Errorf("%s: detail %v, %d results, %d holes", detail, env["detail"], len(results), len(holes))
				}
			}
		})
	}
}

// Each tool lists the generated schemas, with the inventory's devices as the
// device enum.
func TestToolsListTheDeviceEnum(t *testing.T) {
	t.Parallel()
	cs := connect(t, labEnv(t))
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lt.Tools) != 6 {
		t.Fatalf("%d tools", len(lt.Tools))
	}
	for _, tool := range lt.Tools {
		b, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"enum":["fw01","fw02"]`) {
			t.Errorf("%s: no device enum in %s", tool.Name, b)
		}
		if tool.OutputSchema == nil {
			t.Errorf("%s: no output schema", tool.Name)
		}
	}
}

// A refused input is a structured error the output schema accepts, with
// IsError; a value outside an enum is the SDK's own input error (S7).
func TestErrorsAreStructured(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := connect(t, labEnv(t))
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_policy", Arguments: map[string]any{
		"source": pathlab.Source, "destination": pathlab.Destination, "router": "default",
	}})
	if err != nil || !res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	got, _ := plain(t, res.StructuredContent).(map[string]any)
	e, _ := got["error"].(map[string]any)
	if got["envelope"] != nil || e["code"] != "call.usage" || e["text"] != "router needs device" {
		t.Errorf("%v", got)
	}
	// A choice only the user can make.
	nat := connect(t, labEnv(t, snap{pathlab.FW01, fixture("firewall-nat.xml")}))
	res, err = nat.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_nat", Arguments: map[string]any{"destination": "198.18.250.10", "device": "fw01"}})
	if err != nil || !res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	got, _ = plain(t, res.StructuredContent).(map[string]any)
	if e, _ := got["error"].(map[string]any); got["envelope"] != nil || e["code"] != "call.choice" {
		t.Errorf("choice: %v", got)
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_nat", Arguments: map[string]any{"destination": "198.18.250.10", "device": "fw09"}})
	if err != nil || !res.IsError || res.StructuredContent != nil || !strings.Contains(text(res), "validating") {
		t.Errorf("bad enum: %v %+v", err, res)
	}
}

// text is a result's first text content.
func text(res *sdk.CallToolResult) string {
	if len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*sdk.TextContent); ok {
		return tc.Text
	}
	return ""
}
