package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
)

// clock is when the first snapshot is taken; the questions run an hour later.
var clock = time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)

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
	root := t.TempDir()
	st, err := store.Open(root)
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
	// The server reads the inventory fetch exported into the store.
	inv, err := inventory.Parse(strings.NewReader("version: 1\ndefaults:\n  username: reader\n  password_env: LAB_PW\ndevices:\n" +
		"  - name: fw01\n    host: fw01.example.test\n" +
		"  - name: fw02\n    host: fw02.example.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.WriteExport(root, inv); err != nil {
		t.Fatal(err)
	}
	if inv, err = inventory.ReadExport(inventory.ExportPath(root)); err != nil {
		t.Fatal(err)
	}
	return query.Env{Store: st, Inventory: inv, Now: func() time.Time { return clock.Add(time.Hour) }, MaxAge: 24 * time.Hour}
}

// recorder keeps the audit records.
type recorder struct {
	mu    sync.Mutex
	calls []Call
}

func (r *recorder) Audit(c Call) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, c)
}

// last is the newest record.
func (r *recorder) last(t *testing.T) Call {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.calls) == 0 {
		t.Fatal("no call audited")
	}
	return r.calls[len(r.calls)-1]
}

// serve runs a server over env through in-memory transports and returns the
// client's session and the audit. strict is New's: a panic fails the test.
func serve(t *testing.T, env query.Env, strict bool) (*sdk.ClientSession, *recorder) {
	t.Helper()
	ctx := context.Background()
	rec := &recorder{}
	s, err := newServer(Options{Env: env, Audit: rec, Version: "test"}, strict)
	if err != nil {
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
	return cs, rec
}

// connect serves env as New does in a test binary.
func connect(t *testing.T, env query.Env) *sdk.ClientSession {
	t.Helper()
	cs, _ := serve(t, env, true)
	return cs
}

// docOf is a query's answer as the tool returns it: the envelope in the
// detail asked.
func docOf[In query.Echoer[E], E, R, S any](t *testing.T, e query.Envelope[In, R], err error, detail string, summary func(R) S) any {
	t.Helper()
	if err != nil {
		t.Fatalf("the query failed: %v", err)
	}
	if detail == query.DetailSummary {
		return output{Envelope: query.DocOf(query.Summarize(e, summary))}
	}
	return output{Envelope: query.DocOf(e)}
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
		read  []string // the devices whose every snapshot the audit names
		args  map[string]any
		want  func(t *testing.T, detail string) any
		empty bool // no results
	}{
		{
			"policy along the path", path, "simulate_policy",
			[]string{pathlab.FW01, pathlab.FW02},
			map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "protocol": "tcp", "port": 443},
			func(t *testing.T, d string) any {
				e, err := query.Policy(ctx, path, query.PolicyInput{Flow: labFlow})
				return docOf(t, e, err, d, query.PathResult.Summary)
			}, false,
		},
		{
			"policy with holes only", holes, "simulate_policy",
			[]string{pathlab.FW01},
			map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "protocol": "tcp", "port": 443},
			func(t *testing.T, d string) any {
				e, err := query.Policy(ctx, holes, query.PolicyInput{Flow: labFlow})
				return docOf(t, e, err, d, query.PathResult.Summary)
			}, true,
		},
		{
			"routing", path, "simulate_routing",
			[]string{pathlab.FW01, pathlab.FW02},
			map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "port": 443},
			func(t *testing.T, d string) any {
				e, err := query.Routing(ctx, path, query.RoutingInput{Source: pathlab.Source, Destination: pathlab.Destination, Port: "443"})
				return docOf(t, e, err, d, query.RoutingResult.Summary)
			}, false,
		},
		{
			"nat", natLab, "simulate_nat",
			[]string{pathlab.FW01},
			map[string]any{"source": "198.18.1.10", "destination": "198.18.250.10", "port": 8443, "device": "fw01", "router": "default"},
			func(t *testing.T, d string) any {
				e, err := query.NAT(ctx, natLab, query.NATInput{
					Flow: query.FlowInput{Source: "198.18.1.10", Destination: "198.18.250.10", Protocol: "tcp", Port: "8443"}, Device: "fw01", Router: "default",
				})
				return docOf(t, e, err, d, query.NATResult.Summary)
			}, false,
		},
		{
			"nat with a hole", natLab, "simulate_nat", nil,
			map[string]any{"destination": "198.18.250.10", "device": "fw02"},
			func(t *testing.T, d string) any {
				e, err := query.NAT(ctx, natLab, query.NATInput{Flow: query.FlowInput{Destination: "198.18.250.10", Protocol: "tcp"}, Device: "fw02"})
				return docOf(t, e, err, d, query.NATResult.Summary)
			}, true,
		},
		{
			"search", lab, "search",
			[]string{pathlab.FW01},
			map[string]any{"value": "198.18.10.100"},
			func(t *testing.T, d string) any {
				e, err := query.Search(ctx, lab, query.SearchInput{Term: "198.18.10.100"})
				return docOf(t, e, err, d, query.Finding.Summary)
			}, false,
		},
		{
			"search without a finding", lab, "search",
			[]string{pathlab.FW01},
			map[string]any{"value": "no-such-name"},
			func(t *testing.T, d string) any {
				e, err := query.Search(ctx, lab, query.SearchInput{Term: "no-such-name"})
				return docOf(t, e, err, d, query.Finding.Summary)
			}, true,
		},
		{
			"lookup", lab, "lookup",
			[]string{pathlab.FW01},
			map[string]any{"name": "dc01", "device": []string{"fw01"}},
			func(t *testing.T, d string) any {
				e, err := query.Lookup(ctx, lab, query.LookupInput{Name: "dc01", Selection: query.Selection{Device: []string{"fw01"}}})
				return docOf(t, e, err, d, query.LookupResult.Summary)
			}, false,
		},
		{
			"snapshot diff", diff, "snapshot_diff",
			[]string{pathlab.FW01},
			map[string]any{"device": "fw01"},
			func(t *testing.T, d string) any {
				e, err := query.SnapshotDiff(ctx, diff, query.DiffInput{Selection: query.Selection{Device: []string{"fw01"}}})
				return docOf(t, e, err, d, query.DiffResult.Summary)
			}, false,
		},
		{
			"snapshot diff of one snapshot", diff, "snapshot_diff", nil,
			map[string]any{"device": "fw02"},
			func(t *testing.T, d string) any {
				e, err := query.SnapshotDiff(ctx, diff, query.DiffInput{Selection: query.Selection{Device: []string{"fw02"}}})
				return docOf(t, e, err, d, query.DiffResult.Summary)
			}, true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs, rec := serve(t, tc.env, true)
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
				want := tc.want(t, detail)
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
				// The text content opens with the first answer line; the audit
				// has the answers and the status.
				v := viewOf(env)
				c := rec.last(t)
				if as := v.answers(); len(as) > 0 && !strings.HasPrefix(text(res), as[0]+"\n") && text(res) != as[0] {
					t.Errorf("%s: text %q, answers %q", detail, text(res), as)
				}
				if want := snapshotsOf(t, tc.env, tc.read...); !slices.Equal(c.Snapshots, want) {
					t.Errorf("%s: audit snapshots %q, want %q", detail, c.Snapshots, want)
				}
				if c.Tool != tc.tool || c.Status != StatusOK || c.Code != "" || !slices.Equal(c.Answers, v.answers()) || c.Duration < 0 {
					t.Errorf("%s: audit %+v", detail, c)
				}
			}
		})
	}
}

// snapshotsOf names every snapshot of the devices in env's store as the audit
// does: device@snapshot-id, sorted.
func snapshotsOf(t *testing.T, env query.Env, devices ...string) []string {
	t.Helper()
	var out []string
	for _, d := range devices {
		ids, err := env.Store.List(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			out = append(out, d+"@"+id)
		}
	}
	slices.Sort(out)
	return out
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
		if tool.OutputSchema == nil || tool.Description == "" {
			t.Errorf("%s: no output schema or no description", tool.Name)
		}
	}
}

// Each tool says it only reads (spec 2026-10-10 F1): a title and the three
// hints, and no destructive hint.
func TestToolsAreReadOnly(t *testing.T) {
	t.Parallel()
	cs := connect(t, labEnv(t))
	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lt.Tools) != len(toolTitles) {
		t.Fatalf("%d tools, %d titles", len(lt.Tools), len(toolTitles))
	}
	for _, tool := range lt.Tools {
		a := tool.Annotations
		if a == nil {
			t.Errorf("%s: no annotations", tool.Name)
			continue
		}
		want := toolTitles[tool.Name]
		if want == "" || tool.Title != want || a.Title != want {
			t.Errorf("%s: title %q, annotation title %q, want %q", tool.Name, tool.Title, a.Title, want)
		}
		if !a.ReadOnlyHint || !a.IdempotentHint || a.OpenWorldHint == nil || *a.OpenWorldHint || a.DestructiveHint != nil {
			t.Errorf("%s: hints %+v", tool.Name, a)
		}
	}
}

// A refused input is a structured error the output schema accepts, with
// IsError and a text content; the audit has its status. A value outside an
// enum is the SDK's own input error (S7), audited as usage.
func TestErrorsAreStructured(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs, rec := serve(t, labEnv(t, snap{pathlab.FW01, fixture("firewall-nat.xml")}), true)
	for _, tc := range []struct {
		name, tool string
		args       map[string]any
		want       toolError
		status     string
	}{
		{
			"usage in the tool's words", "simulate_policy",
			map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "router": "default"},
			toolError{Code: "call.usage", Text: "router needs device", Options: []string{}, Needs: []query.Need{}},
			StatusUsage,
		},
		{
			"a choice only the user can make", "simulate_nat",
			map[string]any{"destination": "198.18.250.10", "device": "fw01"},
			toolError{
				Code: "call.choice", Text: "fw01 has several routers; name one in router", Options: []string{"default", "lte"},
				Needs: []query.Need{{Code: "input.router", Input: "router", Text: "give router: one of the options"}},
			},
			StatusChoice,
		},
		{
			"a question without a choice", "simulate_routing",
			map[string]any{"destination": "2001:db8::1", "device": "fw01"},
			toolError{Code: "call.usage", Text: "the destination must be an IPv4 address; IPv6 is not simulated yet", Options: []string{}, Needs: []query.Need{}},
			StatusUsage,
		},
	} {
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: tc.tool, Arguments: tc.args})
		if err != nil || !res.IsError {
			t.Fatalf("%s: %v %+v", tc.name, err, res)
		}
		got, _ := plain(t, res.StructuredContent).(map[string]any)
		if got["envelope"] != nil || !reflect.DeepEqual(got["error"], plain(t, tc.want)) {
			t.Errorf("%s: %v", tc.name, got)
		}
		if want := errorText(&tc.want); text(res) != want {
			t.Errorf("%s: text %q, want %q", tc.name, text(res), want)
		}
		if c := rec.last(t); c.Status != tc.status || c.Code != tc.want.Code || c.Tool != tc.tool || !strings.Contains(string(c.Input), `"destination"`) {
			t.Errorf("%s: audit %+v", tc.name, c)
		}
	}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_nat", Arguments: map[string]any{"destination": "198.18.250.10", "device": "fw09"}})
	if err != nil || !res.IsError || res.StructuredContent != nil || !strings.Contains(text(res), "validating") {
		t.Errorf("bad enum: %v %+v", err, res)
	}
	if c := rec.last(t); c.Status != StatusUsage || c.Code != "call.usage" || !strings.Contains(c.Err, "validating") {
		t.Errorf("bad enum audit: %+v", c)
	}
	// No such tool: the SDK refuses it before any handler.
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "no_such_tool", Arguments: map[string]any{}}); err == nil {
		t.Error("an unknown tool answered")
	}
	if c := rec.last(t); c.Status != StatusUsage || c.Tool != "no_such_tool" {
		t.Errorf("unknown tool audit: %+v", c)
	}
}

// A tie of placement offers the devices the device input accepts, and the
// text keeps each start's interface. The client can call again with one.
func TestATieOffersDevices(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs, rec := serve(t, labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)}), true)
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_routing", Arguments: map[string]any{"source": "198.18.100.50", "destination": "8.8.8.8"}})
	if err != nil || !res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	got, _ := plain(t, res.StructuredContent).(map[string]any)
	want := toolError{
		Code:    "call.choice",
		Text:    "198.18.100.50 could enter at several firewalls; name one in device (starts: fw01 ethernet1/5, fw02 vlan.100)",
		Options: []string{"fw01", "fw02"}, Needs: []query.Need{choiceNeeds[simulate.ChoiceDevice]},
	}
	if !reflect.DeepEqual(got["error"], plain(t, want)) {
		t.Errorf("%v", got)
	}
	if c := rec.last(t); c.Status != StatusChoice {
		t.Errorf("audit %+v", c)
	}
	// An option passes the device enum; fw01 then asks for its router.
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_routing", Arguments: map[string]any{"source": "198.18.100.50", "destination": "8.8.8.8", "device": "fw01"}})
	if err != nil || res.StructuredContent == nil || !strings.HasPrefix(text(res), "call.choice: fw01 has several routers") {
		t.Errorf("the option was refused: %v %s", err, text(res))
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_routing", Arguments: map[string]any{"source": "198.18.100.50", "destination": "8.8.8.8", "device": "fw01", "router": "default"}})
	if err != nil || res.IsError {
		t.Errorf("the option was refused: %v %s", err, text(res))
	}
}

// A call without detail answers in summary.
func TestDetailDefaultsToSummary(t *testing.T) {
	t.Parallel()
	cs := connect(t, labEnv(t, snap{pathlab.FW01, fixture("firewall-lab.xml")}))
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "search", Arguments: map[string]any{"value": "198.18.10.100"}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	env, _ := plain(t, res.StructuredContent).(map[string]any)["envelope"].(map[string]any)
	if env["detail"] != query.DetailSummary {
		t.Errorf("detail %v", env["detail"])
	}
}

// The text content holds each result's answer, fidelity and needs, then the
// holes, unresolved entries and notes; an empty answer says so.
func TestTextContent(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"results": []any{map[string]any{
			"answer": "fw01: undecided", "fidelity": map[string]any{"level": "undermatch"},
			"needs": []any{map[string]any{"code": "input.port", "input": "port", "text": "give the destination port"}},
		}},
		"holes":      []any{map[string]any{"device": "fw02", "code": "gap.no-snapshot", "text": "no snapshot"}},
		"unresolved": []any{map[string]any{"device": "fw01", "vsys": "vsys1", "value": "edl-x", "code": "gap.edl", "text": "external list"}},
		"notes":      []any{map[string]any{"device": "", "code": "note.tls-off", "text": "run note"}},
	}
	want := "fw01: undecided\n  fidelity: undermatch\n  needs port: give the destination port\n" +
		"hole: fw02: no snapshot\nunresolved: fw01/vsys1: edl-x: external list\nnote: run note"
	v := viewOf(doc)
	if got := v.text(); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if got := v.codes(); !slices.Equal(got, []reason.Code{"gap.no-snapshot", "gap.edl", "note.tls-off"}) {
		t.Errorf("codes %v", got)
	}
	held := map[string]any{"results": []any{map[string]any{"answer": "fw01: undecided", "needs": []any{}}}}
	if got := viewOf(held).text(); got != "fw01: undecided\n  needs: none; no input can decide this" {
		t.Errorf("held back, no input helps: %q", got)
	}
	if got := viewOf(map[string]any{"results": []any{}}).text(); got != "no result" {
		t.Errorf("empty: %q", got)
	}
	if got := viewOf(map[string]any{"summary": map[string]any{"answer": "0 found"}}).text(); got != "0 found" {
		t.Errorf("summary: %q", got)
	}
	if got := viewOf(func() {}).answers(); got != nil {
		t.Errorf("a value JSON cannot write: %v", got)
	}
	e := &toolError{Code: "call.choice", Text: "pick", Options: []string{"a", "b"}, Needs: []query.Need{{Input: "router", Text: "give router"}}}
	if got := errorText(e); got != "call.choice: pick\noptions: a, b\nneeds router: give router" {
		t.Errorf("error text %q", got)
	}
}

// The server gives its instructions, the reason registry, each tool's
// envelope schemas and the limits.
func TestResourcesAndInstructions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cs := connect(t, labEnv(t))
	if got := cs.InitializeResult().Instructions; got != instructions || strings.Count(got, ". ") != 4 {
		t.Errorf("instructions %q", got)
	}
	lr, err := cs.ListResources(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lr.Resources) != 2+6*2 {
		t.Errorf("%d resources", len(lr.Resources))
	}
	read := func(uri string) string {
		rr, err := cs.ReadResource(ctx, &sdk.ReadResourceParams{URI: uri})
		if err != nil || len(rr.Contents) != 1 {
			t.Fatalf("%s: %v", uri, err)
		}
		return rr.Contents[0].Text
	}
	var reasons []map[string]string
	if err := json.Unmarshal([]byte(read(reasonsURI)), &reasons); err != nil || len(reasons) != len(reason.Registry()) || reasons[0]["class"] == "" {
		t.Errorf("reasons: %v %v", err, reasons[:1])
	}
	gen := generated(t)
	for _, sh := range shapes {
		for _, d := range []string{query.DetailSummary, query.DetailFull} {
			if sh.tool == "" {
				continue
			}
			if got, want := read(schemaURI(sh.tool, d)), string(bytes.TrimSpace(marshal(t, gen[sh.name+"."+d+".json"]))); got != want {
				t.Errorf("%s %s: the resource is not the generated schema", sh.tool, d)
			}
		}
	}
	if got := read(limitsURI); !strings.Contains(got, "undermatch") {
		t.Errorf("limits %q", got)
	}
}

// A panic in a call gives call.internal with the stack in the audit, and the
// server keeps answering (S8). Here the resolver panics.
func TestAPanicGivesCallInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	env.Resolve = func(context.Context, string) ([]netip.Addr, error) { panic("resolver bug") }
	cs, rec := serve(t, env, false)
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_routing", Arguments: map[string]any{"destination": "host.example.test", "device": "fw01"}})
	if err != nil || !res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	got, _ := plain(t, res.StructuredContent).(map[string]any)
	if e, _ := got["error"].(map[string]any); got["envelope"] != nil || e["code"] != "call.internal" || e["text"] != internalText {
		t.Errorf("%v", got)
	}
	if c := rec.last(t); c.Status != StatusInternal || !bytes.Contains(c.Stack, []byte("resolver bug")) || !bytes.Contains(c.Stack, []byte("goroutine")) {
		t.Errorf("audit %+v", c)
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_routing", Arguments: map[string]any{"source": pathlab.Source, "destination": pathlab.Destination}})
	if err != nil || res.IsError {
		t.Errorf("the server stopped answering: %v %+v", err, res)
	}
}

// The middleware on its own: output the SDK refuses after the handler
// answered is audited as internal (S3); in a test binary a panic goes on; a
// panic outside a tool call is an error.
func TestTheMiddleware(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rec := &recorder{}
	req := &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "search", Arguments: json.RawMessage(`{"value":"x"}`)}}
	refused := func(ctx context.Context, _ string, _ sdk.Request) (sdk.Result, error) {
		callOf(ctx).set(func(c *Call) { c.Status = StatusOK })
		return nil, errors.New("validating tool output: no")
	}
	m := middleware{audit: rec, now: time.Now}
	if _, err := m.receive(refused)(ctx, "tools/call", req); err == nil {
		t.Error("the SDK's error is lost")
	}
	if c := rec.last(t); c.Status != StatusInternal || c.Code != "call.internal" || c.Tool != "search" || c.Err != "validating tool output: no" {
		t.Errorf("audit %+v", c)
	}
	boom := func(context.Context, string, sdk.Request) (sdk.Result, error) { panic("boom") }
	func() {
		defer func() {
			if p := recover(); p != "boom" {
				t.Errorf("strict: recovered %v", p)
			}
		}()
		strict := middleware{audit: rec, now: time.Now, strict: true}
		_, _ = strict.receive(boom)(ctx, "tools/call", req)
	}()
	// A handler that filled the record and then panicked gave no answer.
	half := func(ctx context.Context, _ string, _ sdk.Request) (sdk.Result, error) {
		callOf(ctx).set(func(c *Call) {
			c.Answers, c.Codes, c.Snapshots = []string{"allowed"}, []reason.Code{"note.ha-peer"}, []string{"fw01@x"}
		})
		panic("late")
	}
	if _, err := m.receive(half)(ctx, "tools/call", req); err != nil {
		t.Error(err)
	}
	if c := rec.last(t); c.Status != StatusInternal || c.Answers != nil || c.Codes != nil || c.Snapshots != nil {
		t.Errorf("panic after answers: %+v", c)
	}
	if _, err := m.receive(boom)(ctx, "resources/read", nil); err == nil || !strings.Contains(err.Error(), internalText) {
		t.Errorf("resources/read: %v", err)
	}
	func() {
		defer func() {
			if p := recover(); p != "boom" {
				t.Errorf("strict, not a call: recovered %v", p)
			}
		}()
		strict := middleware{now: time.Now, strict: true}
		_, _ = strict.receive(boom)(ctx, "resources/read", nil)
	}()
	// Outside a served call the handler's record takes nothing.
	callOf(ctx).set(func(*Call) { t.Error("set ran without a record") })
}

// New refuses an inventory without a device; Serve answers over a transport
// until its context ends.
func TestServe(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Error("New without an inventory")
	}
	if err := Serve(context.Background(), Options{}, Stdio()); err == nil {
		t.Error("Serve without an inventory")
	}
	env := labEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	ct, st := sdk.NewInMemoryTransports()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, Options{Env: env}, st) }()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "client", Version: "test"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lt, err := cs.ListTools(context.Background(), nil); err != nil || len(lt.Tools) != 6 {
		t.Errorf("tools: %v", err)
	}
	cancel()
	_ = cs.Close()
	<-done
}

// search refuses an unknown kind in the tool's words, with the kinds it knows.
func TestSearchRefusesAnUnknownKind(t *testing.T) {
	t.Parallel()
	cs, rec := serve(t, labEnv(t, snap{pathlab.FW01, fixture("firewall-nat.xml")}), true)
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name: "search", Arguments: map[string]any{"value": pathlab.Destination, "kind": "addr"},
	})
	if err != nil || !res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	got, _ := plain(t, res.StructuredContent).(map[string]any)
	e, _ := got["error"].(map[string]any)
	msg, _ := e["text"].(string)
	if e["code"] != "call.usage" || !strings.HasPrefix(msg, `kind "addr": want one of `) ||
		!strings.Contains(msg, "address, address-group") || strings.Contains(msg, "--") {
		t.Errorf("error %v", e)
	}
	if c := rec.last(t); c.Status != StatusUsage || c.Code != "call.usage" {
		t.Errorf("audit %+v", c)
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

// errorOf gives each kind of query error its code; toolOf knows only the six
// tools.
func TestErrorOf(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		err  error
		code reason.Code
		text string
	}{
		{fmt.Errorf("load: %w", context.DeadlineExceeded), "call.timeout", "the call ran longer than its time limit"},
		{errors.New("store: unreadable"), "call.internal", "store: unreadable"},
		{&simulate.ChoiceError{Question: "the source must be an IPv4 address"}, "call.usage", "the source must be an IPv4 address"},
		{&simulate.ChoiceError{Kind: simulate.ChoiceDevice, Question: "pick --device", ToolText: "pick device", Options: []string{"fw01"}}, "call.choice", "pick device"},
		{fmt.Errorf("call: %w", context.Canceled), "call.timeout", "the call was cancelled before it answered"},
	} {
		if got := errorOf(tc.err); got.Code != tc.code || got.Text != tc.text || got.Options == nil || got.Needs == nil {
			t.Errorf("%v: %+v", tc.err, got)
		}
	}
	// Ties: starts on one device differ by router, or by interface alone.
	tie := func(starts ...simulate.Port) *simulate.ChoiceError {
		c := &simulate.ChoiceError{Kind: simulate.ChoiceDevice, Question: "q", ToolText: "t", Starts: starts}
		for _, p := range starts {
			c.Options = append(c.Options, p.Device+" "+p.Interface)
		}
		return c
	}
	e := errorOf(tie(simulate.Port{Device: "fw01", Router: "default", Interface: "ethernet1/1"}, simulate.Port{Device: "fw01", Router: "lte", Interface: "ethernet1/7"}))
	if e.Code != "call.choice" || !slices.Equal(e.Options, []string{"default", "lte"}) || len(e.Needs) != 1 || e.Needs[0].Input != "router" ||
		!strings.Contains(e.Text, "name device fw01 and one router (starts: fw01 ethernet1/1, fw01 ethernet1/7)") {
		t.Errorf("routers: %+v", e)
	}
	e = errorOf(tie(simulate.Port{Device: "fw01", Router: "default", Interface: "ethernet1/1"}, simulate.Port{Device: "fw01", Router: "default", Interface: "ethernet1/2"}))
	if e.Code != "call.usage" || len(e.Options) != 0 || !strings.Contains(e.Text, "fw01 at several interfaces of one router") {
		t.Errorf("one router: %+v", e)
	}
	if _, err := toolOf("no_such_tool", nil); err == nil {
		t.Error("toolOf of an unknown tool")
	}
	if _, ok := shapeByTool(""); ok {
		t.Error("the file shape has no tool")
	}
}
