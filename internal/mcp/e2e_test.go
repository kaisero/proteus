package mcp

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kaisero/proteus/internal/query"
	"github.com/kaisero/proteus/internal/simulate/pathlab"
)

// Spec §7 race row: 16 calls of mixed tools at once over HTTP, each from its
// own client, share the server's cache and limits. Each answers as the same
// call alone does. Run with -race.
func TestParallelCallsOverHTTP(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	url, rec, _ := httpLab(t, Options{Limits: Limits{MaxConcurrent: 4, MaxQueue: 16}})
	calls := []sdk.CallToolParams{
		{Name: "simulate_policy", Arguments: map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "protocol": "tcp", "port": 443}},
		{Name: "simulate_routing", Arguments: map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "port": 443, "detail": "full"}},
		{Name: "simulate_nat", Arguments: map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "port": 443, "device": "fw01", "router": "default"}},
		{Name: "search", Arguments: map[string]any{"value": pathlab.Destination}},
		{Name: "lookup", Arguments: map[string]any{"name": "dc01", "detail": "full"}},
		{Name: "snapshot_diff", Arguments: map[string]any{"device": "fw01"}},
	}
	// Each call alone, on a server of its own, is the answer to match: a cold
	// cache there, a shared and warm one in the parallel run.
	alone, _, _ := httpLab(t, Options{})
	want := make([]any, len(calls))
	for i, p := range calls {
		res, err := httpClient(t, alone, nil).CallTool(ctx, &p)
		if err != nil || res.IsError {
			t.Fatalf("%s alone: %v %s", p.Name, err, textOf(res))
		}
		want[i] = plain(t, res.StructuredContent)
	}
	const n = 16
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			p := calls[i%len(calls)]
			res, err := httpClient(t, url, nil).CallTool(ctx, &p)
			if err != nil || res.IsError {
				t.Errorf("call %d %s: %v %s", i, p.Name, err, textOf(res))
				return
			}
			if got := plain(t, res.StructuredContent); !reflect.DeepEqual(got, want[i%len(calls)]) {
				t.Errorf("call %d %s: the answer differs from the call alone", i, p.Name)
			}
		})
	}
	wg.Wait()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	ok := 0
	for _, c := range rec.calls {
		if c.Status == StatusOK {
			ok++
		}
	}
	if ok != n {
		t.Errorf("%d of %d calls audited ok", ok, n)
	}
}

// textOf is a result's text, or "" for none.
func textOf(res *sdk.CallToolResult) string {
	if res == nil {
		return ""
	}
	return text(res)
}

// S3 end to end: output that fails the tool's output schema reaches the
// client as a JSON-RPC error through the real SDK, and the audit has it as
// internal. The tool answers search's envelope against lookup's schema.
func TestOutputOutsideTheSchemaIsInternal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := labEnv(t, snap{pathlab.FW01, fixture("firewall-lab.xml")})
	rec := &recorder{}
	s, _, err := build(Options{Env: env, Audit: rec, Version: "test"}, true)
	if err != nil {
		t.Fatal(err)
	}
	tool, err := toolOf("lookup", env.Inventory.Names())
	if err != nil {
		t.Fatal(err)
	}
	tool.Name = "lookup_answered_by_search"
	sdk.AddTool(s, tool, func(ctx context.Context, _ *sdk.CallToolRequest, a lookupArgs) (*sdk.CallToolResult, output, error) {
		e, err := query.Search(ctx, env, query.SearchInput{Term: a.Name})
		return answer(ctx, e, err, a.Detail, query.Finding.Summary)
	})
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
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: tool.Name, Arguments: map[string]any{"name": pathlab.Destination}})
	if err == nil {
		t.Fatalf("the SDK passed output outside the schema: %+v", res)
	}
	c := rec.last(t)
	if c.Tool != tool.Name || c.Status != StatusInternal || c.Code != "call.internal" || !strings.Contains(c.Err, "output") {
		t.Errorf("audit %+v", c)
	}
	// The same server answers the next call.
	if res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "search", Arguments: map[string]any{"value": pathlab.Destination}}); err != nil || res.IsError {
		t.Errorf("next call: %v", err)
	}
}
