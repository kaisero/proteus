package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kaisero/proteus/internal/simulate/pathlab"
)

// More calls than slots wait in the queue; one more is busy at once.
func TestTheCallQueueIsBounded(t *testing.T) {
	t.Parallel()
	l := newLimiter(1, 1, time.Minute, time.Minute)
	if err := l.enter(context.Background()); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- l.enter(context.Background()) }()
	eventually(t, "the second call waits", func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.waiting == 1
	})
	if err := l.enter(context.Background()); !errors.Is(err, errQueueFull) || !isBusy(err) {
		t.Errorf("third call: %v", err)
	}
	l.leave()
	if err := <-waited; err != nil {
		t.Errorf("the waiting call: %v", err)
	}
	// A waiting caller that goes is not kept.
	ctx, cancel := context.WithCancel(context.Background())
	gone := make(chan error, 1)
	go func() { gone <- l.enter(ctx) }()
	eventually(t, "a call waits", func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.waiting == 1
	})
	cancel()
	if err := <-gone; !errors.Is(err, context.Canceled) {
		t.Errorf("the caller that went: %v", err)
	}
}

// A call that waits longer than max_wait is busy.
func TestACallWaitsAtMostMaxWait(t *testing.T) {
	t.Parallel()
	l := newLimiter(1, 4, 20*time.Millisecond, time.Minute)
	if err := l.enter(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := l.enter(context.Background())
	if !isBusy(err) || !strings.Contains(err.Error(), "waited 20ms") || time.Since(start) < 20*time.Millisecond {
		t.Errorf("err = %v after %s", err, time.Since(start))
	}
	if te := errorOf(err); te.Code != "call.busy" {
		t.Errorf("tool error %+v", te)
	}
}

// Stopping refuses new and waiting calls, waits for the running work, and
// gives up after the call timeout.
func TestStopWaitsForTheRunningWork(t *testing.T) {
	t.Parallel()
	l := newLimiter(2, 4, time.Minute, time.Minute)
	if err := l.enter(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := l.enter(context.Background()); err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() { waiting <- l.enter(context.Background()) }()
	eventually(t, "a call waits", func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.waiting == 1
	})
	stopped := make(chan bool, 1)
	go func() { stopped <- l.stop() }()
	if err := <-waiting; !errors.Is(err, errStopping) {
		t.Errorf("the waiting call: %v", err)
	}
	if err := l.enter(context.Background()); !errors.Is(err, errStopping) {
		t.Errorf("a new call: %v", err)
	}
	l.leave()
	select {
	case <-stopped:
		t.Fatal("stop returned while work runs")
	case <-time.After(20 * time.Millisecond):
	}
	l.leave()
	if ok := <-stopped; !ok {
		t.Error("stop gave up although the work returned")
	}
	short := newLimiter(1, 1, time.Minute, 20*time.Millisecond)
	if err := short.enter(context.Background()); err != nil {
		t.Fatal(err)
	}
	if short.stop() {
		t.Error("stop waited past the call timeout")
	}
}

// A call past call_timeout answers call.timeout; its work sees the deadline,
// keeps the slot until it returns, and its late answer is not audited.
func TestATimeoutKeepsTheSlot(t *testing.T) {
	t.Parallel()
	rec := &recorder{}
	m := middleware{audit: rec, now: time.Now, lim: newLimiter(1, 0, time.Millisecond, 30*time.Millisecond)}
	req := &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "search", Arguments: json.RawMessage(`{"value":"x"}`)}}
	release := make(chan struct{})
	var sawDeadline atomic.Bool
	slow := func(ctx context.Context, _ string, _ sdk.Request) (sdk.Result, error) {
		<-ctx.Done()
		sawDeadline.Store(errors.Is(ctx.Err(), context.DeadlineExceeded))
		<-release
		callOf(ctx).set(func(c *Call) { c.Status = StatusOK })
		return &sdk.CallToolResult{}, nil
	}
	ctx := context.Background()
	res, err := m.receive(slow)(ctx, "tools/call", req)
	if r, _ := res.(*sdk.CallToolResult); err != nil || r == nil || !r.IsError || !strings.HasPrefix(text(r), "call.timeout") {
		t.Fatalf("%v %+v", err, res)
	}
	if c := rec.last(t); c.Status != StatusTimeout || c.Code != "call.timeout" || c.Tool != "search" {
		t.Errorf("audit %+v", c)
	}
	eventually(t, "the work sees the deadline", sawDeadline.Load)
	// The next calls must answer in time, also under a loaded -race run.
	// Only this goroutine reads the timeout: each call reads it as it starts.
	m.lim.timeout = time.Minute
	// The slot is still held: the next call is busy at once.
	fast := func(ctx context.Context, _ string, _ sdk.Request) (sdk.Result, error) {
		callOf(ctx).set(func(c *Call) { c.Status = StatusOK })
		return &sdk.CallToolResult{}, nil
	}
	if res, _ := m.receive(fast)(ctx, "tools/call", req); !strings.HasPrefix(text(res.(*sdk.CallToolResult)), "call.busy") {
		t.Errorf("while the work runs: %+v", res)
	}
	if c := rec.last(t); c.Status != StatusBusy || c.Code != "call.busy" {
		t.Errorf("busy audit %+v", c)
	}
	close(release)
	eventually(t, "the slot is free", func() bool { return len(m.lim.slots) == 0 })
	if res, err := m.receive(fast)(ctx, "tools/call", req); err != nil || res.(*sdk.CallToolResult).IsError {
		t.Errorf("after: %v %+v", err, res)
	}
	if c := rec.last(t); c.Status != StatusOK {
		t.Errorf("audit after %+v", c)
	}
	// The work frees its slot before it hands its answer over: the next
	// call finds it free, with no queue to wait in.
	if len(m.lim.slots) != 0 {
		t.Error("the slot of an answered call is still held")
	}
	rec.mu.Lock()
	n := len(rec.calls)
	rec.mu.Unlock()
	if n != 3 {
		t.Errorf("%d audit lines, want 3: the late answer is not one", n)
	}
	// A cancelled call answers call.timeout too.
	gone, cancel := context.WithCancel(ctx)
	cancel()
	hold := make(chan struct{})
	held := func(context.Context, string, sdk.Request) (sdk.Result, error) {
		<-hold
		return &sdk.CallToolResult{}, nil
	}
	if res, _ := m.receive(held)(gone, "tools/call", req); !strings.HasPrefix(text(res.(*sdk.CallToolResult)), "call.timeout") {
		t.Errorf("cancelled: %+v", res)
	}
	close(hold)
	// In a test binary a panic in the work panics on in the caller.
	strict := middleware{now: time.Now, strict: true, lim: newLimiter(1, 0, time.Millisecond, time.Minute)}
	func() {
		defer func() {
			if p := recover(); p != "boom" {
				t.Errorf("strict: %v", p)
			}
		}()
		_, _ = strict.receive(func(context.Context, string, sdk.Request) (sdk.Result, error) { panic("boom") })(ctx, "tools/call", req)
	}()
}

// When Serve's context ends, new calls are busy, a running call still
// answers, and then Serve returns.
func TestServeStopsAfterTheRunningCalls(t *testing.T) {
	t.Parallel()
	env := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	entered, release := make(chan struct{}), make(chan struct{})
	env.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		close(entered)
		<-release
		return []netip.Addr{netip.MustParseAddr(pathlab.Destination)}, nil
	}
	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	ct, st := sdk.NewInMemoryTransports()
	served := make(chan error, 1)
	go func() {
		served <- Serve(ctx, Options{Env: env, Audit: rec, Limits: Limits{CallTimeout: 10 * time.Second}}, st)
	}()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "client", Version: "test"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	first := make(chan *sdk.CallToolResult, 1)
	go func() {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "simulate_routing", Arguments: map[string]any{"source": pathlab.Source, "destination": "app.example.test"}})
		if err != nil {
			t.Error(err)
		}
		first <- res
	}()
	<-entered
	cancel()
	eventually(t, "new calls are busy", func() bool {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{Name: "search", Arguments: map[string]any{"value": "x"}})
		return err == nil && strings.HasPrefix(text(res), "call.busy: the server is stopping")
	})
	if c := rec.last(t); c.Status != StatusBusy || c.Tool != "search" {
		t.Errorf("busy audit %+v", c)
	}
	select {
	case err := <-served:
		t.Fatalf("Serve returned while a call runs: %v", err)
	default:
	}
	close(release)
	if res := <-first; res == nil || res.IsError {
		t.Errorf("the running call: %+v", res)
	}
	if err := <-served; !errors.Is(err, context.Canceled) {
		t.Errorf("Serve: %v", err)
	}
}

// With no call running or arriving, a stop does not wait the answer grace.
func TestServeStopsAtOnceWhenIdle(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	ct, st := sdk.NewInMemoryTransports()
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, Options{Env: labEnv(t)}, st) }()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "client", Version: "test"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	start := time.Now()
	cancel()
	if err := <-served; !errors.Is(err, context.Canceled) {
		t.Errorf("Serve: %v", err)
	}
	if d := time.Since(start); d >= answerGrace {
		t.Errorf("an idle stop took %s", d)
	}
}

// When the client goes, Serve returns.
func TestServeEndsWithTheClient(t *testing.T) {
	t.Parallel()
	ct, st := sdk.NewInMemoryTransports()
	served := make(chan error, 1)
	go func() { served <- Serve(context.Background(), Options{Env: labEnv(t)}, st) }()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "client", Version: "test"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = cs.Close()
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// Zero limits take the defaults of spec §4.2.
func TestLimitDefaults(t *testing.T) {
	t.Parallel()
	if got := (Limits{}).withDefaults(); got != DefaultLimits {
		t.Errorf("%+v", got)
	}
	set := Limits{MaxConcurrent: 1, MaxQueue: 2, MaxWait: time.Second, CallTimeout: time.Second, MaxLoads: 3, MaxCacheMB: 4}
	if got := set.withDefaults(); got != set {
		t.Errorf("%+v", got)
	}
}
