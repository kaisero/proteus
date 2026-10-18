package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kaisero/proteus/internal/query"
	"github.com/kaisero/proteus/internal/runlog"
	"github.com/kaisero/proteus/internal/simulate/pathlab"
)

// A call's run log, mcp-<tool>-<time>-<seq>.log, holds its input, what the
// query logged, and how it ended. It is written only for a call that ends
// internal (with the panic's stack) or timeout, or for every call at debug
// (spec §4.9, §4.10; spec 2026-10-10 F4).
func TestRunLogsOnlyForFailedCalls(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	env := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	panicking := env
	panicking.Resolve = func(context.Context, string) ([]netip.Addr, error) { panic("resolver bug") }
	slow := env
	slow.Resolve = func(ctx context.Context, _ string) ([]netip.Addr, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ok := map[string]any{"source": pathlab.Source, "destination": pathlab.Destination}
	byName := map[string]any{"destination": "host.example.test", "device": "fw01"}
	// run makes one call at level with the call timeout and returns the run
	// logs it left in a directory of its own, and the audited status. Only
	// the slow call gets a short timeout: under -race a first load alone
	// takes about 200 ms.
	run := func(level runlog.Level, timeout time.Duration, env query.Env, args map[string]any) ([]string, string) {
		t.Helper()
		dir, rec := t.TempDir(), &recorder{}
		o := Options{
			Env: env, Audit: rec, Logs: &runlog.Options{Dir: dir, Keep: 10, Level: level},
			Limits: Limits{CallTimeout: timeout},
		}
		s, _, err := build(o, false)
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
		if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "simulate_routing", Arguments: args}); err != nil {
			t.Fatal(err)
		}
		_ = cs.Close()
		_ = ss.Wait()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		name := regexp.MustCompile(`^mcp-simulate_routing-\d{8}T\d{6}\.\d{3}Z-\d{3,}\.log$`)
		var texts []string
		for _, e := range entries {
			if !name.MatchString(e.Name()) {
				t.Errorf("run log name %s", e.Name())
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			texts = append(texts, string(b))
		}
		return texts, rec.last(t).Status
	}
	if logs, status := run(runlog.Info, time.Minute, env, ok); status != StatusOK || len(logs) != 0 {
		t.Errorf("an answered call: %s, logs %q", status, logs)
	}
	logs, status := run(runlog.Info, time.Minute, panicking, byName)
	if status != StatusInternal || len(logs) != 1 || !strings.Contains(logs[0], "panic: resolver bug") ||
		!strings.Contains(logs[0], "goroutine") || !strings.Contains(logs[0], "status internal call.internal") ||
		!strings.Contains(logs[0], `call simulate_routing: {"destination":"host.example.test"`) {
		t.Errorf("a panicking call: %s, logs:\n%s", status, strings.Join(logs, "\n---\n"))
	}
	logs, status = run(runlog.Info, 200*time.Millisecond, slow, byName)
	if status != StatusTimeout || len(logs) != 1 || !strings.Contains(logs[0], "status timeout call.timeout") ||
		!strings.Contains(logs[0], "call simulate_routing:") {
		t.Errorf("a timed-out call: %s, logs:\n%s", status, strings.Join(logs, "\n---\n"))
	}
	logs, status = run(runlog.Debug, time.Minute, env, ok)
	if status != StatusOK || len(logs) != 1 || !strings.Contains(logs[0], "status ok") ||
		!strings.Contains(logs[0], `call simulate_routing: {"destination":"`+pathlab.Destination) || !strings.Contains(logs[0], "[SNAP]") {
		t.Errorf("an answered call at debug: %s, logs:\n%s", status, strings.Join(logs, "\n---\n"))
	}
	// A run log that cannot open leaves the call without one.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var proc bytes.Buffer
	procLog, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "mcp", Level: runlog.Info, Echo: &proc})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = procLog.Close() })
	m := middleware{logs: &runlog.Options{Dir: filepath.Join(file, "sub"), Level: runlog.Debug}, proc: procLog}
	if l := m.openLog(&Call{Tool: "search"}); l != nil {
		t.Errorf("opened %s", l.Path())
	}
	m.logs.Level = runlog.Info
	l := m.openLog(&Call{Tool: "search"})
	m.closeLog(l, &Call{Tool: "search", Status: StatusInternal})
	if l.Path() != "" {
		t.Errorf("persisted %s", l.Path())
	}
	if !strings.Contains(proc.String(), "[WARN] [RUN] mcp: the run log of a call to search (status internal) was not written") {
		t.Errorf("process log:\n%s", proc.String())
	}
	m.closeLog(nil, &Call{})
	// The error the SDK returned goes into the log it keeps.
	m.logs.Dir = t.TempDir()
	l = m.openLog(&Call{Tool: "lookup"})
	m.closeLog(l, &Call{Status: StatusInternal, Code: "call.internal", Err: "output fails its schema"})
	if b, err := os.ReadFile(l.Path()); err != nil || !strings.Contains(string(b), "[WARN] [RUN] output fails its schema") {
		t.Errorf("log %q: %v", b, err)
	}
}

// A call refused before it runs (busy) is audited but writes no run log.
func TestABusyCallHasNoRunLog(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	rec := &recorder{}
	lim := newLimiter(1, 1, time.Second, time.Second)
	lim.stop()
	m := middleware{audit: rec, now: time.Now, logs: &runlog.Options{Dir: dir, Keep: 10, Level: runlog.Info}, lim: lim}
	next := func(context.Context, string, sdk.Request) (sdk.Result, error) {
		t.Error("a refused call ran")
		return nil, nil
	}
	req := &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "search", Arguments: json.RawMessage(`{"value":"x"}`)}}
	if _, err := m.receive(next)(context.Background(), "tools/call", req); err != nil {
		t.Fatal(err)
	}
	if c := rec.last(t); c.Status != StatusBusy || c.Code != "call.busy" {
		t.Errorf("audit %+v", c)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("run logs %v", entries)
	}
}

// A call that timed out keeps its run log open for its work: the caller's
// lines come first, then what the work logged late, that it returned, and a
// late panic's stack. The log is closed when the work frees the slot.
func TestALateCallKeepsItsRunLog(t *testing.T) {
	t.Parallel()
	req := &sdk.CallToolRequest{Params: &sdk.CallToolParamsRaw{Name: "search", Arguments: json.RawMessage(`{"value":"x"}`)}}
	for _, tc := range []struct {
		name  string
		panic bool
		want  []string
	}{
		{"returns", false, []string{"status timeout call.timeout", "late line", "work returned after"}},
		{"panics", true, []string{"status timeout call.timeout", "late line", "work returned after", "panic: late bug", "goroutine"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir, rec := t.TempDir(), &recorder{}
			m := middleware{
				audit: rec, now: time.Now, logs: &runlog.Options{Dir: dir, Keep: 10, Level: runlog.Info},
				lim: newLimiter(1, 0, time.Millisecond, 30*time.Millisecond),
			}
			release := make(chan struct{})
			slow := func(ctx context.Context, _ string, _ sdk.Request) (sdk.Result, error) {
				<-ctx.Done()
				<-release
				logOf(ctx).Infof(runlog.TagRun, "late line")
				if tc.panic {
					panic("late bug")
				}
				callOf(ctx).set(func(c *Call) { c.Status = StatusOK })
				return &sdk.CallToolResult{}, nil
			}
			res, err := m.receive(slow)(context.Background(), "tools/call", req)
			if r, _ := res.(*sdk.CallToolResult); err != nil || r == nil || !strings.HasPrefix(text(r), "call.timeout") {
				t.Fatalf("%v %+v", err, res)
			}
			if c := rec.last(t); c.Status != StatusTimeout {
				t.Errorf("audit %+v", c)
			}
			close(release)
			// The work closes the log before it frees the slot.
			eventually(t, "the slot is free", func() bool { return len(m.lim.slots) == 0 })
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("run logs %v, %v", entries, err)
			}
			b, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
			if err != nil {
				t.Fatal(err)
			}
			rest := string(b)
			for _, w := range tc.want {
				_, after, ok := strings.Cut(rest, w)
				if !ok {
					t.Fatalf("no %q in order in:\n%s", w, b)
				}
				rest = after
			}
		})
	}
}
