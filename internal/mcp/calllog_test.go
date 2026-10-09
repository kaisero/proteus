package mcp

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
)

// Each tool call gets its own run log, mcp-<tool>-<time>-<seq>.log, with its
// input, what the query logged, and how it ended; a panic's stack goes there
// (spec §4.9, §4.10).
func TestEachCallHasItsRunLog(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	env := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	broken := env
	broken.Resolve = func(context.Context, string) ([]netip.Addr, error) { panic("resolver bug") }
	logs := &runlog.Options{Dir: dir, Keep: 10, Level: runlog.Info}
	run := func(o Options, args map[string]any) {
		t.Helper()
		o.Logs = logs
		s, err := newServer(o, false)
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
	}
	run(Options{Env: env}, map[string]any{"source": pathlab.Source, "destination": pathlab.Destination})
	run(Options{Env: broken}, map[string]any{"destination": "host.example.test", "device": "fw01"})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	name := regexp.MustCompile(`^mcp-simulate_routing-\d{8}T\d{6}\.\d{3}Z-\d{3,}\.log$`)
	if len(names) != 2 || !name.MatchString(names[0]) || !name.MatchString(names[1]) {
		t.Fatalf("run logs %v", names)
	}
	var texts []string
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		texts = append(texts, string(b))
	}
	ok := slices.IndexFunc(texts, func(s string) bool { return strings.Contains(s, "status ok") })
	bad := slices.IndexFunc(texts, func(s string) bool { return strings.Contains(s, "status internal call.internal") })
	if ok < 0 || bad < 0 || ok == bad {
		t.Fatalf("logs:\n%s", strings.Join(texts, "\n---\n"))
	}
	if !strings.Contains(texts[ok], `call simulate_routing: {"destination":"`+pathlab.Destination) || !strings.Contains(texts[ok], "[SNAP]") {
		t.Errorf("the answered call's log:\n%s", texts[ok])
	}
	if !strings.Contains(texts[bad], "panic: resolver bug") || !strings.Contains(texts[bad], "goroutine") {
		t.Errorf("the failed call's log:\n%s", texts[bad])
	}
	// A run log that cannot open leaves the call without one.
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := middleware{logs: &runlog.Options{Dir: filepath.Join(file, "sub")}}
	if l := m.openLog(&Call{Tool: "search"}); l != nil {
		t.Errorf("opened %s", l.Path())
	}
	closeLog(nil, &Call{})
}
