package query

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"testing"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
)

// sharedOps is a stand-in for the server's cache: it holds each snapshot's
// operational data once and hands the same tables to every question.
type sharedOps struct {
	mu     sync.Mutex
	tables map[string]estate.OpTables
	reads  int
}

func (s *sharedOps) HA(sn store.Snapshot) (resolve.HAState, error) { return estate.DiskOps{}.HA(sn) }

func (s *sharedOps) Tables(sn store.Snapshot) (estate.OpTables, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sn.Device + "@" + sn.ID
	if t, ok := s.tables[key]; ok {
		return t, nil
	}
	s.reads++
	t, err := estate.DiskOps{}.Tables(sn)
	if err == nil {
		s.tables[key] = t
	}
	return t, err
}

// sharedConfigs is a stand-in for the server's cache of configurations: it
// loads each snapshot once and hands the same configuration and index set to
// every question.
type sharedConfigs struct {
	mu     sync.Mutex
	loaded map[string]estate.Loaded
	loads  int
}

func (s *sharedConfigs) Config(sn store.Snapshot) (estate.Loaded, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sn.Device + "@" + sn.ID
	if l, ok := s.loaded[key]; ok {
		return l, nil
	}
	s.loads++
	l, err := estate.DiskConfigs{}.Config(sn)
	if err == nil {
		l.Indexes = index.NewSet(l.Config)
		s.loaded[key] = l
	}
	return l, err
}

// elapsed is a stage's timing, the one value that differs between runs.
var elapsed = regexp.MustCompile(`"elapsed_ms":[0-9.e+-]+`)

// Questions of every kind run at once on one store and one shared source of
// operational data and of configurations, and each answers as it does alone
// with neither. Run with -race: the
// queries keep no package state, and what they share they only read (spec
// 2026-10-09 §4.10).
func TestParallelQueriesShareAStore(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.fetch(pathlab.FW01, pathlab.ConfigFile(pathlab.FW01))
	l.fetch(pathlab.FW02, pathlab.ConfigFile(pathlab.FW02))
	l.fetch(pathlab.FW01, pathlab.ConfigFile(pathlab.FW01))
	env := l.env()
	ops := &sharedOps{tables: map[string]estate.OpTables{}}
	env.Ops = ops
	ctx := context.Background()
	asJSON := func(v any, err error) (string, error) {
		if err != nil {
			return "", err
		}
		b, err := json.Marshal(v)
		return elapsed.ReplaceAllString(string(b), `"elapsed_ms":0`), err
	}
	questions := []func() (string, error){
		func() (string, error) { return asJSON(Policy(ctx, env, PolicyInput{Flow: labFlow()})) },
		func() (string, error) {
			return asJSON(Routing(ctx, env, RoutingInput{Source: pathlab.Source, Destination: pathlab.Destination, Port: "udp/53", RIB: true}))
		},
		func() (string, error) {
			return asJSON(NAT(ctx, env, NATInput{Flow: labFlow(), Device: pathlab.FW01, Router: "default"}))
		},
		func() (string, error) { return asJSON(Search(ctx, env, SearchInput{Term: pathlab.Destination})) },
		func() (string, error) { return asJSON(Lookup(ctx, env, LookupInput{Name: "any", Expand: true})) },
		func() (string, error) { return asJSON(SnapshotDiff(ctx, env, DiffInput{})) },
		func() (string, error) {
			return asJSON(PolicyFile(ctx, env, PolicyFileInput{Flow: labFlow(), Selection: Selection{File: fixture("firewall-lab.xml"), Vsys: []string{"vsys1"}}}))
		},
	}
	// Alone, each question loads its configurations itself; together they
	// share them.
	alone := make([]string, len(questions))
	for i, q := range questions {
		var err error
		if alone[i], err = q(); err != nil {
			t.Fatalf("question %d: %v", i, err)
		}
	}
	configs := &sharedConfigs{loaded: map[string]estate.Loaded{}}
	env.Configs = configs
	const calls = 16
	got := make([]string, calls)
	errs := make([]error, calls)
	var wg sync.WaitGroup
	for i := range calls {
		wg.Go(func() { got[i], errs[i] = questions[i%len(questions)]() })
	}
	wg.Wait()
	for i := range calls {
		q := i % len(questions)
		if errs[i] != nil {
			t.Errorf("call %d: %v", i, errs[i])
		} else if got[i] != alone[q] {
			n := 0
			for n < len(got[i]) && n < len(alone[q]) && got[i][n] == alone[q][n] {
				n++
			}
			t.Errorf("call %d answers otherwise than question %d alone, from byte %d:\n%.200s\n%.200s", i, q, n, got[i][n:], alone[q][n:])
		}
	}
	if want := 2; ops.reads != want {
		t.Errorf("tables read %d times, want %d: one per snapshot a question routes over", ops.reads, want)
	}
	if want := 3; configs.loads != want {
		t.Errorf("configurations loaded %d times, want %d: one per snapshot", configs.loads, want)
	}
}
