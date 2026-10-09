package index

import (
	"fmt"
	"sync"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// Set builds the indexes of one configuration on demand: each (scope, rulebase)
// index at most once, all from one edge list. Its owner decides how long the
// indexes live, a CLI run or a cache entry; the package keeps none. It is safe for
// concurrent use.
type Set struct {
	cfg *config.Config

	edgesMu sync.Mutex
	edges   *Edges

	mu    sync.Mutex
	built map[setKey]*setEntry

	// build is Build; a test replaces it.
	build func(*config.Config, *Edges, config.Scope, resolve.Rulebase) (*Index, error)
}

type setKey struct {
	scope config.Scope
	rb    resolve.Rulebase
}

type setEntry struct {
	once  sync.Once
	idx   *Index
	err   error
	panic any // a build's panic, which every caller of the entry repeats
}

// NewSet returns an empty set over a configuration.
func NewSet(cfg *config.Config) *Set {
	return &Set{cfg: cfg, built: map[setKey]*setEntry{}}
}

// Config returns the configuration the set's indexes are built from.
func (s *Set) Config() *config.Config { return s.cfg }

// Index returns a scope's index of a rulebase, building it on the first call.
// Concurrent first calls share one build. A failed build is not kept, so a later
// call can retry.
func (s *Set) Index(sc config.Scope, rb resolve.Rulebase) (*Index, error) {
	k := setKey{scope: sc, rb: rb}
	s.mu.Lock()
	e, ok := s.built[k]
	if !ok {
		e = &setEntry{}
		s.built[k] = e
	}
	s.mu.Unlock()

	e.once.Do(func() {
		// A panic must not leave a done entry with no index and no error: a
		// set a server shares would answer nil to every later call.
		defer func() {
			if p := recover(); p != nil {
				e.idx, e.err, e.panic = nil, fmt.Errorf("index %s %s: build failed: %v", sc, rb, p), p
			}
		}()
		edges, err := s.readEdges()
		if err != nil {
			e.err = err
			return
		}
		build := s.build
		if build == nil {
			build = Build
		}
		e.idx, e.err = build(s.cfg, edges, sc, rb)
	})
	if e.err != nil {
		s.mu.Lock()
		if s.built[k] == e {
			delete(s.built, k)
		}
		s.mu.Unlock()
		if e.panic != nil {
			// Not kept, so a later call builds again; the panic goes on to
			// the caller's recover with its value.
			panic(e.panic)
		}
		return nil, e.err
	}
	return e.idx, nil
}

// Provider returns a function that gives a scope's index of any rulebase, the
// shape a simulation's target carries.
func (s *Set) Provider(sc config.Scope) func(resolve.Rulebase) (*Index, error) {
	return func(rb resolve.Rulebase) (*Index, error) { return s.Index(sc, rb) }
}

// readEdges reads the configuration's edges on the first call. A failed read is
// not kept.
func (s *Set) readEdges() (*Edges, error) {
	s.edgesMu.Lock()
	defer s.edgesMu.Unlock()
	if s.edges != nil {
		return s.edges, nil
	}
	e, err := ReadEdges(s.cfg)
	if err != nil {
		return nil, err
	}
	s.edges = e
	return e, nil
}
