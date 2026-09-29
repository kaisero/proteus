package index

import (
	"sync"

	"github.com/okaiser/proteus/internal/config"
)

// edgeList is every reference edge in a configuration, in document order, each
// carrying the scope it was found in.
//
// This is a materialisation of the file, not an index: it answers no question and
// is keyed by nothing. R10 keeps indexes scoped, and every index built from this
// still is — a scope's index holds only the edges that scope can see. What is
// shared here is the reading, which is the same work whoever asks for it.
//
// Reading it once matters. newRefsIndex walked the whole configuration and threw
// away everything outside its scope, so a file with N scopes was read N times.
// BenchmarkRefsIndexEveryScope builds every scope's index of a generated 13-scope
// firewall in 0.044 s; BenchmarkReadEdges reads it once in 0.034 s. Before the
// shared edge list, each of those builds re-read the file.
type edgeList []Ref

type edgeCacheEntry struct {
	once  sync.Once
	edges edgeList
	err   error
}

var (
	edgeCacheMu sync.Mutex
	edgeCache   = map[string]*edgeCacheEntry{}
)

// edgesOf returns every reference edge in a configuration, reading it on the first
// call and returning the same slice afterwards.
//
// The slice is never mutated after it is built, so concurrent readers need no lock
// once past the sync.Once, which is the same contract Index itself has.
func edgesOf(cfg *config.Config) (edgeList, error) {
	key := cfg.Path()

	edgeCacheMu.Lock()
	e, ok := edgeCache[key]
	if !ok {
		e = &edgeCacheEntry{}
		edgeCache[key] = e
	}
	edgeCacheMu.Unlock()

	e.once.Do(func() { e.edges, e.err = readEdges(cfg) })
	if e.err != nil {
		// A failed read is not cached, so a later call can retry.
		edgeCacheMu.Lock()
		delete(edgeCache, key)
		edgeCacheMu.Unlock()
		return nil, e.err
	}
	return e.edges, nil
}

func readEdges(cfg *config.Config) (edgeList, error) {
	var out edgeList
	err := cfg.WalkPaths(func(e config.Event) bool {
		for _, v := range e.Values {
			out = append(out, Ref{
				Scope:      e.Scope,
				From:       e.EntryPath,
				Field:      e.Field,
				Target:     v,
				Candidates: e.Candidates,
			})
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
