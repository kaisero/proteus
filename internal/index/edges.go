package index

import (
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

// Edges is a configuration's edge list, read once and handed to every index built
// from that configuration. It is never mutated after it is read, so the indexes
// that share it need no lock. Whoever reads it owns it: the package keeps none.
type Edges struct {
	cfg  *config.Config
	list edgeList
}

// ReadEdges reads every reference edge in a configuration.
func ReadEdges(cfg *config.Config) (*Edges, error) {
	list, err := readEdges(cfg)
	if err != nil {
		return nil, err
	}
	return &Edges{cfg: cfg, list: list}, nil
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
