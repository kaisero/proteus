package index

import "github.com/okaiser/panos-analyst/config"

// Ref is one reference edge.
//
// Candidates is a list, not a single kind: of 2,961 reference fields in
// cms-schema.xml, 1,034 declare two or more and the worst declares 153, so the
// schema alone cannot say which kind a target is. The counts are pinned by
// TestReferenceFieldCensus. From is an instance path, because two
// vsys can each hold an object of the same name.
type Ref struct {
	Scope      config.Scope
	From       string
	Field      string
	Target     string
	Candidates []string
}

// refsIndex answers "what points at this name", for one scope.
//
// It holds positions into the configuration's edge list rather than copies of the
// edges. A configuration's scopes overlap heavily. Every scope sees shared, so
// copying an edge into each index that can see it stores shared edges once per
// scope.
type refsIndex struct {
	all      edgeList
	byTarget map[uint32][]int32
}

// newRefsIndex keeps the positions of the edges whose scope this index covers.
// Shared edges are kept too, because every scope inherits shared.
func newRefsIndex(in *Interner, cfg *config.Config, sc config.Scope) (*refsIndex, error) {
	all, err := edgesOf(cfg)
	if err != nil {
		return nil, err
	}
	r := &refsIndex{all: all, byTarget: map[uint32][]int32{}}
	for i, e := range all {
		if e.Scope != sc && e.Scope.Sort != config.ScopeShared {
			continue
		}
		id := in.ID(e.Target)
		// G115: a position in the edge list. The largest configuration measured
		// held 479,482 edges, and a file with 2^31 of them would be terabytes.
		//nolint:gosec // see above
		r.byTarget[id] = append(r.byTarget[id], int32(i))
	}
	return r, nil
}

// Refs returns every edge pointing at a name.
func (i *Index) Refs(name string) []Ref {
	id, known := i.in.Lookup(name)
	if !known {
		return nil
	}
	at := i.refs.byTarget[id]
	out := make([]Ref, 0, len(at))
	for _, p := range at {
		out = append(out, i.refs.all[p])
	}
	return out
}
