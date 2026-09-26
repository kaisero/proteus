package index

import "github.com/okaiser/go-panos-schema/config"

// Ref is one reference edge.
//
// Candidates is a list, not a single kind: of 2,420 reference fields in
// cms-schema.xml, 919 declare two or more and the worst declares 31, so the schema
// alone cannot say which kind a target is. From is an instance path, because two
// device groups can each hold an object of the same name.
type Ref struct {
	Scope      config.Scope
	From       string
	Field      string
	Target     string
	Candidates []string
}

// refsIndex answers "what points at this name".
type refsIndex struct {
	byTarget map[uint32][]Ref
}

// newRefsIndex reads the configuration once and keeps the edges whose scope this
// index covers. Shared edges are kept too, because every scope inherits shared.
func newRefsIndex(in *Interner, cfg *config.Config, sc config.Scope) (*refsIndex, error) {
	r := &refsIndex{byTarget: map[uint32][]Ref{}}
	err := cfg.Walk(func(e config.Event) bool {
		if e.Scope != sc && e.Scope.Sort != config.ScopeShared {
			return true
		}
		for _, v := range e.Values {
			id := in.ID(v)
			r.byTarget[id] = append(r.byTarget[id], Ref{
				Scope:      e.Scope,
				From:       e.EntryPath,
				Field:      e.Field,
				Target:     v,
				Candidates: e.Candidates,
			})
		}
		return true
	})
	return r, err
}

// Refs returns every edge pointing at a name.
func (i *Index) Refs(name string) []Ref {
	id, known := i.in.Lookup(name)
	if !known {
		return nil
	}
	return append([]Ref{}, i.refs.byTarget[id]...)
}
