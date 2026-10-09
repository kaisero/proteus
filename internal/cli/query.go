package cli

import "github.com/okaiser/proteus/internal/query"

// enveloped is the part of an answer a query's envelope gives: the command, the
// results and the qualifiers. A command's answer type embeds it and adds its
// format-1 input block and its text.
type enveloped[In, Res any] struct {
	e query.Envelope[In, Res]
}

func (a enveloped[In, Res]) Command() string { return a.e.Command }
func (a enveloped[In, Res]) Results() any    { return a.e.Results }

func (a enveloped[In, Res]) Qualifiers() qualifiers {
	return qualifiers{Holes: a.e.Holes, Unresolved: a.e.Unresolved, Notes: a.e.Notes}
}

// queryEnv is what a query reads, from the resolved settings, without the store:
// a question on a file needs none.
func (a *app) queryEnv(s settings) query.Env {
	return query.Env{
		Inventory: s.inv, Now: a.now, MaxAge: s.maxAge, Resolve: a.lookup, Log: a.log, Users: a.userSnapshot,
	}
}

// storeEnv is queryEnv with the store, opened with the app's clock.
func (a *app) storeEnv(s settings) (query.Env, error) {
	env := a.queryEnv(s)
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return env, err
	}
	env.Store = st
	return env, nil
}
