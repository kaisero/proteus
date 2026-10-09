package cli

import (
	"context"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/store"
)

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
	env.Store, env.Fresh = st, a.freshFetch(s.inv, st)
	return env, nil
}

// selectionEnv is the env of a question on a selection: one file needs neither
// the inventory nor the store; the store's devices need both.
func (a *app) selectionEnv(sel query.Selection) (query.Env, error) {
	s, err := a.settings(sel.File == "")
	if err != nil {
		return query.Env{}, err
	}
	if sel.File != "" {
		return a.queryEnv(s), nil
	}
	return a.storeEnv(s)
}

// freshFetch fetches the selected devices before a question reads them (--fresh).
// What each fetch found becomes notes on its device: TLS verification off, a
// failed document, or a failed fetch that leaves the previous snapshot in use.
func (a *app) freshFetch(inv *inventory.Inventory, st *store.Store) func(context.Context, []string) (map[string][]reason.Reason, error) {
	return func(ctx context.Context, names []string) (map[string][]reason.Reason, error) {
		out := map[string][]reason.Reason{}
		for _, r := range a.fetcher(inv, st).each(ctx, names) {
			var ns []reason.Reason
			if r.TLSVerification != nil && !*r.TLSVerification {
				ns = append(ns, tlsOff())
			}
			for _, d := range r.Documents {
				if d.Error != "" {
					ns = append(ns, reason.New("note.fresh-document-failed", "fresh fetch: "+d.Name+" failed: "+d.Error))
				}
			}
			if r.Error != "" {
				ns = append(ns, reason.New("note.fresh-failed", "fresh fetch failed, answering from the previous snapshot: "+r.Error))
			}
			out[r.Device] = ns
		}
		return out, nil
	}
}
