package resolve

import (
	"github.com/kaisero/proteus/internal/config"
)

// URLFilteringProfile is one url-filtering profile visible in a scope.
//
// Lists holds the profile's action lists by name — block, alert, allow, continue,
// override and whatever else the schema grows — each naming URL categories. Which
// list a category sits in decides what the profile does with a matching request, but
// that decision is not modelled here: it depends on the response the site gives and
// on what the session carries, neither of which is in a configuration.
type URLFilteringProfile struct {
	Name  string
	Scope config.Scope
	Lists map[string][]string
}

// ProfileGroup is one security profile group, naming profiles by kind.
type ProfileGroup struct {
	Name  string
	Scope config.Scope
	Kinds map[string][]string
}

// URLFilteringProfilesInScope returns the url-filtering profiles visible in a scope,
// a descendant definition shadowing an ancestor's of the same name.
func URLFilteringProfilesInScope(cfg *config.Config, sc config.Scope) []URLFilteringProfile {
	entries := entriesInScope(cfg, sc, "url-filtering")
	out := make([]URLFilteringProfile, 0, len(entries))
	for _, e := range entries {
		out = append(out, URLFilteringProfile{
			Name:  e.name,
			Scope: e.scope,
			Lists: memberLists(e.el),
		})
	}
	return out
}

// ProfileGroupsInScope returns the security profile groups visible in a scope.
func ProfileGroupsInScope(cfg *config.Config, sc config.Scope) []ProfileGroup {
	entries := entriesInScope(cfg, sc, "profile-group")
	out := make([]ProfileGroup, 0, len(entries))
	for _, e := range entries {
		out = append(out, ProfileGroup{
			Name:  e.name,
			Scope: e.scope,
			Kinds: memberLists(e.el),
		})
	}
	return out
}

// scopedEntry is one entry of a kind, with the scope it was found in.
type scopedEntry struct {
	name  string
	scope config.Scope
	el    *config.Element
}

// entriesInScope reads a kind's entries along a scope's inheritance chain, keeping
// the element itself.
//
// Object does not fit here: these entries carry several lists rather than one value,
// and flattening them to a single string would lose which list a category sits in.
// The visibility rules are the same ones Objects uses — shared first, then the vsys, a later definition replacing an earlier one.
func entriesInScope(cfg *config.Config, sc config.Scope, kind string) []scopedEntry {
	chain := chainFor(sc)
	within := cfg.KindContainer(kind)
	if within == nil {
		within = []string{kind}
	}
	inner := append(append([]string{}, within...), "entry")

	byName := map[string]scopedEntry{}
	var order []string
	for _, s := range chain {
		path, ok := scopeContainer(s)
		if !ok {
			continue
		}
		for _, container := range cfg.Root().Find(path...) {
			if s.Name != "" && container.Attr("name") != s.Name {
				continue
			}
			for _, e := range container.Find(inner...) {
				name := e.Attr("name")
				if _, seen := byName[name]; !seen {
					order = append(order, name)
				}
				byName[name] = scopedEntry{name: name, scope: s, el: e}
			}
		}
	}
	out := make([]scopedEntry, 0, len(order))
	for _, n := range order {
		out = append(out, byName[n])
	}
	return out
}
