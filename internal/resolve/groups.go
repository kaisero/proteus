package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/config"
)

// Members is a group's membership as the configuration describes it.
type Members struct {
	Static      []string // members named directly
	ByTag       []string // members matched by a dynamic filter, within this scope only
	Filter      string   // the dynamic filter, if any
	FilterError string   // set when the filter could not be parsed, so ByTag is empty
	Note        string   // what this answer does not cover
}

const runtimeNote = "Members registered at runtime through User-ID or VM " +
	"monitoring are not in a configuration file and are not included."

// ResolveGroup returns the membership of an address group as seen by the target.
func (t *Target) ResolveGroup(name string) (Members, error) {
	return resolveGroup(t.cfg, t.Chain(), name)
}

// GroupInScope returns the membership of an address group as seen in one scope.
//
// The same shared group resolves differently in different vsys, because only
// shared and the vsys itself contribute members. First observed on a lab device,
// PAN-OS 11.2.7-h1: corp-location was 10.124.0.0/16 in one scope and
// 10.125.0.0/16 in its sibling. See AGENTS.md R5.
func GroupInScope(cfg *config.Config, sc config.Scope, name string) (Members, error) {
	return resolveGroup(cfg, chainFor(sc), name)
}

func resolveGroup(cfg *config.Config, chain []config.Scope, name string) (Members, error) {
	groups := objectsInChain(cfg, chain, "address-group", nil)
	var target *Object
	for i := range groups {
		if groups[i].Name == name {
			target = &groups[i]
		}
	}
	if target == nil {
		known := make([]string, 0, len(groups))
		for _, g := range groups {
			known = append(known, g.Name)
		}
		slices.Sort(known)
		return Members{}, fmt.Errorf("resolve: no address group %q in this scope; it has %v",
			name, known)
	}

	out := Members{Note: runtimeNote}
	// A dynamic group's value is its tag filter, which PAN-OS quotes. A static
	// group's value is its member list.
	if !strings.HasPrefix(target.Value, "'") {
		out.Static = strings.Split(target.Value, ", ")
		return out, nil
	}
	out.Filter = target.Value
	filter, err := ParseTagFilter(target.Value)
	if err != nil {
		// A filter that cannot be parsed yields no members rather than a guess:
		// putting an object in a group PAN-OS would leave out is worse than saying
		// nothing. The caller is told why.
		out.FilterError = err.Error()
		return out, nil
	}
	for _, a := range objectsInChain(cfg, chain, "address", nil) {
		if filter.Match(a.Tags) {
			out.ByTag = append(out.ByTag, a.Name)
		}
	}
	slices.Sort(out.ByTag)
	return out, nil
}
