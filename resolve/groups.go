package resolve

import (
	"fmt"
	"sort"
	"strings"

	"github.com/okaiser/go-panos-schema/config"
)

// Members is a group's membership as the configuration describes it.
type Members struct {
	Static []string // members named directly
	ByTag  []string // members matched by a dynamic filter, within this scope only
	Filter string   // the dynamic filter, if any
	Note   string   // what this answer does not cover
}

const runtimeNote = "Members registered at runtime through User-ID or VM " +
	"monitoring are not in a configuration file and are not included."

// ResolveGroup returns the membership of an address group as seen by the target.
func (t *Target) ResolveGroup(name string) (Members, error) {
	return resolveGroup(t.root, t.Chain(), name)
}

// GroupInScope returns the membership of an address group as seen in one scope.
//
// The same shared group resolves differently in different device groups, because
// only the visible scope contributes members. Observed on Panorama 11.2.7-h1:
// corp-location is 10.124.0.0/16 in host_1_directory and 10.125.0.0/16 in its
// sibling corp-graz. See AGENTS.md R5.
func GroupInScope(cfg *config.Config, sc config.Scope, name string) (Members, error) {
	chain, err := chainFor(cfg, sc)
	if err != nil {
		return Members{}, err
	}
	return resolveGroup(cfg.Root(), chain, name)
}

func resolveGroup(root *config.Element, chain []config.Scope, name string) (Members, error) {
	groups := objectsInChain(root, chain, "address-group")
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
		sort.Strings(known)
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
	want := strings.Trim(target.Value, "' ")

	for _, a := range objectsInChain(root, chain, "address") {
		for _, tag := range a.Tags {
			if tag == want {
				out.ByTag = append(out.ByTag, a.Name)
				break
			}
		}
	}
	sort.Strings(out.ByTag)
	return out, nil
}
