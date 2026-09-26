package resolve

import (
	"strings"

	"github.com/okaiser/go-panos-schema/config"
)

// Object is one configuration object visible in a scope.
type Object struct {
	Name         string
	Kind         string // address, address-group, service, tag, ...
	Scope        config.Scope
	Value        string
	Tags         []string
	ShadowedFrom *config.Scope // the scope whose definition this one replaced
}

// Objects returns the objects of one kind visible to the target, with a
// descendant definition shadowing an ancestor's of the same name.
func (t *Target) Objects(kind string) ([]Object, error) {
	return objectsInChain(t.root, t.Chain(), kind), nil
}

// ObjectsInScope returns the objects of one kind visible in a scope and its
// ancestors.
func ObjectsInScope(cfg *config.Config, sc config.Scope, kind string) ([]Object, error) {
	chain, err := chainFor(cfg, sc)
	if err != nil {
		return nil, err
	}
	return objectsInChain(cfg.Root(), chain, kind), nil
}

// chainFor returns the scopes a scope inherits from, shared first.
func chainFor(cfg *config.Config, sc config.Scope) ([]config.Scope, error) {
	if sc.Sort == config.ScopeDeviceGroup {
		h, err := NewHierarchy(cfg)
		if err != nil {
			return nil, err
		}
		return h.Chain(sc.Name), nil
	}
	chain := []config.Scope{{Sort: config.ScopeShared}}
	if sc.Sort != config.ScopeShared {
		chain = append(chain, sc)
	}
	return chain, nil
}

// objectsInChain walks the chain root to leaf, so a later definition replaces an
// earlier one and the replacement is recorded.
func objectsInChain(root *config.Element, chain []config.Scope, kind string) []Object {
	byName := map[string]Object{}
	var order []string
	for _, sc := range chain {
		for _, o := range readObjects(root, sc, kind) {
			if prev, seen := byName[o.Name]; seen {
				prevScope := prev.Scope
				o.ShadowedFrom = &prevScope
			} else {
				order = append(order, o.Name)
			}
			byName[o.Name] = o
		}
	}
	out := make([]Object, 0, len(order))
	for _, n := range order {
		out = append(out, byName[n])
	}
	return out
}

// scopeContainer names where a scope's objects live, as a path under /config.
func scopeContainer(sc config.Scope) ([]string, bool) {
	switch sc.Sort {
	case config.ScopeShared:
		return []string{"shared"}, true
	case config.ScopeDeviceGroup:
		return []string{"devices", "entry", "device-group", "entry"}, true
	case config.ScopeVsys:
		return []string{"devices", "entry", "vsys", "entry"}, true
	default:
		return nil, false
	}
}

// readObjects reads one scope's objects of one kind.
//
// The container path is matched exactly, so a template's nested configuration
// cannot contribute objects to a device group.
func readObjects(root *config.Element, sc config.Scope, kind string) []Object {
	path, ok := scopeContainer(sc)
	if !ok {
		return nil
	}
	var out []Object
	for _, container := range root.Find(path...) {
		if sc.Name != "" && container.Attr("name") != sc.Name {
			continue
		}
		for _, e := range container.Find(kind, "entry") {
			out = append(out, Object{
				Name:  e.Attr("name"),
				Kind:  kind,
				Scope: sc,
				Value: objectValue(e),
				Tags:  e.Child("tag").Members(),
			})
		}
	}
	return out
}

// objectValue reduces an object to the one value that identifies it.
func objectValue(e *config.Element) string {
	for _, f := range []string{"ip-netmask", "ip-range", "fqdn", "ip-wildcard"} {
		if v := e.Child(f).TextOr(""); v != "" {
			return v
		}
	}
	if m := e.Child("static").Members(); len(m) > 0 {
		return strings.Join(m, ", ")
	}
	if v := e.Child("dynamic").Child("filter").TextOr(""); v != "" {
		return v
	}
	if m := e.Child("value").Members(); len(m) > 0 {
		return strings.Join(m, ", ")
	}
	return ""
}
