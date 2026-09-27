package resolve

import (
	"strings"

	"github.com/okaiser/panos-analyst/config"
)

// Object is one configuration object visible in a scope.
type Object struct {
	Name  string
	Kind  string // address, address-group, service, tag, ...
	Scope config.Scope
	Value string
	// Subtype is the object's type element, when it has one: "URL List" for a
	// custom URL category, "url" or "ip" for an external list. Two kinds share one
	// container but mean different things, so the type decides how to read them.
	Subtype      string
	Tags         []string
	ShadowedFrom *config.Scope // the scope whose definition this one replaced
}

// Objects returns the objects of one kind visible to the target, with a
// descendant definition shadowing an ancestor's of the same name.
func (t *Target) Objects(kind string) ([]Object, error) {
	return objectsInChain(t.cfg, t.Chain(), kind, nil), nil
}

// ObjectsInScope returns the objects of one kind visible in a scope and its
// ancestors.
func ObjectsInScope(cfg *config.Config, sc config.Scope, kind string) ([]Object, error) {
	chain := chainFor(sc)
	return objectsInChain(cfg, chain, kind, nil), nil
}

// ObjectsAt reads a kind from an explicit container path, for the kinds whose name
// appears in more than one place under a scope.
//
// "user" is the example: the schema puts a user array both at local-user-database/user
// and directly under a vsys, and they are different things. A caller that means one of
// them has to say which.
func ObjectsAt(cfg *config.Config, sc config.Scope, kind string, within []string) ([]Object, error) {
	chain := chainFor(sc)
	return objectsInChain(cfg, chain, kind, within), nil
}

// chainFor returns the scopes a scope inherits from, shared first.
func chainFor(sc config.Scope) []config.Scope {
	chain := []config.Scope{{Sort: config.ScopeShared}}
	if sc.Sort != config.ScopeShared {
		chain = append(chain, sc)
	}
	return chain
}

// objectsInChain walks the chain shared first, so a later definition replaces an
// earlier one and the replacement is recorded.
func objectsInChain(cfg *config.Config, chain []config.Scope, kind string, within []string) []Object {
	// Where a kind sits under a scope comes from the schema: most are direct
	// children, but a custom URL category and every security profile live under
	// profiles/. A caller may name the path instead, for a kind whose name is
	// ambiguous.
	if within == nil {
		within = cfg.KindContainer(kind)
	}
	if within == nil {
		within = []string{kind}
	}
	byName := map[string]Object{}
	var order []string
	for _, sc := range chain {
		for _, o := range readObjects(cfg.Root(), sc, kind, within) {
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

// scopeContainer names where a scope's objects and rulebase live, as a path under
// /config. The config scope holds neither.
func scopeContainer(sc config.Scope) ([]string, bool) {
	switch sc.Sort {
	case config.ScopeShared:
		return []string{"shared"}, true
	case config.ScopeVsys:
		return []string{"devices", "entry", "vsys", "entry"}, true
	default:
		return nil, false
	}
}

// readObjects reads one scope's objects of one kind.
//
// The container path is matched exactly.
func readObjects(root *config.Element, sc config.Scope, kind string, within []string) []Object {
	path, ok := scopeContainer(sc)
	if !ok {
		return nil
	}
	inner := append(append([]string{}, within...), "entry")
	var out []Object
	for _, container := range root.Find(path...) {
		if sc.Name != "" && container.Attr("name") != sc.Name {
			continue
		}
		for _, e := range container.Find(inner...) {
			out = append(out, Object{
				Name:    e.Attr("name"),
				Kind:    kind,
				Scope:   sc,
				Value:   objectValue(e),
				Subtype: objectSubtype(e),
				Tags:    e.Child("tag").Members(),
			})
		}
	}
	return out
}

// objectSubtype reads an object's type, which PAN-OS writes two ways: as text, as
// a custom URL category does with "URL List", or as a single child element, as an
// external list does with <type><url>.
func objectSubtype(e *config.Element) string {
	t := e.Child("type")
	if t == nil {
		return ""
	}
	if v := t.TextOr(""); v != "" {
		return v
	}
	if len(t.Children) == 1 {
		return t.Children[0].Name
	}
	return ""
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
	// A service group spells its membership "members", not "static".
	if m := e.Child("members").Members(); len(m) > 0 {
		return strings.Join(m, ", ")
	}
	// A local user group spells its membership "user".
	if m := e.Child("user").Members(); len(m) > 0 {
		return strings.Join(m, ", ")
	}
	if v := e.Child("dynamic").Child("filter").TextOr(""); v != "" {
		return v
	}
	if m := e.Child("value").Members(); len(m) > 0 {
		return strings.Join(m, ", ")
	}
	// A custom URL category holds its members in list/member.
	if m := e.Child("list").Members(); len(m) > 0 {
		return strings.Join(m, ", ")
	}
	// A service keeps its value one level down, under the protocol it uses.
	// Without this a service object reports an empty value, which it did.
	if p := e.Child("protocol"); p != nil {
		for _, proto := range []string{"tcp", "udp", "sctp"} {
			if port := p.Child(proto).Child("port").TextOr(""); port != "" {
				return proto + "/" + port
			}
		}
	}
	return ""
}
