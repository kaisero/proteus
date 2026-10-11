package resolve

import (
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/config"
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
	Description  string
	ShadowedFrom *config.Scope // the scope whose definition this one replaced
	// Dynamic is set for an address group with a dynamic element. Its Value is
	// then the tag filter, not a member list.
	Dynamic bool
	// Wildcard is set for an address with an ip-wildcard element. Its Value is
	// then an address and a wildcard mask, a.b.c.d/m.m.m.m, not a prefix.
	Wildcard bool
}

// Objects returns the objects of one kind visible to the target, with a
// descendant definition shadowing an ancestor's of the same name.
func (t *Target) Objects(kind string) []Object {
	return objectsInChain(t.cfg, t.Chain(), kind, nil)
}

// ObjectsInScope returns the objects of one kind visible in a scope and its
// ancestors.
func ObjectsInScope(cfg *config.Config, sc config.Scope, kind string) []Object {
	chain := chainFor(sc)
	return objectsInChain(cfg, chain, kind, nil)
}

// ObjectsOfKindsInScope returns, by kind, the objects of several kinds that one
// name in a field can mean, visible in a scope and its ancestors. A name resolves
// by scope first and kind second: only the nearest scope that defines the name in
// any of the kinds counts, the vsys before shared before the predefined objects,
// and a namesake in a farther scope is hidden, whatever its kind. Each kind keeps
// the order ObjectsInScope gives it.
//
// As observed on fw02, PAN-OS 12.2.3 (L9): a vsys service group hides the
// predefined service of its name, and a vsys service hides a shared service group
// of its name, in NAT and security rules alike.
func ObjectsOfKindsInScope(cfg *config.Config, sc config.Scope, kinds ...string) map[string][]Object {
	chain := append([]config.Scope{predefinedScope}, chainFor(sc)...)
	nearness := func(o Object) int { return slices.Index(chain, o.Scope) }
	out := make(map[string][]Object, len(kinds))
	nearest := map[string]int{}
	for _, kind := range kinds {
		objs := ObjectsInScope(cfg, sc, kind)
		out[kind] = objs
		for _, o := range objs {
			nearest[o.Name] = max(nearest[o.Name], nearness(o))
		}
	}
	for kind, objs := range out {
		out[kind] = slices.DeleteFunc(objs, func(o Object) bool { return nearness(o) < nearest[o.Name] })
	}
	return out
}

// namesakes are the kinds whose names resolve together (L9, L10).
var namesakes = map[string][]string{
	"service": {"service", "service-group"}, "service-group": {"service", "service-group"},
	"address": {"address", "address-group"}, "address-group": {"address", "address-group"},
}

// Namesakes returns the kinds a name of this kind resolves together with, by
// scope first and kind second, the kind among them: a vsys service hides a shared
// service group of its name, a vsys address group a shared address, and the other
// way round (as observed on fw02, PAN-OS 12.2.3, L9 and L10). A kind with no
// namesake kind comes back alone.
func Namesakes(kind string) []string {
	if ks, ok := namesakes[kind]; ok {
		return ks
	}
	return []string{kind}
}

// ObjectsAt reads a kind from an explicit container path, for the kinds whose name
// appears in more than one place under a scope.
//
// "user" is the example: the schema puts a user array both at local-user-database/user
// and directly under a vsys, and they are different things. A caller that means one of
// them has to say which.
func ObjectsAt(cfg *config.Config, sc config.Scope, kind string, within []string) []Object {
	chain := chainFor(sc)
	return objectsInChain(cfg, chain, kind, within)
}

// chainFor returns the scopes a scope inherits from, shared first.
func chainFor(sc config.Scope) []config.Scope {
	chain := []config.Scope{{Sort: config.ScopeShared}}
	if sc.Sort != config.ScopeShared {
		chain = append(chain, sc)
	}
	return chain
}

// predefinedScope is the scope of what the device itself defines. Every chain
// starts there: a configured object of the same name hides it. It is read for
// every kind, but only services are stored there today.
var predefinedScope = config.Scope{Sort: config.ScopePredefined}

// objectsInChain walks the chain shared first, so a later definition replaces an
// earlier one and the replacement is recorded.
//
// The device's predefined services come before shared, when the configuration
// came with them. As observed on fw02, PAN-OS 12.2.3: the device defines
// service-http and service-https (L4), and a configured service of the same name
// wins, the vsys's over shared's over the predefined one (L7).
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
	for _, sc := range append([]config.Scope{predefinedScope}, chain...) {
		for _, o := range readObjects(cfg, sc, kind, within) {
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

// scopeElements returns the elements a scope's objects sit under: the predefined
// element, or the containers scopeContainer names, matched by the scope's name.
func scopeElements(cfg *config.Config, sc config.Scope) []*config.Element {
	if sc.Sort == config.ScopePredefined {
		if p := cfg.Predefined(); p != nil {
			return []*config.Element{p}
		}
		return nil
	}
	path, ok := scopeContainer(sc)
	if !ok {
		return nil
	}
	var out []*config.Element
	for _, container := range cfg.Root().Find(path...) {
		if sc.Name == "" || container.Attr("name") == sc.Name {
			out = append(out, container)
		}
	}
	return out
}

// readObjects reads one scope's objects of one kind.
//
// The container path is matched exactly.
func readObjects(cfg *config.Config, sc config.Scope, kind string, within []string) []Object {
	inner := append(append([]string{}, within...), "entry")
	var out []Object
	for _, container := range scopeElements(cfg, sc) {
		for _, e := range container.Find(inner...) {
			out = append(out, Object{
				Name:    e.Attr("name"),
				Kind:    kind,
				Scope:   sc,
				Value:   objectValue(e),
				Subtype: objectSubtype(e),
				Tags:    e.Child("tag").Members(),
				// The element says a group is dynamic, not its filter text. As
				// observed on fw02, PAN-OS 12.2.3: a filter may start with "(";
				// "not" is refused (L1, L1b).
				Dynamic:  kind == "address-group" && e.Child("dynamic") != nil,
				Wildcard: kind == "address" && e.Child("ip-wildcard") != nil,

				Description: e.Child("description").TextOr(""),
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
