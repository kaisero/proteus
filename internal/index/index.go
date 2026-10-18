package index

import (
	"errors"
	"fmt"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// Index is the lookup structures for one scope. It is immutable once built, so
// concurrent readers need no lock.
type Index struct {
	scope config.Scope
	in    *Interner
	// families holds one membership closure per group kind, by kind: an
	// address group and a service group may share a name.
	families      []*groupFamily
	fieldFamilies map[Field][]*groupFamily
	refs          *refsIndex
	rules         *rulesIndex
	resolvers     map[Field][]resolver
	profiles      *profileIndex
	// addrRes is the address resolver, kept directly because address containment is
	// also exposed on its own and every scope has one.
	addrRes *addressResolver
	// opaque records the rules naming addresses the configuration does not hold.
	opaque *opaqueIndex
}

// Scope returns the scope the index covers.
func (i *Index) Scope() config.Scope { return i.scope }

// Interner returns the index's name table, so a caller can turn names into the
// ids RulesWith takes.
func (i *Index) Interner() *Interner { return i.in }

// Build builds the index of one scope's rulebase from a configuration and the
// edges read from it. The security index answers every field; the NAT and PBF
// indexes answer which of their rules a value can reach with the same matching:
// groups, negation left to the caller, FQDNs and lists alike. Only
// the address fields are meaningful for those rulebases; zones and interfaces are
// the caller's to compare.
//
// The package keeps nothing: the caller owns the index and decides how long it
// lives. Pass the same edges to every index of one configuration, so the file is
// read once (see Edges).
func Build(cfg *config.Config, edges *Edges, sc config.Scope, rb resolve.Rulebase) (*Index, error) {
	if edges == nil || edges.cfg != cfg {
		return nil, errors.New("index: the edges were not read from this configuration")
	}
	return build(cfg, edges.list, sc, rb)
}

// New reads a configuration's edges and builds one index, for a caller that needs
// a single index of it. A caller that needs more uses a Set or Build.
func New(cfg *config.Config, sc config.Scope, rb resolve.Rulebase) (*Index, error) {
	edges, err := ReadEdges(cfg)
	if err != nil {
		return nil, err
	}
	return build(cfg, edges.list, sc, rb)
}

func build(cfg *config.Config, edges edgeList, sc config.Scope, rb resolve.Rulebase) (*Index, error) {
	in := NewInterner()

	// A service or address name resolves by scope first, kind second: a vsys
	// service hides a shared service group of its name, a vsys address group
	// a shared address, and the other way round (L9, L10).
	addrKinds := resolve.ObjectsOfKindsInScope(cfg, sc, "address", addressGroups)
	addrs, groups := addrKinds["address"], addrKinds[addressGroups]
	svcKinds := resolve.ObjectsOfKindsInScope(cfg, sc, "service", "service-group")
	svcs, svcGroups := svcKinds["service"], svcKinds["service-group"]
	appGroups := resolve.ObjectsInScope(cfg, sc, "application-group")
	// Intern the addresses first, so their ids are dense and stable.
	for _, o := range addrs {
		in.ID(o.Name)
	}

	refs := newRefsIndex(in, edges, sc)

	rules, err := rulesForScope(cfg, sc, rb)
	if err != nil {
		return nil, err
	}

	ri := newRulesIndex(in, rules)

	// Which resolvers a field needs comes from the schema, not from a list here:
	// the schema declares the object kinds each field accepts, and a kind maps to
	// the resolver that can answer for it. A kind with no resolver is not silently
	// dropped; see opaque rule-field values.
	cats := resolve.ObjectsInScope(cfg, sc, "custom-url-category")
	// "user" is ambiguous in the schema, so the container is named rather than
	// guessed: a vsys has both a local user database and a separate user array.
	localUsers := resolve.ObjectsAt(cfg, sc, "user", []string{"local-user-database", "user"})
	userGroups := resolve.ObjectsInScope(cfg, sc, "user-group")
	dynUsers := resolve.ObjectsInScope(cfg, sc, "dynamic-user-group")

	apps := resolve.Applications(cfg, sc)
	appFilters := resolve.ApplicationFilters(cfg, sc)
	appTags := resolve.ApplicationTags(cfg, sc)
	appContainers := resolve.ObjectsInScope(cfg, sc, "application-container")

	zones := resolve.ZonesInScope(cfg, sc)
	ifAddrs := resolve.InterfaceAddresses(cfg)
	routes := resolve.StaticRoutes(cfg)

	addrRes := newAddressResolver(addrs, ri)

	byKind := map[string]resolver{}
	for _, r := range []resolver{
		addrRes,
		newURLResolver(cats),
		newServiceResolver(svcs, ri),
		newUserResolver(sc, localUsers, userGroups, dynUsers, rules),
		newZoneResolver(sc, zones, ifAddrs, routes, resolve.DynamicRoutingProtocols(cfg)),
		newAppResolver(apps, appFilters, appTags, appContainers),
	} {
		for _, k := range r.kinds() {
			byKind[k] = r
		}
	}

	lists := resolve.ObjectsInScope(cfg, sc, "external-list")
	lists = append(lists, resolve.ObjectsInScope(cfg, sc, "ip-block-list-v2")...)
	opaque := newOpaqueIndex(rules, opaqueObjects{
		addrs: addrs, groups: groups, lists: lists, regions: resolve.ObjectsInScope(cfg, sc, "region"),
	})

	profs := resolve.URLFilteringProfilesInScope(cfg, sc)
	pgroups := resolve.ProfileGroupsInScope(cfg, sc)

	families := []*groupFamily{
		{kind: addressGroups, closure: newClosureIndex(in, groups, addrs)},
		{kind: "application-group", closure: newClosureIndex(in, appGroups, nil)},
		{kind: "service-group", closure: newClosureIndex(in, svcGroups, nil)},
	}
	for _, fam := range families {
		fam.members = memberKinds(cfg, fam.kind)
	}
	fieldKinds := cfg.FieldKinds("rulebase/" + rb.String() + "/rules")

	return &Index{
		scope:         sc,
		in:            in,
		families:      families,
		fieldFamilies: fieldFamilies(fieldKinds, families),
		refs:          refs,
		rules:         ri,
		resolvers:     wireResolvers(fieldKinds, byKind),
		profiles:      newProfileIndex(rules, profs, pgroups),
		addrRes:       addrRes,
		opaque:        opaque,
	}, nil
}

// rulesForScope returns the policy of a scope. A vsys has one: its own rulebase,
// wrapped in whatever shared pre and post rules were pushed to it. Shared has
// none of its own, because shared rules are a layer of a vsys's policy rather than
// a policy in their own right.
func rulesForScope(cfg *config.Config, sc config.Scope, rb resolve.Rulebase) ([]resolve.Rule, error) {
	if sc.Sort != config.ScopeVsys {
		return nil, nil
	}
	tgs := resolve.Targets(cfg)
	for _, tg := range tgs {
		if tg.Scope() == sc {
			return tg.Rules(rb), nil
		}
	}
	return nil, fmt.Errorf("index: no vsys named %q", sc.Name)
}
