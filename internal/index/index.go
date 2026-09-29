package index

import (
	"fmt"
	"sync"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// Index is the lookup structures for one scope. It is immutable once built, so
// concurrent readers need no lock.
type Index struct {
	scope     config.Scope
	in        *Interner
	closure   *closureIndex
	refs      *refsIndex
	rules     *rulesIndex
	resolvers map[Field][]resolver
	profiles  *profileIndex
	// addrRes is the address resolver, kept directly because address containment is
	// also exposed on its own and every scope has one.
	addrRes *addressResolver
	// gap is the configuration's version gap, empty when its schema matched.
	gap string
}

// Scope returns the scope the index covers.
func (i *Index) Scope() config.Scope { return i.scope }

// VersionGap returns the configuration's version gap, empty when it was read with
// its own version's schema. Answers without a report, such as Refs and Containing,
// are subject to it too; this is how a caller of those finds out.
func (i *Index) VersionGap() string { return i.gap }

// Interner returns the index's name table, so a caller can turn names into the
// ids RulesWith takes.
func (i *Index) Interner() *Interner { return i.in }

type cacheKey struct {
	path  string
	scope string
	rb    resolve.Rulebase
}

type cacheEntry struct {
	once sync.Once
	idx  *Index
	err  error
}

var (
	cacheMu sync.Mutex
	cache   = map[cacheKey]*cacheEntry{}
)

// For returns the index for a scope, building it on first call and returning the
// cached instance afterwards.
//
// Rule bitmaps key on the vsys: each vsys has its own rulebase, so the cache is
// bounded by the number of vsys.
func For(cfg *config.Config, sc config.Scope) (*Index, error) {
	return ForRulebase(cfg, sc, resolve.Security)
}

// ForRulebase returns the index of a scope's NAT or PBF rules, answering which of
// them a value can reach with the same matching the security index uses: groups,
// negation left to the caller, FQDNs, lists and version gaps alike. Only the
// address fields are meaningful for these rulebases; zones and interfaces are the
// caller's to compare.
func ForRulebase(cfg *config.Config, sc config.Scope, rb resolve.Rulebase) (*Index, error) {
	key := cacheKey{path: cfg.Path(), scope: sc.String(), rb: rb}

	cacheMu.Lock()
	e, ok := cache[key]
	if !ok {
		e = &cacheEntry{}
		cache[key] = e
	}
	cacheMu.Unlock()

	e.once.Do(func() { e.idx, e.err = build(cfg, sc, rb) })
	if e.err != nil {
		// A failed build is not cached, so a later call can retry.
		cacheMu.Lock()
		delete(cache, key)
		cacheMu.Unlock()
		return nil, e.err
	}
	return e.idx, nil
}

func build(cfg *config.Config, sc config.Scope, rb resolve.Rulebase) (*Index, error) {
	in := NewInterner()

	addrs, err := resolve.ObjectsInScope(cfg, sc, "address")
	if err != nil {
		return nil, err
	}
	groups, err := resolve.ObjectsInScope(cfg, sc, "address-group")
	if err != nil {
		return nil, err
	}
	svcGroups, err := resolve.ObjectsInScope(cfg, sc, "service-group")
	if err != nil {
		return nil, err
	}
	appGroups, err := resolve.ObjectsInScope(cfg, sc, "application-group")
	if err != nil {
		return nil, err
	}
	// Intern the addresses first, so their ids are dense and stable.
	for _, o := range addrs {
		in.ID(o.Name)
	}

	refs, err := newRefsIndex(in, cfg, sc)
	if err != nil {
		return nil, err
	}

	rules, err := rulesForScope(cfg, sc, rb)
	if err != nil {
		return nil, err
	}

	ri := newRulesIndex(in, rules)

	// Which resolvers a field needs comes from the schema, not from a list here:
	// the schema declares the object kinds each field accepts, and a kind maps to
	// the resolver that can answer for it. A kind with no resolver is not silently
	// dropped; see opaque rule-field values.
	cats, err := resolve.ObjectsInScope(cfg, sc, "custom-url-category")
	if err != nil {
		return nil, err
	}
	svcs, err := resolve.ObjectsInScope(cfg, sc, "service")
	if err != nil {
		return nil, err
	}
	// "user" is ambiguous in the schema, so the container is named rather than
	// guessed: a vsys has both a local user database and a separate user array.
	localUsers, err := resolve.ObjectsAt(cfg, sc, "user", []string{"local-user-database", "user"})
	if err != nil {
		return nil, err
	}
	userGroups, err := resolve.ObjectsInScope(cfg, sc, "user-group")
	if err != nil {
		return nil, err
	}
	dynUsers, err := resolve.ObjectsInScope(cfg, sc, "dynamic-user-group")
	if err != nil {
		return nil, err
	}

	apps, err := resolve.ObjectsInScope(cfg, sc, "application")
	if err != nil {
		return nil, err
	}
	appFilters, err := resolve.ObjectsInScope(cfg, sc, "application-filter")
	if err != nil {
		return nil, err
	}
	appContainers, err := resolve.ObjectsInScope(cfg, sc, "application-container")
	if err != nil {
		return nil, err
	}

	zones, err := resolve.ZonesInScope(cfg, sc)
	if err != nil {
		return nil, err
	}
	ifAddrs, err := resolve.InterfaceAddresses(cfg)
	if err != nil {
		return nil, err
	}
	routes, err := resolve.StaticRoutes(cfg)
	if err != nil {
		return nil, err
	}

	addrRes := newAddressResolver(addrs, ri)

	byKind := map[string]resolver{}
	for _, r := range []resolver{
		addrRes,
		newURLResolver(cats),
		newServiceResolver(svcs, ri),
		newUserResolver(localUsers, userGroups, dynUsers),
		newZoneResolver(sc, zones, ifAddrs, routes, resolve.DynamicRoutingProtocols(cfg)),
		newAppResolver(apps, appFilters, appContainers),
	} {
		for _, k := range r.kinds() {
			byKind[k] = r
		}
	}

	profs, err := resolve.URLFilteringProfilesInScope(cfg, sc)
	if err != nil {
		return nil, err
	}
	pgroups, err := resolve.ProfileGroupsInScope(cfg, sc)
	if err != nil {
		return nil, err
	}

	return &Index{
		scope:     sc,
		in:        in,
		closure:   newClosureIndex(in, groups, addrs, svcGroups, appGroups),
		refs:      refs,
		rules:     ri,
		resolvers: wireResolvers(cfg.FieldKinds("rulebase/"+rb.String()+"/rules"), byKind),
		profiles:  newProfileIndex(rules, profs, pgroups),
		addrRes:   addrRes,
		gap:       cfg.VersionGap(),
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
	tgs, err := resolve.Targets(cfg)
	if err != nil {
		return nil, err
	}
	for _, tg := range tgs {
		if tg.Scope() == sc {
			return tg.Rules(rb)
		}
	}
	return nil, fmt.Errorf("index: no vsys named %q", sc.Name)
}

// clearCache drops every built index. Tests and benchmarks use it to measure a
// cold build; nothing else should.
func clearCache() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cache = map[cacheKey]*cacheEntry{}
}
