package index

import (
	"fmt"
	"sync"

	"github.com/okaiser/go-panos-schema/config"
	"github.com/okaiser/go-panos-schema/resolve"
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
}

// Scope returns the scope the index covers.
func (i *Index) Scope() config.Scope { return i.scope }

// Interner returns the index's name table, so a caller can turn names into the
// ids RulesWith takes.
func (i *Index) Interner() *Interner { return i.in }

type cacheKey struct {
	path  string
	scope string
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
// Rule bitmaps key on the device group rather than on (serial, vsys), because
// merged Panorama policy is identical for every firewall in the same device group.
// That bounds the cache to the number of device groups.
func For(cfg *config.Config, sc config.Scope) (*Index, error) {
	key := cacheKey{path: cfg.Path(), scope: sc.String()}

	cacheMu.Lock()
	e, ok := cache[key]
	if !ok {
		e = &cacheEntry{}
		cache[key] = e
	}
	cacheMu.Unlock()

	e.once.Do(func() { e.idx, e.err = build(cfg, sc) })
	if e.err != nil {
		// A failed build is not cached, so a later call can retry.
		cacheMu.Lock()
		delete(cache, key)
		cacheMu.Unlock()
		return nil, e.err
	}
	return e.idx, nil
}

func build(cfg *config.Config, sc config.Scope) (*Index, error) {
	in := NewInterner()

	addrs, err := resolve.ObjectsInScope(cfg, sc, "address")
	if err != nil {
		return nil, err
	}
	groups, err := resolve.ObjectsInScope(cfg, sc, "address-group")
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

	rules, err := rulesForScope(cfg, sc)
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

	byKind := map[string]resolver{}
	for _, r := range []resolver{newAddressResolver(addrs, ri), newURLResolver(cats)} {
		for _, k := range r.kinds() {
			byKind[k] = r
		}
	}

	return &Index{
		scope:     sc,
		in:        in,
		closure:   newClosureIndex(in, groups, addrs),
		refs:      refs,
		rules:     ri,
		resolvers: wireResolvers(cfg.FieldKinds("rulebase/security/rules"), byKind),
	}, nil
}

// rulesForScope returns the effective policy of a scope.
//
// A device group has one, and so does a firewall's vsys: its own rulebase, wrapped
// in whatever pre and post rules were pushed to it. Shared has none of its own,
// because shared rules are a layer of another scope's policy rather than a policy
// in their own right, and a template carries no rules at all.
func rulesForScope(cfg *config.Config, sc config.Scope) ([]resolve.Rule, error) {
	switch sc.Sort {
	case config.ScopeDeviceGroup, config.ScopeVsys:
	default:
		return nil, nil
	}
	tgs, err := resolve.Targets(cfg)
	if err != nil {
		return nil, err
	}
	for _, tg := range tgs {
		if tg.Scope() == sc {
			return tg.Rules(resolve.Security)
		}
	}
	if sc.Sort == config.ScopeVsys {
		return nil, fmt.Errorf("index: no vsys named %q", sc.Name)
	}
	// A device group with no firewall assigned still has a policy. Build a target
	// for it directly.
	h, err := resolve.NewHierarchy(cfg)
	if err != nil {
		return nil, err
	}
	found := false
	for _, r := range h.Roots() {
		if r == sc.Name {
			found = true
		}
	}
	if !found {
		if _, ok := h.ParentOf(sc.Name); !ok {
			return nil, fmt.Errorf("index: no device group named %q", sc.Name)
		}
	}
	return resolve.RulesForDeviceGroup(cfg, sc.Name, resolve.Security)
}

// clearCache drops every built index. Tests and benchmarks use it to measure a
// cold build; nothing else should.
func clearCache() {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	cache = map[cacheKey]*cacheEntry{}
}
