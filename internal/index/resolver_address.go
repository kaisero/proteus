package index

import (
	"net/netip"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
)

// addressResolver answers the address value space: prefixes, ranges, wildcards and
// FQDNs.
//
// A prefix trie is the right structure for containment and stays. What changed is
// where it sits: it used to be a field of the index, which made every reachability
// question address-shaped. A wildcard object is no prefix, so it is kept apart and
// matched by its mask.
type addressResolver struct {
	cidr      *cidrIndex
	wildcards []wildcard
	fqdn      map[string][]Hit
	rules     *rulesIndex
}

func newAddressResolver(objs []resolve.Object, rules *rulesIndex) *addressResolver {
	r := &addressResolver{
		cidr:  newCIDRIndex(objs),
		fqdn:  map[string][]Hit{},
		rules: rules,
	}
	for _, o := range objs {
		v := strings.TrimSpace(o.Value)
		if v == "" || prefixesOf(v) != nil {
			continue
		}
		if o.Wildcard {
			if w, ok := parseWildcard(o); ok {
				r.wildcards = append(r.wildcards, w)
				continue
			}
		}
		// What is left is an FQDN, or a wildcard this build cannot read. The
		// firewall resolves an FQDN at runtime, so the configuration holds no
		// addresses for it, but the name itself is still a value a caller can ask
		// about.
		key := strings.ToLower(v)
		r.fqdn[key] = append(r.fqdn[key], Hit{Name: o.Name, Kind: o.Kind, Scope: o.Scope, Via: v})
	}
	return r
}

func (r *addressResolver) kinds() []string { return []string{"address", "address-group"} }

func (r *addressResolver) resolve(value string, _ Providers) ([]Hit, []Unresolved, bool) {
	if p, ok := addressOrPrefix(value); ok {
		// A /32 is one address, and is asked as the address is.
		single := p.IsSingleIP()
		var hits []Hit
		if single {
			hits = r.hitsOf(r.covering(p.Addr()))
		} else {
			hits = r.hitsOf(r.overlapping(p))
		}
		wild, un := r.matchWildcards([]netip.Prefix{p}, single)
		return append(hits, wild...), un, true
	}
	for _, w := range r.wildcards {
		if strings.EqualFold(w.Value, value) {
			return []Hit{w.hit()}, nil, true
		}
	}
	if hits, ok := r.fqdn[strings.ToLower(value)]; ok {
		// The object is found by its FQDN, but the addresses behind that name are
		// resolved on the device and are not in the file.
		un := []Unresolved{NewUnresolved(value, "address", reason.New("gap.fqdn-no-address",
			"an fqdn object matches this name, but the addresses it resolves to are not in the configuration, so rules reaching those addresses another way are not reported"))}
		return hits, un, true
	}
	return nil, nil, false
}

func (r *addressResolver) literalRules(f Field, value string) *roaring.Bitmap {
	p, ok := addressOrPrefix(value)
	switch {
	case !ok:
		return roaring.New()
	case p.IsSingleIP():
		return r.rules.withAddr(f, p.Addr())
	}
	return r.rules.withPrefix(f, p)
}

// addressOrPrefix reads a value as an address, which is a prefix of one
// address, or as a prefix.
func addressOrPrefix(value string) (netip.Prefix, bool) {
	if addr, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	p, err := netip.ParsePrefix(value)
	return p, err == nil
}

// covering returns every object whose value covers the address, most specific
// first.
func (r *addressResolver) covering(addr netip.Addr) []Match {
	var out []Match
	for _, ms := range r.cidr.table.Supernets(netip.PrefixFrom(addr, addr.BitLen())) {
		out = append(out, ms...)
	}
	return out
}

// overlapping returns every object whose value intersects the prefix.
func (r *addressResolver) overlapping(p netip.Prefix) []Match {
	var out []Match
	for q, ms := range r.cidr.table.All() {
		if q.Overlaps(p) {
			out = append(out, ms...)
		}
	}
	return out
}

// search finds an object by a fragment of its address or FQDN.
func (r *addressResolver) search(substr string) []Hit {
	want := strings.ToLower(substr)
	var out []Hit
	for p, ms := range r.cidr.table.All() {
		if !strings.Contains(strings.ToLower(p.String()), want) {
			continue
		}
		for _, m := range ms {
			out = append(out, Hit{Name: m.Name, Kind: "address", Scope: m.Scope, Via: m.Prefix.String()})
		}
	}
	for _, w := range r.wildcards {
		if strings.Contains(strings.ToLower(w.Value), want) {
			out = append(out, w.hit())
		}
	}
	for value, hits := range r.fqdn {
		if strings.Contains(value, want) {
			out = append(out, hits...)
		}
	}
	return out
}

func (r *addressResolver) hitsOf(ms []Match) []Hit {
	out := make([]Hit, 0, len(ms))
	for _, m := range ms {
		out = append(out, Hit{Name: m.Name, Kind: "address", Scope: m.Scope, Via: m.Prefix.String()})
	}
	return out
}
