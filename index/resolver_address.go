package index

import (
	"net/netip"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/go-panos-schema/resolve"
)

// addressResolver answers the address value space: prefixes, ranges and FQDNs.
//
// A prefix trie is the right structure for containment and stays. What changed is
// where it sits: it used to be a field of the index, which made every reachability
// question address-shaped.
type addressResolver struct {
	cidr  *cidrIndex
	fqdn  map[string][]Hit
	rules *rulesIndex
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
		// What is left is an FQDN or a wildcard. The firewall resolves an FQDN at
		// runtime, so the configuration holds no addresses for it, but the name
		// itself is still a value a caller can ask about.
		key := strings.ToLower(v)
		r.fqdn[key] = append(r.fqdn[key], Hit{Name: o.Name, Kind: o.Kind, Scope: o.Scope, Via: v})
	}
	return r
}

func (r *addressResolver) kinds() []string { return []string{"address", "address-group"} }

func (r *addressResolver) resolve(value string, _ Providers) ([]Hit, []Unresolved, bool) {
	if addr, err := netip.ParseAddr(value); err == nil {
		return r.hitsOf(r.covering(addr)), nil, true
	}
	if p, err := netip.ParsePrefix(value); err == nil {
		return r.hitsOf(r.overlapping(p)), nil, true
	}
	if hits, ok := r.fqdn[strings.ToLower(value)]; ok {
		// The object is found by its FQDN, but the addresses behind that name are
		// resolved on the device and are not in the file.
		un := []Unresolved{{
			Value:  value,
			Kind:   "address",
			Reason: "an fqdn object matches this name, but the addresses it resolves to are not in the configuration, so rules reaching those addresses another way are not reported",
		}}
		return hits, un, true
	}
	return nil, nil, false
}

func (r *addressResolver) literalRules(f Field, value string) *roaring.Bitmap {
	if addr, err := netip.ParseAddr(value); err == nil {
		return r.rules.withAddr(f, addr)
	}
	if p, err := netip.ParsePrefix(value); err == nil {
		return r.rules.withPrefix(f, p)
	}
	return roaring.New()
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

func (r *addressResolver) hitsOf(ms []Match) []Hit {
	out := make([]Hit, 0, len(ms))
	for _, m := range ms {
		out = append(out, Hit{Name: m.Name, Kind: "address", Scope: m.Scope, Via: m.Prefix.String()})
	}
	return out
}
