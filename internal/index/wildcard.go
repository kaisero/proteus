package index

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
)

// wildcard is an ip-wildcard address object: an IPv4 address and a wildcard mask.
// An address matches when it agrees with the address on every bit the mask
// leaves clear, so the object is no prefix and has no place in the trie.
//
// As observed on fw02, PAN-OS 12.2.3 (L2): 10.88.2.1/0.0.255.0 matched
// 10.88.7.1 and 10.88.200.1, and not 10.88.7.2 or 10.89.7.1, so an address
// matches when addr &^ mask == base &^ mask.
type wildcard struct {
	Name  string
	Scope config.Scope
	Value string // as written, a.b.c.d/m.m.m.m

	base, mask uint32
}

// parseWildcard reads an ip-wildcard object. Only IPv4 has wildcard objects on
// PAN-OS; any other value is not one.
func parseWildcard(o resolve.Object) (wildcard, bool) {
	b, m, ok := strings.Cut(strings.TrimSpace(o.Value), "/")
	if !ok {
		return wildcard{}, false
	}
	base, err1 := netip.ParseAddr(b)
	mask, err2 := netip.ParseAddr(m)
	if err1 != nil || err2 != nil || !base.Is4() || !mask.Is4() {
		return wildcard{}, false
	}
	return wildcard{Name: o.Name, Scope: o.Scope, Value: o.Value, base: u32(base), mask: u32(mask)}, true
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// contains reports whether the object matches the address.
func (w wildcard) contains(a netip.Addr) bool {
	return a.Is4() && u32(a)&^w.mask == w.base&^w.mask
}

// overlaps reports whether the object matches some address of the prefix: the
// two agree on every bit both of them fix.
func (w wildcard) overlaps(p netip.Prefix) bool {
	if !p.Addr().Is4() {
		return false
	}
	fixed := ^uint32(0) << (32 - p.Bits()) &^ w.mask // a shift by 32 gives 0
	return u32(p.Masked().Addr())&fixed == w.base&fixed
}

func (w wildcard) hit() Hit {
	return Hit{Name: w.Name, Kind: "address", Scope: w.Scope, Via: w.Value}
}

// MatchWildcards matches a term, given as its prefixes, against the scope's
// wildcard address objects. They match by mask, so Containing and Overlapping,
// which answer from the trie, do not list them.
//
// One address decides an object: with single set, the term is the address of
// its one prefix, and hits lists the objects that match it. Any other term asks
// about a block of addresses, and an object holds a pattern of them, so it is
// not said to cover or overlap the term (owner decision C1): unresolved lists
// each object that may hold an address of the term, and leaves out one that
// cannot. A caller that compares whole values, not addresses, passes single
// false for one address too.
func (i *Index) MatchWildcards(prefixes []netip.Prefix, single bool) ([]Hit, []Unresolved) {
	return i.addrRes.matchWildcards(prefixes, single)
}

func (r *addressResolver) matchWildcards(prefixes []netip.Prefix, single bool) ([]Hit, []Unresolved) {
	single = single && len(prefixes) == 1
	var hits []Hit
	var un []Unresolved
	for _, w := range r.wildcards {
		if single {
			if w.contains(prefixes[0].Addr()) {
				hits = append(hits, w.hit())
			}
			continue
		}
		for _, p := range prefixes {
			if w.overlaps(p) {
				un = append(un, NewUnresolved(w.Name, "address", reason.New("gap.address-wildcard", fmt.Sprintf(
					"wildcard object %s (%s) matches by mask; a prefix query cannot decide it for %s", w.Name, w.Value, p.Masked()))))
				break
			}
		}
	}
	return hits, un
}
