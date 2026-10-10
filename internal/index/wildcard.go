package index

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// Wildcard is an ip-wildcard address object: an IPv4 address and a wildcard mask.
// An address matches when it agrees with the address on every bit the mask
// leaves clear, so the object is no prefix and has no place in the trie.
//
// As observed on fw02, PAN-OS 12.2.3 (L2): 10.88.2.1/0.0.255.0 matched
// 10.88.7.1 and 10.88.200.1, and not 10.88.7.2 or 10.89.7.1, so an address
// matches when addr &^ mask == base &^ mask.
type Wildcard struct {
	Name  string
	Scope config.Scope
	Value string // as written, a.b.c.d/m.m.m.m

	base, mask uint32
}

// parseWildcard reads an ip-wildcard object. Only IPv4 has wildcard objects on
// PAN-OS; any other value is not one.
func parseWildcard(o resolve.Object) (Wildcard, bool) {
	b, m, ok := strings.Cut(strings.TrimSpace(o.Value), "/")
	if !ok {
		return Wildcard{}, false
	}
	base, err1 := netip.ParseAddr(b)
	mask, err2 := netip.ParseAddr(m)
	if err1 != nil || err2 != nil || !base.Is4() || !mask.Is4() {
		return Wildcard{}, false
	}
	return Wildcard{Name: o.Name, Scope: o.Scope, Value: o.Value, base: u32(base), mask: u32(mask)}, true
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// Contains reports whether the object matches the address.
func (w Wildcard) Contains(a netip.Addr) bool {
	return a.Is4() && u32(a)&^w.mask == w.base&^w.mask
}

// Overlaps reports whether the object matches some address of the prefix: the
// two agree on every bit both of them fix.
func (w Wildcard) Overlaps(p netip.Prefix) bool {
	if !p.Addr().Is4() {
		return false
	}
	fixed := ^uint32(0) << (32 - p.Bits()) &^ w.mask // a shift by 32 gives 0
	return u32(p.Masked().Addr())&fixed == w.base&fixed
}

// Wildcards returns the scope's wildcard address objects. They match by mask, so
// Containing and Overlapping, which answer from the trie, do not list them.
func (i *Index) Wildcards() []Wildcard {
	return slices.Clone(i.addrRes.wildcards)
}
