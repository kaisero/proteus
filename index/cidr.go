package index

import (
	"math/big"
	"net/netip"
	"strings"

	"github.com/gaissmai/bart"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/resolve"
)

// Match is one object whose value covers or overlaps an address.
type Match struct {
	Name   string
	Prefix netip.Prefix
	Scope  config.Scope
}

// cidrIndex answers address containment. bart is a routing-table trie, so
// longest-prefix match is the operation it is built for.
type cidrIndex struct {
	table *bart.Table[[]Match]
}

func newCIDRIndex(objs []resolve.Object) *cidrIndex {
	c := &cidrIndex{table: new(bart.Table[[]Match])}
	for _, o := range objs {
		for _, p := range prefixesOf(o.Value) {
			m := Match{Name: o.Name, Prefix: p, Scope: o.Scope}
			if existing, ok := c.table.Get(p); ok {
				c.table.Insert(p, append(existing, m))
				continue
			}
			c.table.Insert(p, []Match{m})
		}
	}
	return c
}

// prefixesOf turns an address object's value into prefixes. An fqdn yields none,
// because the firewall resolves it at runtime and the configuration holds no
// addresses for it.
func prefixesOf(value string) []netip.Prefix {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	if lo, hi, isRange := strings.Cut(v, "-"); isRange && !strings.Contains(v, "/") {
		a, err1 := netip.ParseAddr(strings.TrimSpace(lo))
		b, err2 := netip.ParseAddr(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil {
			return nil
		}
		return rangePrefixes(a, b)
	}
	if p, err := netip.ParsePrefix(v); err == nil {
		return []netip.Prefix{p.Masked()}
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}
	}
	return nil
}

// rangePrefixes covers an inclusive address range with the fewest prefixes.
//
// PAN-OS writes an ip-range as two addresses, and a trie indexes prefixes, so the
// range has to be decomposed. The arithmetic uses big.Int because an IPv6 address
// does not fit in a uint64.
func rangePrefixes(lo, hi netip.Addr) []netip.Prefix {
	if !lo.IsValid() || !hi.IsValid() || lo.BitLen() != hi.BitLen() || hi.Less(lo) {
		return nil
	}
	bits := lo.BitLen()
	cur := addrToInt(lo)
	end := addrToInt(hi)
	one := big.NewInt(1)

	var out []netip.Prefix
	for cur.Cmp(end) <= 0 {
		// The largest block starting at cur is limited by its alignment and by
		// how much of the range is left.
		size := bits - trailingZeros(cur, bits)
		for {
			blockLen := new(big.Int).Lsh(one, uint(bits-size))
			last := new(big.Int).Add(cur, new(big.Int).Sub(blockLen, one))
			if last.Cmp(end) <= 0 {
				break
			}
			size++
		}
		p := netip.PrefixFrom(intToAddr(cur, bits), size)
		out = append(out, p)

		blockLen := new(big.Int).Lsh(one, uint(bits-size))
		cur = new(big.Int).Add(cur, blockLen)
	}
	return out
}

func addrToInt(a netip.Addr) *big.Int {
	if a.Is4() {
		b := a.As4()
		return new(big.Int).SetBytes(b[:])
	}
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
}

func intToAddr(n *big.Int, bits int) netip.Addr {
	size := bits / 8
	buf := make([]byte, size)
	n.FillBytes(buf)
	a, _ := netip.AddrFromSlice(buf)
	return a
}

// trailingZeros counts the alignment of an address, i.e. how large a block may
// start there.
func trailingZeros(n *big.Int, bits int) int {
	if n.Sign() == 0 {
		return bits
	}
	for i := 0; i < bits; i++ {
		if n.Bit(i) == 1 {
			return i
		}
	}
	return bits
}

// lastAddr returns the highest address in a prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	bits := p.Addr().BitLen()
	n := addrToInt(p.Masked().Addr())
	blockLen := new(big.Int).Lsh(big.NewInt(1), uint(bits-p.Bits()))
	last := new(big.Int).Add(n, new(big.Int).Sub(blockLen, big.NewInt(1)))
	return intToAddr(last, bits)
}

// Containing returns every object whose value covers the address, most specific
// first.
func (i *Index) Containing(addr netip.Addr) []Match {
	return i.addrRes.covering(addr)
}

// Overlapping returns every object whose value intersects the prefix.
func (i *Index) Overlapping(p netip.Prefix) []Match {
	return i.addrRes.overlapping(p)
}
