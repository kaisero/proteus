package index

import (
	"net/netip"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/gaissmai/bart"

	"github.com/okaiser/go-panos-schema/resolve"
)

// Field is an indexed rule field.
type Field int

// The rule fields the index covers.
const (
	Source Field = iota
	Destination
	Application
	Service
	FromZone
	ToZone
	Category
	SourceUser
	Tag
)

var fieldNames = map[Field]string{
	Source: "source", Destination: "destination", Application: "application",
	Service: "service", FromZone: "from", ToZone: "to", Category: "category",
	SourceUser: "source-user", Tag: "tag",
}

func (f Field) String() string { return fieldNames[f] }

// rulesIndex maps a field value to the rules naming it. The bit index is the
// rule's position in the effective order, so the lowest set bit is the first
// match: PAN-OS evaluates top to bottom and the first match wins.
type rulesIndex struct {
	rules    []resolve.Rule
	byField  map[Field]map[uint32]*roaring.Bitmap
	byPrefix map[Field]*bart.Table[*roaring.Bitmap]
	disabled *roaring.Bitmap
}

func newRulesIndex(in *Interner, rules []resolve.Rule) *rulesIndex {
	r := &rulesIndex{
		rules:    rules,
		byField:  map[Field]map[uint32]*roaring.Bitmap{},
		byPrefix: map[Field]*bart.Table[*roaring.Bitmap]{},
		disabled: roaring.New(),
	}
	for pos, rule := range rules {
		//nolint:gosec // a rule position cannot reach 2^32; a rulebase is capped far below that
		bit := uint32(pos)
		if rule.Disabled {
			r.disabled.Add(bit)
		}
		for f, name := range fieldNames {
			for _, v := range rule.Fields[name] {
				id := in.ID(v)
				if r.byField[f] == nil {
					r.byField[f] = map[uint32]*roaring.Bitmap{}
				}
				b, ok := r.byField[f][id]
				if !ok {
					b = roaring.New()
					r.byField[f][id] = b
				}
				b.Add(bit)

				// A rule may name an address directly instead of naming an
				// object. Those go in a trie as well, so an address lookup
				// reaches them.
				r.addLiteral(f, v, bit)
			}
		}
	}
	return r
}

// addLiteral indexes a field value that is itself an address or prefix.
//
// A configuration can be written entirely this way: the lab Panorama had seven
// literal addresses and no named objects in source and destination. Without this
// an address lookup finds nothing there.
func (r *rulesIndex) addLiteral(f Field, value string, bit uint32) {
	prefixes := prefixesOf(value)
	if len(prefixes) == 0 {
		return // a name, a keyword, or something else that is not an address
	}
	if r.byPrefix[f] == nil {
		r.byPrefix[f] = new(bart.Table[*roaring.Bitmap])
	}
	for _, p := range prefixes {
		b, ok := r.byPrefix[f].Get(p)
		if !ok {
			b = roaring.New()
			r.byPrefix[f].Insert(p, b)
		}
		b.Add(bit)
	}
}

// RulesWith returns the rules naming any of the ids in a field.
func (i *Index) RulesWith(f Field, ids ...uint32) *roaring.Bitmap {
	out := roaring.New()
	for _, id := range ids {
		if b, ok := i.rules.byField[f][id]; ok {
			out.Or(b)
		}
	}
	return out
}

// RulesWithAddr returns the rules whose field names an address covering addr.
//
// This is the literal path: a rule that names 198.18.0.0/16 as its source matches
// any address inside it, with no object involved.
func (i *Index) RulesWithAddr(f Field, addr netip.Addr) *roaring.Bitmap {
	out := roaring.New()
	t, ok := i.rules.byPrefix[f]
	if !ok {
		return out
	}
	for _, b := range t.Supernets(netip.PrefixFrom(addr, addr.BitLen())) {
		out.Or(b)
	}
	return out
}

// RulesWithPrefix returns the rules whose field names an address overlapping p.
func (i *Index) RulesWithPrefix(f Field, p netip.Prefix) *roaring.Bitmap {
	out := roaring.New()
	t, ok := i.rules.byPrefix[f]
	if !ok {
		return out
	}
	for q, b := range t.All() {
		if q.Overlaps(p) {
			out.Or(b)
		}
	}
	return out
}

// Rules returns the effective policy, in order. The bit index used by RulesWith is
// the position in this slice.
func (i *Index) Rules() []resolve.Rule { return append([]resolve.Rule{}, i.rules.rules...) }

// Disabled returns the disabled rules as a mask, for AndNot.
func (i *Index) Disabled() *roaring.Bitmap { return i.rules.disabled.Clone() }
