package index

import (
	"net/netip"

	"github.com/RoaringBitmap/roaring/v2"
	"github.com/gaissmai/bart"

	"github.com/okaiser/proteus/internal/resolve"
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

var fieldNames = [...]string{
	Source: "source", Destination: "destination", Application: "application",
	Service: "service", FromZone: "from", ToZone: "to", Category: "category",
	SourceUser: "source-user", Tag: "tag",
}

func (f Field) String() string {
	if f < 0 || int(f) >= len(fieldNames) {
		return ""
	}
	return fieldNames[f]
}

// rulesIndex maps a field value to the rules naming it. The bit index is the
// rule's position in the effective order, so the lowest set bit is the first
// match: PAN-OS evaluates top to bottom and the first match wins.
type rulesIndex struct {
	rules    []resolve.Rule
	byField  map[Field]map[uint32]*roaring.Bitmap
	byPrefix map[Field]*bart.Table[*roaring.Bitmap]
	anyField map[Field]*roaring.Bitmap
	disabled *roaring.Bitmap
}

func newRulesIndex(in *Interner, rules []resolve.Rule) *rulesIndex {
	r := &rulesIndex{
		rules:    rules,
		byField:  map[Field]map[uint32]*roaring.Bitmap{},
		byPrefix: map[Field]*bart.Table[*roaring.Bitmap]{},
		anyField: map[Field]*roaring.Bitmap{},
		disabled: roaring.New(),
	}
	for pos, rule := range rules {
		//nolint:gosec // a rule position cannot reach 2^32; a rulebase is capped far below that
		bit := uint32(pos)
		if rule.Disabled {
			r.disabled.Add(bit)
		}
		for i, name := range fieldNames {
			f := Field(i)
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

				// "any" matches every address. It is not an object, so it never
				// becomes a reference edge, but a first-match answer is wrong
				// without it.
				if v == "any" {
					b, ok := r.anyField[f]
					if !ok {
						b = roaring.New()
						r.anyField[f] = b
					}
					b.Add(bit)
				}
			}
		}
	}
	return r
}

// addLiteral indexes a field value that is itself an address or prefix.
//
// A configuration can be written entirely this way, with literal addresses and
// no named objects in source and destination. Without this
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
	return i.rules.withAddr(f, addr)
}

func (r *rulesIndex) withAddr(f Field, addr netip.Addr) *roaring.Bitmap {
	out := roaring.New()
	t, ok := r.byPrefix[f]
	if !ok {
		return out
	}
	for _, b := range t.Supernets(netip.PrefixFrom(addr, addr.BitLen())) {
		out.Or(b)
	}
	return out
}

// RulesWithAny returns the rules whose field is "any", which matches every
// address.
//
// A first-match answer needs these. Checked against a live firewall: for
// 198.18.0.5 to 198.18.1.5 the device reported ztnac-to-lab, rule 3, whose source
// is any; matching on addresses alone reported rule 8 instead. An any-rule is
// usually earlier in a rulebase than a specific one, so leaving it out does not
// merely lose candidates, it returns the wrong winner.
func (i *Index) RulesWithAny(f Field) *roaring.Bitmap {
	if b, ok := i.rules.anyField[f]; ok {
		return b.Clone()
	}
	return roaring.New()
}

// RulesWithPrefix returns the rules whose field names an address overlapping p.
func (i *Index) RulesWithPrefix(f Field, p netip.Prefix) *roaring.Bitmap {
	return i.rules.withPrefix(f, p)
}

func (r *rulesIndex) withPrefix(f Field, p netip.Prefix) *roaring.Bitmap {
	out := roaring.New()
	t, ok := r.byPrefix[f]
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
