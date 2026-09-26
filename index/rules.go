package index

import (
	"github.com/RoaringBitmap/roaring/v2"

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
	disabled *roaring.Bitmap
}

func newRulesIndex(in *Interner, rules []resolve.Rule) *rulesIndex {
	r := &rulesIndex{
		rules:    rules,
		byField:  map[Field]map[uint32]*roaring.Bitmap{},
		disabled: roaring.New(),
	}
	for pos, rule := range rules {
		if rule.Disabled {
			r.disabled.Add(uint32(pos))
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
				b.Add(uint32(pos))
			}
		}
	}
	return r
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

// Rules returns the effective policy, in order. The bit index used by RulesWith is
// the position in this slice.
func (i *Index) Rules() []resolve.Rule { return append([]resolve.Rule{}, i.rules.rules...) }

// Disabled returns the disabled rules as a mask, for AndNot.
func (i *Index) Disabled() *roaring.Bitmap { return i.rules.disabled.Clone() }
