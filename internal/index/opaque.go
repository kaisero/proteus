package index

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
)

// The reasons a rule's address field value has addresses the configuration does
// not hold.
const (
	opaqueExternalList = "external list"
	opaqueRegion       = "region"
	opaqueRuntime      = "members registered at runtime are not known"
)

// opaqueIndex records, per address field, the rules that name an external list, a
// region or a dynamic address group, directly or through a static group.
//
// None of the three can be matched from a configuration. An external list is
// fetched by the device, a region is the device's geolocation database, and a
// dynamic group also holds members registered at runtime through User-ID or VM
// monitoring (resolve.Members.Note). An address lookup reaches a rule naming one
// only through "any", or, for a dynamic group, through the members the
// configuration tags; without this record such a rule silently vanishes.
type opaqueIndex struct {
	rules   map[Field]*roaring.Bitmap
	reasons map[Field]map[uint32][]reason.Reason
}

// predefinedRegion matches the name of a predefined region: a country, by its
// two-letter ISO 3166 code. Source: PAN-OS admin guide, "Objects > Regions" and
// "Use Geolocation in Policy": predefined regions are countries, named by code.
var predefinedRegion = regexp.MustCompile(`^[A-Z][A-Z0-9]$`)

// predefinedListPrefix starts the name of a built-in external dynamic list, such as
// panw-highrisk-ip-list. Source: PAN-OS admin guide, "Built-in External Dynamic
// Lists".
const predefinedListPrefix = "panw-"

// opaqueObjects are the objects of a scope that decide whether a value is opaque.
type opaqueObjects struct {
	addrs, groups, lists, regions []resolve.Object
}

func newOpaqueIndex(rules []resolve.Rule, objs opaqueObjects) *opaqueIndex {
	addr := map[string]bool{}
	for _, o := range objs.addrs {
		addr[o.Name] = true
	}
	list := map[string]bool{}
	for _, o := range objs.lists {
		list[o.Name] = true
	}
	region := map[string]bool{}
	for _, o := range objs.regions {
		region[o.Name] = true
	}
	group := map[string]resolve.Object{}
	for _, g := range objs.groups {
		group[g.Name] = g
	}

	// classify classifies one value, following static groups; a cycle stops. The
	// zero reason means the value is not opaque.
	var classify func(v string, onPath map[string]bool) reason.Reason
	classify = func(v string, onPath map[string]bool) reason.Reason {
		if g, ok := group[v]; ok {
			if strings.HasPrefix(g.Value, "'") {
				return reason.New("doubt.dynamic-group", fmt.Sprintf("%s (%s)", opaqueRuntime, v))
			}
			if onPath[v] {
				return reason.Reason{}
			}
			onPath[v] = true
			defer delete(onPath, v)
			for m := range strings.SplitSeq(g.Value, ", ") {
				if r := classify(strings.TrimSpace(m), onPath); r.Text != "" {
					r.Text = strings.TrimSuffix(r.Text, ")") + ", in group " + v + ")"
					return r
				}
			}
			return reason.Reason{}
		}
		switch {
		case v == "any" || addr[v] || len(prefixesOf(v)) > 0:
			return reason.Reason{}
		case list[v] || strings.HasPrefix(v, predefinedListPrefix):
			return reason.New("doubt.edl", fmt.Sprintf("%s (%s)", opaqueExternalList, v))
		case region[v] || predefinedRegion.MatchString(v):
			return reason.New("doubt.region", fmt.Sprintf("%s (%s)", opaqueRegion, v))
		}
		return reason.Reason{}
	}

	o := &opaqueIndex{rules: map[Field]*roaring.Bitmap{}, reasons: map[Field]map[uint32][]reason.Reason{}}
	for _, f := range []Field{Source, Destination} {
		b, why := roaring.New(), map[uint32][]reason.Reason{}
		for pos, r := range rules {
			var rs []reason.Reason
			for _, v := range r.Fields[f.String()] {
				if c := classify(v, map[string]bool{}); c.Text != "" {
					rs = append(rs, c)
				}
			}
			if len(rs) > 0 {
				//nolint:gosec // a rule position cannot reach 2^32; a rulebase is capped far below that
				bit := uint32(pos)
				b.Add(bit)
				why[bit] = rs
			}
		}
		o.rules[f], o.reasons[f] = b, why
	}
	return o
}

// Opaque returns the rules whose field names an external list, a region or a
// dynamic address group, directly or through a static group, and why, by rule
// position: one reason per value the rule names, in field order. An address
// lookup cannot say whether such a rule matches: the caller keeps it as a
// candidate and says so. Only the address fields have any.
func (v *View) Opaque(f Field) (*roaring.Bitmap, map[uint32][]reason.Reason) {
	o := v.idx.opaque
	b, ok := o.rules[f]
	if !ok {
		return roaring.New(), nil
	}
	why := make(map[uint32][]reason.Reason, len(o.reasons[f]))
	for k, r := range o.reasons[f] {
		why[k] = slices.Clone(r)
	}
	return b.Clone(), why
}
