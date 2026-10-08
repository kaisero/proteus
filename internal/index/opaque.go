package index

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

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
	reasons map[Field]map[uint32]string
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

	// reason classifies one value, following static groups; a cycle stops.
	var reason func(v string, onPath map[string]bool) string
	reason = func(v string, onPath map[string]bool) string {
		if g, ok := group[v]; ok {
			if strings.HasPrefix(g.Value, "'") {
				return fmt.Sprintf("%s (%s)", opaqueRuntime, v)
			}
			if onPath[v] {
				return ""
			}
			onPath[v] = true
			defer delete(onPath, v)
			for m := range strings.SplitSeq(g.Value, ", ") {
				if r := reason(strings.TrimSpace(m), onPath); r != "" {
					return strings.TrimSuffix(r, ")") + ", in group " + v + ")"
				}
			}
			return ""
		}
		switch {
		case v == "any" || addr[v] || len(prefixesOf(v)) > 0:
			return ""
		case list[v] || strings.HasPrefix(v, predefinedListPrefix):
			return fmt.Sprintf("%s (%s)", opaqueExternalList, v)
		case region[v] || predefinedRegion.MatchString(v):
			return fmt.Sprintf("%s (%s)", opaqueRegion, v)
		}
		return ""
	}

	o := &opaqueIndex{rules: map[Field]*roaring.Bitmap{}, reasons: map[Field]map[uint32]string{}}
	for _, f := range []Field{Source, Destination} {
		b, why := roaring.New(), map[uint32]string{}
		for pos, r := range rules {
			var rs []string
			for _, v := range r.Fields[f.String()] {
				if s := reason(v, map[string]bool{}); s != "" {
					rs = append(rs, s)
				}
			}
			if len(rs) > 0 {
				//nolint:gosec // a rule position cannot reach 2^32; a rulebase is capped far below that
				bit := uint32(pos)
				b.Add(bit)
				why[bit] = strings.Join(rs, "; ")
			}
		}
		o.rules[f], o.reasons[f] = b, why
	}
	return o
}

// Opaque returns the rules whose field names an external list, a region or a
// dynamic address group, directly or through a static group, and why, by rule
// position. An address lookup cannot say whether such a rule matches: the caller
// keeps it as a candidate and says so. Only the address fields have any.
func (v *View) Opaque(f Field) (*roaring.Bitmap, map[uint32]string) {
	o := v.idx.opaque
	b, ok := o.rules[f]
	if !ok {
		return roaring.New(), nil
	}
	why := make(map[uint32]string, len(o.reasons[f]))
	for k, r := range o.reasons[f] {
		why[k] = r
	}
	return b.Clone(), why
}
