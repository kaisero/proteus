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
// monitoring, which are not in a configuration file. An address lookup reaches a
// rule naming one only through "any", or, for a dynamic group, through the
// members the configuration tags; without this record such a rule silently
// vanishes.
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
	c := newClassifier(objs)
	o := &opaqueIndex{rules: map[Field]*roaring.Bitmap{}, reasons: map[Field]map[uint32][]reason.Reason{}}
	for _, f := range []Field{Source, Destination} {
		b, why := roaring.New(), map[uint32][]reason.Reason{}
		for pos, r := range rules {
			var rs []reason.Reason
			for _, v := range r.Fields[f.String()] {
				if why := c.classify(v); why.Text != "" {
					rs = append(rs, why)
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

// classifier decides whether a value is opaque, following static groups. It
// decides every static group once, when it is built.
type classifier struct {
	addr, list, region map[string]bool
	group              map[string]resolve.Object

	// via holds, for each static group, the member through which it is
	// opaque, or "" when it is not.
	via map[string]string
	// reads counts the members read while deciding, so a test can bound the
	// work.
	reads int
}

func newClassifier(objs opaqueObjects) *classifier {
	c := &classifier{
		addr:   map[string]bool{},
		list:   map[string]bool{},
		region: map[string]bool{},
		group:  map[string]resolve.Object{},
		via:    map[string]string{},
	}
	for _, o := range objs.addrs {
		c.addr[o.Name] = true
	}
	for _, o := range objs.lists {
		c.list[o.Name] = true
	}
	for _, o := range objs.regions {
		c.region[o.Name] = true
	}
	for _, g := range objs.groups {
		c.group[g.Name] = g
	}
	c.decide()
	return c
}

// decide sets via for every static group. Static groups may hold each other in
// a cycle, which the configuration allows, so the groups are taken by strongly
// connected component, each after every component it holds: a component is
// opaque when one of its groups holds an opaque value from outside it.
//
// Within an opaque component, each group's via is the first member, in the
// order the group lists them, on a shortest way to such a value. The answer
// depends on the configuration alone, not on the rule that asks first.
func (c *classifier) decide() {
	members := map[string][]string{}
	var static []string
	for name, g := range c.group {
		if g.Dynamic {
			continue
		}
		static = append(static, name)
		for m := range strings.SplitSeq(g.Value, ", ") {
			members[name] = append(members[name], strings.TrimSpace(m))
		}
	}
	slices.Sort(static)
	isStatic := func(v string) bool { _, ok := members[v]; return ok }
	inner := func(g string) []string {
		c.reads += len(members[g])
		var out []string
		for _, m := range members[g] {
			if isStatic(m) {
				out = append(out, m)
			}
		}
		return out
	}
	// opaque decides a value outside the component being decided.
	opaque := func(v string) bool {
		if isStatic(v) {
			return c.via[v] != ""
		}
		return c.leaf(v).Text != ""
	}
	for _, comp := range components(static, inner) {
		in := make(map[string]bool, len(comp))
		for _, g := range comp {
			in[g] = true
		}
		// steps counts, for each group, the groups of the component it passes
		// through to an opaque value outside it: 0 for a group that holds one.
		steps := map[string]int{}
		var queue []string
		holders := map[string][]string{} // member -> the groups of comp holding it
		for _, g := range comp {
			c.reads += len(members[g])
			for _, m := range members[g] {
				switch {
				case in[m]:
					holders[m] = append(holders[m], g)
				case !opaque(m):
				default:
					if _, done := steps[g]; !done {
						steps[g] = 0
						queue = append(queue, g)
					}
				}
			}
		}
		for i := 0; i < len(queue); i++ {
			for _, h := range holders[queue[i]] {
				if _, done := steps[h]; !done {
					steps[h] = steps[queue[i]] + 1
					queue = append(queue, h)
				}
			}
		}
		for _, g := range comp {
			c.via[g] = ""
			n, ok := steps[g]
			if !ok {
				continue
			}
			c.reads += len(members[g])
			for _, m := range members[g] {
				if s, on := steps[m]; in[m] && on && s == n-1 || !in[m] && n == 0 && opaque(m) {
					c.via[g] = m
					break
				}
			}
		}
	}
}

// classify returns why a value is opaque: the zero reason when it is not. A value
// reached through static groups names them, innermost first.
func (c *classifier) classify(v string) reason.Reason {
	var chain []string
	for {
		g, ok := c.group[v]
		if !ok || g.Dynamic {
			break
		}
		if c.via[v] == "" {
			return reason.Reason{}
		}
		chain = append(chain, v)
		v = c.via[v]
	}
	r := c.leaf(v)
	if r.Text == "" || len(chain) == 0 {
		return r
	}
	text := strings.TrimSuffix(r.Text, ")")
	for _, g := range slices.Backward(chain) {
		text += ", in group " + g
	}
	r.Text = text + ")"
	return r
}

// leaf classifies a value that is no static group: a dynamic group, an external
// list, a region, or an address, which is not opaque.
func (c *classifier) leaf(v string) reason.Reason {
	if g, ok := c.group[v]; ok && g.Dynamic {
		return reason.New("doubt.dynamic-group", fmt.Sprintf("%s (%s)", opaqueRuntime, v))
	}
	switch {
	case v == "any" || c.addr[v] || len(prefixesOf(v)) > 0:
		return reason.Reason{}
	case c.list[v] || strings.HasPrefix(v, predefinedListPrefix):
		return reason.New("doubt.edl", fmt.Sprintf("%s (%s)", opaqueExternalList, v))
	case c.region[v] || predefinedRegion.MatchString(v):
		return reason.New("doubt.region", fmt.Sprintf("%s (%s)", opaqueRegion, v))
	}
	return reason.Reason{}
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
