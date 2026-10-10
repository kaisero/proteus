package index

import (
	"fmt"
	"math"
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
// monitoring, which are not in a configuration file. An address lookup reaches a rule naming one
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
	c := &classifier{
		addr:   map[string]bool{},
		list:   map[string]bool{},
		region: map[string]bool{},
		group:  map[string]resolve.Object{},
		via:    map[string]string{},
		depth:  map[string]int{},
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

// classifier decides whether a value is opaque, following static groups. Each
// static group is walked once per index build: via remembers the answer.
type classifier struct {
	addr, list, region map[string]bool
	group              map[string]resolve.Object

	// via holds, for each static group walked, the member through which it is
	// opaque, or "" when it is not.
	via map[string]string
	// depth holds the static groups on the walk, by their depth on it.
	depth map[string]int
	// pending holds the groups found not opaque only because the walk was cut
	// at a group above them; their answer waits for that group's.
	pending []string
}

// onNoCycle is the depth walk returns when it cut no cycle.
const onNoCycle = math.MaxInt

// classify returns why a value is opaque: the zero reason when it is not. A value
// reached through static groups names them, innermost first.
func (c *classifier) classify(v string) reason.Reason {
	if found, _ := c.walk(v); found == "" {
		return reason.Reason{}
	}
	var chain []string
	for {
		if g, ok := c.group[v]; !ok || g.Dynamic {
			break
		}
		chain = append(chain, v)
		v = c.via[v]
	}
	r := c.leaf(v)
	text := strings.TrimSuffix(r.Text, ")")
	for _, g := range slices.Backward(chain) {
		text += ", in group " + g
	}
	r.Text = text + ")"
	return r
}

// walk returns v when the value is opaque and "" when it is not, and the least
// depth of a group on the walk that a cycle led back to, onNoCycle when none.
func (c *classifier) walk(v string) (string, int) {
	g, isGroup := c.group[v]
	if !isGroup || g.Dynamic {
		if c.leaf(v).Text != "" {
			return v, onNoCycle
		}
		return "", onNoCycle
	}
	if m, done := c.via[v]; done {
		if m == "" {
			return "", onNoCycle
		}
		return v, onNoCycle
	}
	if d, on := c.depth[v]; on {
		return "", d // a cycle: stop rather than recurse
	}
	d := len(c.depth)
	c.depth[v] = d
	mark := len(c.pending)
	cut := onNoCycle
	via := ""
	for m := range strings.SplitSeq(g.Value, ", ") {
		m = strings.TrimSpace(m)
		found, at := c.walk(m)
		cut = min(cut, at)
		if found != "" {
			via = m
			break
		}
	}
	delete(c.depth, v)
	switch {
	case via != "":
		c.via[v] = via
		// The groups pending below v reach v, so they are opaque too; they
		// are walked again when a rule names them.
		c.pending = c.pending[:mark]
		return v, onNoCycle
	case cut >= d:
		// The walk from v saw everything v reaches and found nothing, and the
		// groups pending below v reach only what v reaches.
		for _, p := range c.pending[mark:] {
			c.via[p] = ""
		}
		c.pending = c.pending[:mark]
		c.via[v] = ""
		return "", onNoCycle
	default:
		c.pending = append(c.pending, v)
		return "", cut
	}
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
