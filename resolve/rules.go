package resolve

import (
	"github.com/okaiser/panos-analyst/config"
)

// Rulebase is which rulebase to read.
type Rulebase int

// The rulebases this package reads.
const (
	Security Rulebase = iota
	NAT
)

func (r Rulebase) String() string {
	if r == NAT {
		return "nat"
	}
	return "security"
}

// Layer is where in the evaluation order a rule came from.
type Layer int

// The layers a firewall evaluates, in order.
const (
	LayerSharedPre Layer = iota
	LayerDeviceGroupPre
	LayerLocal // rules defined on the firewall itself, never in a Panorama config
	LayerDeviceGroupPost
	LayerSharedPost
)

var layerNames = map[Layer]string{
	LayerSharedPre: "shared-pre", LayerDeviceGroupPre: "dg-pre", LayerLocal: "local",
	LayerDeviceGroupPost: "dg-post", LayerSharedPost: "shared-post",
}

func (l Layer) String() string { return layerNames[l] }

// Rule is one rule in a target's effective policy.
type Rule struct {
	Name     string
	Action   string
	Disabled bool
	Scope    config.Scope
	Layer    Layer
	Position int // 1-based position in the effective order
	Fields   map[string][]string

	// ProfileGroups are the security profile groups the rule applies, and Profiles
	// the individual profiles it names instead, by kind.
	//
	// These are not matching fields. A rule matches on addresses, zones,
	// application and service; its profiles then inspect what the session carries.
	// They are read so that a caller can see which rules apply a profile that
	// mentions an object, without being told that the rule therefore matches it.
	ProfileGroups []string
	Profiles      map[string][]string
}

// Rules returns the target's effective policy in evaluation order.
//
// Shared pre-rules, then device-group pre-rules from root to leaf, then the
// firewall's own rules, then device-group post-rules from leaf to root, then
// shared post-rules, then the defaults. A Panorama configuration holds no local
// rules, so that layer is empty here.
//
// Source: PAN-OS documentation, "Device Group Policies".
func (t *Target) Rules(rb Rulebase) ([]Rule, error) {
	chain := t.Chain() // shared, then root to leaf

	var out []Rule
	for _, sc := range chain {
		rs := readRules(t.root, sc, "pre-rulebase", rb)
		layer := LayerDeviceGroupPre
		if sc.Sort == config.ScopeShared {
			layer = LayerSharedPre
		}
		for _, r := range rs {
			r.Layer = layer
			out = append(out, r)
		}
	}
	// A firewall's own rules sit in the plain rulebase, between any pushed
	// pre-rules and any pushed post-rules. A Panorama configuration has none, so
	// this layer is simply empty there.
	for _, sc := range chain {
		for _, r := range readRules(t.root, sc, "rulebase", rb) {
			r.Layer = LayerLocal
			out = append(out, r)
		}
	}

	for i := len(chain) - 1; i >= 0; i-- {
		sc := chain[i]
		rs := readRules(t.root, sc, "post-rulebase", rb)
		layer := LayerDeviceGroupPost
		if sc.Sort == config.ScopeShared {
			layer = LayerSharedPost
		}
		for _, r := range rs {
			r.Layer = layer
			out = append(out, r)
		}
	}
	for i := range out {
		out[i].Position = i + 1
	}
	return out, nil
}

// rulebaseContainer names where a scope's rulebase lives, as a path under
// /config. The path is matched exactly, so a template's nested configuration
// cannot contribute rules to a device group.
func rulebaseContainer(sc config.Scope) ([]string, bool) {
	switch sc.Sort {
	case config.ScopeShared:
		return []string{"shared"}, true
	case config.ScopeDeviceGroup:
		return []string{"devices", "entry", "device-group", "entry"}, true
	case config.ScopeVsys:
		return []string{"devices", "entry", "vsys", "entry"}, true
	default:
		return nil, false
	}
}

// readRules reads one scope's rulebase.
func readRules(root *config.Element, sc config.Scope, rulebase string, rb Rulebase) []Rule {
	path, ok := rulebaseContainer(sc)
	if !ok {
		return nil
	}
	var out []Rule
	for _, container := range root.Find(path...) {
		if sc.Name != "" && container.Attr("name") != sc.Name {
			continue
		}
		for _, e := range container.Find(rulebase, rb.String(), "rules", "entry") {
			out = append(out, Rule{
				Name:     e.Attr("name"),
				Action:   e.Child("action").TextOr(""),
				Disabled: e.Child("disabled").TextOr("") == "yes",
				Scope:    sc,
				Fields:   ruleFields(e),

				ProfileGroups: e.Child("profile-setting").Child("group").Members(),
				Profiles:      memberLists(e.Child("profile-setting").Child("profiles")),
			})
		}
	}
	return out
}

// ruleFields collects every member list on a rule, so a caller sees them all
// without the generated model.
func ruleFields(e *config.Element) map[string][]string {
	return memberLists(e)
}

// memberLists collects every child of an element that is a list of members.
func memberLists(e *config.Element) map[string][]string {
	if e == nil {
		return nil
	}
	var out map[string][]string
	for _, f := range e.Children {
		m := f.Members()
		if len(m) == 0 {
			continue
		}
		if out == nil {
			out = map[string][]string{}
		}
		out[f.Name] = m
	}
	return out
}

// RulesForDeviceGroup returns the effective policy of a device group, whether or
// not a firewall is assigned to it.
//
// Every firewall in a device group inherits the same merged Panorama policy, so
// the device group, not the firewall, is what determines it.
func RulesForDeviceGroup(cfg *config.Config, dg string, rb Rulebase) ([]Rule, error) {
	h, err := NewHierarchy(cfg)
	if err != nil {
		return nil, err
	}
	t := &Target{cfg: cfg, root: cfg.Root(), deviceGroup: dg, chain: h.Chain(dg)}
	return t.Rules(rb)
}
