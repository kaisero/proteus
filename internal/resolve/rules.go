package resolve

import (
	"github.com/okaiser/proteus/internal/config"
)

// Rulebase is which rulebase to read.
type Rulebase int

// The rulebases this package reads.
const (
	Security Rulebase = iota
	NAT
	PBF
)

func (r Rulebase) String() string {
	switch r {
	case NAT:
		return "nat"
	case PBF:
		return "pbf"
	}
	return "security"
}

// Layer is where in the evaluation order a rule came from.
type Layer int

// The layers a firewall evaluates, in order.
const (
	LayerSharedPre  Layer = iota // pushed from Panorama, before the firewall's own
	LayerLocal                   // the vsys's own rulebase
	LayerSharedPost              // pushed from Panorama, after the firewall's own
)

var layerNames = map[Layer]string{
	LayerSharedPre: "shared-pre", LayerLocal: "local", LayerSharedPost: "shared-post",
}

func (l Layer) String() string { return layerNames[l] }

// Rule is one rule in a target's effective policy.
type Rule struct {
	Name     string
	Action   string
	Disabled bool
	// NegateSource and NegateDestination invert a side: the rule matches every
	// address except those listed. Source: PAN-OS documentation, "Security Policy
	// Rule", Source and Destination tabs, "Negate".
	NegateSource      bool
	NegateDestination bool
	Scope             config.Scope
	Layer             Layer
	Position          int // 1-based position in the effective order
	Fields            map[string][]string

	// ProfileGroups are the security profile groups the rule applies, and Profiles
	// the individual profiles it names instead, by kind.
	//
	// These are not matching fields. A rule matches on addresses, zones,
	// application and service; its profiles then inspect what the session carries.
	// They are read so that a caller can see which rules apply a profile that
	// mentions an object, without being told that the rule therefore matches it.
	ProfileGroups []string
	Profiles      map[string][]string

	// What the rule editor shows beyond matching: read for a lookup card.
	UUID        string
	Description string
	LogStart    string // the element's yes or no; empty when absent
	LogEnd      string
	LogSetting  string // the log forwarding profile
	Schedule    string
}

// Rules returns the target's policy in evaluation order: shared pre-rules, then
// the vsys's own rulebase, then shared post-rules, then the defaults.
//
// Source: PAN-OS documentation, "Device Group Policies". Where a Panorama-managed
// firewall keeps pushed rules is not yet observed on a device: the 11.2.0
// firewall schema declares no pre-rulebase at all, and /config/panorama as an
// empty node. See docs/specs/2026-09-27-panos-analyst-scope.md §5.3.
func (t *Target) Rules(rb Rulebase) ([]Rule, error) {
	es := t.ruleEntries(rb)
	out := make([]Rule, len(es))
	for i, e := range es {
		out[i] = e.Rule
	}
	return out, nil
}

// ruleEntry is a rule and the element it was read from, for the readers of the
// rulebases whose fields go beyond member lists.
type ruleEntry struct {
	Rule
	e *config.Element
}

// ruleEntries reads a rulebase in evaluation order, keeping each rule's element.
func (t *Target) ruleEntries(rb Rulebase) []ruleEntry {
	shared := config.Scope{Sort: config.ScopeShared}
	var out []ruleEntry
	add := func(rs []ruleEntry, layer Layer) {
		for _, r := range rs {
			r.Layer = layer
			out = append(out, r)
		}
	}
	add(readRules(t.root, shared, "pre-rulebase", rb), LayerSharedPre)
	add(readRules(t.root, t.Scope(), "rulebase", rb), LayerLocal)
	add(readRules(t.root, shared, "post-rulebase", rb), LayerSharedPost)
	for i := range out {
		out[i].Position = i + 1
	}
	return out
}

// readRules reads one scope's rulebase.
func readRules(root *config.Element, sc config.Scope, rulebase string, rb Rulebase) []ruleEntry {
	path, ok := scopeContainer(sc)
	if !ok {
		return nil
	}
	var out []ruleEntry
	for _, container := range root.Find(path...) {
		if sc.Name != "" && container.Attr("name") != sc.Name {
			continue
		}
		for _, e := range container.Find(rulebase, rb.String(), "rules", "entry") {
			out = append(out, ruleEntry{e: e, Rule: Rule{
				Name:     e.Attr("name"),
				Action:   e.Child("action").TextOr(""),
				Disabled: e.Child("disabled").TextOr("") == "yes",

				NegateSource:      e.Child("negate-source").TextOr("") == "yes",
				NegateDestination: e.Child("negate-destination").TextOr("") == "yes",
				Scope:             sc,
				Fields:            ruleFields(e),

				ProfileGroups: e.Child("profile-setting").Child("group").Members(),
				Profiles:      memberLists(e.Child("profile-setting").Child("profiles")),

				UUID:        e.Attr("uuid"),
				Description: e.Child("description").TextOr(""),
				LogStart:    e.Child("log-start").TextOr(""),
				LogEnd:      e.Child("log-end").TextOr(""),
				LogSetting:  e.Child("log-setting").TextOr(""),
				Schedule:    e.Child("schedule").TextOr(""),
			}})
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
