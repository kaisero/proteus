package resolve

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"

	"github.com/okaiser/go-panos-schema/config"
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
		rs, err := readRules(t.path, sc, "pre-rulebase", rb)
		if err != nil {
			return nil, err
		}
		layer := LayerDeviceGroupPre
		if sc.Sort == config.ScopeShared {
			layer = LayerSharedPre
		}
		for _, r := range rs {
			r.Layer = layer
			out = append(out, r)
		}
	}
	for i := len(chain) - 1; i >= 0; i-- {
		sc := chain[i]
		rs, err := readRules(t.path, sc, "post-rulebase", rb)
		if err != nil {
			return nil, err
		}
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

// rawRule matches any rule entry. The named fields are read explicitly and every
// member list lands in Any, so a caller sees them all without the generated model.
type rawRule struct {
	Name     string `xml:"name,attr"`
	Action   string `xml:"action"`
	Disabled string `xml:"disabled"`
	Any      []struct {
		XMLName xml.Name
		Members []string `xml:"member"`
	} `xml:",any"`
}

// readRules reads one scope's rulebase, locating the rules by element path so a
// large configuration costs no more than the rules it holds.
func readRules(path string, sc config.Scope, rulebase string, rb Rulebase) ([]Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("resolve: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	dec := xml.NewDecoder(f)
	var elems, entries []string
	inConfig := false
	var out []Rule

	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			return out, nil
		}
		if terr != nil {
			return nil, fmt.Errorf("resolve: read %s: %w", path, terr)
		}
		switch tv := tok.(type) {
		case xml.StartElement:
			if !inConfig {
				if tv.Name.Local != "config" {
					continue
				}
				inConfig = true
			}
			elems = append(elems, tv.Name.Local)
			if tv.Name.Local != "entry" {
				continue
			}
			name := ""
			for _, a := range tv.Attr {
				if a.Name.Local == "name" {
					name = a.Value
				}
			}
			entries = append(entries, name)

			if !atRulesEntry(elems, entries, sc, rulebase, rb) {
				continue
			}
			var raw rawRule
			if err := dec.DecodeElement(&raw, &tv); err != nil {
				return nil, fmt.Errorf("resolve: read rule %q: %w", name, err)
			}
			fields := map[string][]string{}
			for _, fl := range raw.Any {
				if len(fl.Members) > 0 {
					fields[fl.XMLName.Local] = fl.Members
				}
			}
			out = append(out, Rule{
				Name:     raw.Name,
				Action:   raw.Action,
				Disabled: raw.Disabled == "yes",
				Scope:    sc,
				Fields:   fields,
			})
			elems = elems[:len(elems)-1]
			entries = entries[:len(entries)-1]
		case xml.EndElement:
			if !inConfig || len(elems) == 0 {
				continue
			}
			if elems[len(elems)-1] == "entry" && len(entries) > 0 {
				entries = entries[:len(entries)-1]
			}
			elems = elems[:len(elems)-1]
			if len(elems) == 0 {
				return out, nil
			}
		}
	}
}

// atRulesEntry reports whether the entry just opened is a rule in the wanted
// scope and rulebase.
//
// Shared rules sit at /config/shared/<rulebase>/<kind>/rules/entry. Device-group
// rules sit at /config/devices/entry/device-group/entry/<rulebase>/<kind>/rules/
// entry, and the device-group name is the second entry name on the path: the
// first belongs to devices/entry.
func atRulesEntry(elems, entries []string, sc config.Scope, rulebase string, rb Rulebase) bool {
	n := len(elems)
	if n < 5 || elems[n-1] != "entry" || elems[n-2] != "rules" ||
		elems[n-3] != rb.String() || elems[n-4] != rulebase {
		return false
	}
	switch sc.Sort {
	case config.ScopeShared:
		return n == 6 && elems[0] == "config" && elems[1] == "shared"
	case config.ScopeDeviceGroup:
		if n != 9 || elems[0] != "config" || elems[1] != "devices" ||
			elems[2] != "entry" || elems[3] != "device-group" || elems[4] != "entry" {
			return false
		}
		return len(entries) >= 2 && entries[1] == sc.Name
	default:
		return false
	}
}
