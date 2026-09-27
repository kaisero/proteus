package resolve

import (
	"fmt"
	"sort"

	"github.com/okaiser/go-panos-schema/config"
)

// Target is one firewall vsys and the policy it inherits.
//
// The key is (serial, vsys), never serial. A multi-vsys firewall can have each
// vsys in a different device group, so a serial alone names two different
// effective policies. Observed on Panorama 11.2.7-h1: serial 007900000000004 had
// vsys3 in at-ktn and vsys2 in at-ooe.
type Target struct {
	cfg           *config.Config
	root          *config.Element
	serial        string
	vsys          string
	deviceGroup   string
	templateStack string
	chain         []config.Scope
}

// Serial returns the firewall's serial number.
func (t *Target) Serial() string { return t.serial }

// Vsys returns the vsys name.
func (t *Target) Vsys() string { return t.vsys }

// DeviceGroup returns the device group the vsys belongs to.
func (t *Target) DeviceGroup() string { return t.deviceGroup }

// TemplateStack returns the template stack assigned to the firewall, if any.
func (t *Target) TemplateStack() string { return t.templateStack }

// Scope returns the target's own scope: its device group on Panorama, its vsys on
// a firewall.
func (t *Target) Scope() config.Scope {
	if t.deviceGroup == "" {
		return config.Scope{Sort: config.ScopeVsys, Name: t.vsys}
	}
	return config.Scope{Sort: config.ScopeDeviceGroup, Name: t.deviceGroup}
}

// Chain returns the scopes the target inherits from, shared first, then root to
// leaf.
func (t *Target) Chain() []config.Scope { return append([]config.Scope{}, t.chain...) }

// Vsyses returns the vsys names a firewall configuration defines, sorted. A
// Panorama configuration has none of its own.
func Vsyses(cfg *config.Config) ([]string, error) {
	var out []string
	for _, v := range cfg.Root().Find("devices", "entry", "vsys", "entry") {
		if n := v.Attr("name"); n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Targets returns every policy target the configuration describes.
//
// On Panorama that is every (serial, vsys) assigned to a device group. On a
// firewall it is every vsys, which has no device group but does have its own
// rulebase.
func Targets(cfg *config.Config) ([]*Target, error) {
	if cfg.Platform() == config.Firewall {
		return firewallTargets(cfg)
	}
	h, err := NewHierarchy(cfg)
	if err != nil {
		return nil, err
	}
	assign, stacks := readAssignments(cfg.Root())
	out := make([]*Target, 0, len(assign))
	for k, dg := range assign {
		out = append(out, &Target{
			cfg:           cfg,
			root:          cfg.Root(),
			serial:        k.serial,
			vsys:          k.vsys,
			deviceGroup:   dg,
			templateStack: stacks[k.serial],
			chain:         h.Chain(dg),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].serial != out[j].serial {
			return out[i].serial < out[j].serial
		}
		return out[i].vsys < out[j].vsys
	})
	return out, nil
}

// firewallTargets returns one target per vsys. A firewall configuration carries no
// device groups, so the chain is shared and the vsys itself.
func firewallTargets(cfg *config.Config) ([]*Target, error) {
	names, err := Vsyses(cfg)
	if err != nil {
		return nil, err
	}
	serial := cfg.Root().Find("devices", "entry")
	hostname := ""
	if len(serial) > 0 {
		hostname = serial[0].Attr("name")
	}
	out := make([]*Target, 0, len(names))
	for _, v := range names {
		out = append(out, &Target{
			cfg:    cfg,
			root:   cfg.Root(),
			serial: hostname,
			vsys:   v,
			chain: []config.Scope{
				{Sort: config.ScopeShared},
				{Sort: config.ScopeVsys, Name: v},
			},
		})
	}
	return out, nil
}

// TargetFor returns one target by serial and vsys.
func TargetFor(cfg *config.Config, serial, vsys string) (*Target, error) {
	all, err := Targets(cfg)
	if err != nil {
		return nil, err
	}
	var serials, vsyses []string
	for _, t := range all {
		if t.serial == serial && t.vsys == vsys {
			return t, nil
		}
		serials = append(serials, t.serial)
		if t.serial == serial {
			vsyses = append(vsyses, t.vsys)
		}
	}
	if len(vsyses) > 0 {
		return nil, fmt.Errorf("resolve: serial %s has no vsys %q; it has %v",
			serial, vsys, vsyses)
	}
	return nil, fmt.Errorf("resolve: no device group holds serial %s; known serials are %v",
		serial, dedup(serials))
}

type devKey struct{ serial, vsys string }

// readAssignments reads device-group and template-stack membership.
//
// A device entry without a vsys child is a single-vsys firewall, recorded as
// vsys1, which is what PAN-OS calls it.
//
// Both paths are matched exactly. A template's nested configuration and the
// readonly section each hold device-group elements of their own, and counting
// those would invent device groups that do not exist.
func readAssignments(root *config.Element) (map[devKey]string, map[string]string) {
	assign := map[devKey]string{}
	stacks := map[string]string{}

	for _, dg := range root.Find("devices", "entry", "device-group", "entry") {
		name := dg.Attr("name")
		for _, dev := range dg.Find("devices", "entry") {
			serial := dev.Attr("name")
			vsyses := dev.Find("vsys", "entry")
			if len(vsyses) == 0 {
				assign[devKey{serial, "vsys1"}] = name
				continue
			}
			for _, v := range vsyses {
				assign[devKey{serial, v.Attr("name")}] = name
			}
		}
	}
	for _, ts := range root.Find("devices", "entry", "template-stack", "entry") {
		for _, dev := range ts.Find("devices", "entry") {
			stacks[dev.Attr("name")] = ts.Attr("name")
		}
	}
	return assign, stacks
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
