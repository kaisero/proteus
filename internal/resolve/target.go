// Package resolve applies PAN-OS semantics to a loaded firewall configuration:
// which policy each vsys evaluates, the order its rules are evaluated in, and what
// a name means in a given scope.
package resolve

import (
	"fmt"
	"sort"

	"github.com/okaiser/proteus/internal/config"
)

// Target is one firewall vsys and the policy it evaluates.
//
// The key is (device, vsys). A multi-vsys firewall holds one rulebase per vsys, so
// a device name alone names several policies.
type Target struct {
	cfg    *config.Config
	root   *config.Element
	serial string
	vsys   string
	chain  []config.Scope
}

// Serial returns the name of the device entry the vsys sits under. A firewall's
// own export writes it as localhost.localdomain rather than as the serial number.
func (t *Target) Serial() string { return t.serial }

// Vsys returns the vsys name.
func (t *Target) Vsys() string { return t.vsys }

// Scope returns the target's own scope, its vsys.
func (t *Target) Scope() config.Scope {
	return config.Scope{Sort: config.ScopeVsys, Name: t.vsys}
}

// Chain returns the scopes the target inherits from: shared, then the vsys.
func (t *Target) Chain() []config.Scope { return append([]config.Scope{}, t.chain...) }

// Vsyses returns the vsys names a configuration defines, sorted.
func Vsyses(cfg *config.Config) []string {
	var out []string
	for _, v := range cfg.Root().Find("devices", "entry", "vsys", "entry") {
		if n := v.Attr("name"); n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Targets returns one policy target per vsys the configuration defines.
func Targets(cfg *config.Config) []*Target {
	names := Vsyses(cfg)
	device := ""
	if devs := cfg.Root().Find("devices", "entry"); len(devs) > 0 {
		device = devs[0].Attr("name")
	}
	out := make([]*Target, 0, len(names))
	for _, v := range names {
		out = append(out, &Target{
			cfg:    cfg,
			root:   cfg.Root(),
			serial: device,
			vsys:   v,
			chain: []config.Scope{
				{Sort: config.ScopeShared},
				{Sort: config.ScopeVsys, Name: v},
			},
		})
	}
	return out
}

// TargetFor returns one target by device name and vsys.
func TargetFor(cfg *config.Config, device, vsys string) (*Target, error) {
	all := Targets(cfg)
	var devices, vsyses []string
	for _, t := range all {
		if t.serial == device && t.vsys == vsys {
			return t, nil
		}
		devices = append(devices, t.serial)
		if t.serial == device {
			vsyses = append(vsyses, t.vsys)
		}
	}
	if len(vsyses) > 0 {
		return nil, fmt.Errorf("resolve: device %s has no vsys %q; it has %v",
			device, vsys, vsyses)
	}
	return nil, fmt.Errorf("resolve: no device named %s; known devices are %v",
		device, dedup(devices))
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
