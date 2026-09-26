// Package resolve applies Panorama semantics to a loaded configuration: the
// device-group hierarchy, which firewall inherits which policy, the order rules
// are evaluated in, and what a name means in a given scope.
package resolve

import (
	"fmt"
	"sort"

	"github.com/okaiser/go-panos-schema/config"
)

// Hierarchy is the device-group tree.
//
// The parent of a device group is recorded only at
// /config/readonly/devices/entry/device-group/entry/parent-dg. The device-group
// entries themselves carry no parent, and the schema declares readonly as an
// empty skip-validation sequence, so this node is hand-modelled and registered in
// internal/schema.HandModelled. Observed on Panorama 11.2.7-h1.
type Hierarchy struct {
	parent   map[string]string
	children map[string][]string
	roots    []string
}

// NewHierarchy reads the device-group tree from a configuration.
func NewHierarchy(cfg *config.Config) (*Hierarchy, error) {
	h := &Hierarchy{
		parent:   readParentDg(cfg.Root()),
		children: map[string][]string{},
	}
	seen := map[string]bool{}
	for dg, p := range h.parent {
		seen[dg] = true
		if p == "" {
			continue
		}
		seen[p] = true
		h.children[p] = append(h.children[p], dg)
	}
	for dg := range seen {
		if h.parent[dg] == "" {
			h.roots = append(h.roots, dg)
		}
	}
	sort.Strings(h.roots)
	for k := range h.children {
		sort.Strings(h.children[k])
	}
	if err := h.checkCycles(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *Hierarchy) checkCycles() error {
	for dg := range h.parent {
		seen := map[string]bool{dg: true}
		for cur := h.parent[dg]; cur != ""; cur = h.parent[cur] {
			if seen[cur] {
				return fmt.Errorf("resolve: device-group hierarchy has a cycle through %q", cur)
			}
			seen[cur] = true
		}
	}
	return nil
}

// Roots returns the device groups with no parent, sorted.
func (h *Hierarchy) Roots() []string { return append([]string{}, h.roots...) }

// ParentOf returns the parent of a device group.
func (h *Hierarchy) ParentOf(dg string) (string, bool) {
	p, ok := h.parent[dg]
	if !ok || p == "" {
		return "", false
	}
	return p, true
}

// Children returns the direct children of a device group, sorted.
func (h *Hierarchy) Children(dg string) []string {
	return append([]string{}, h.children[dg]...)
}

// Chain returns the scopes a device group inherits from, shared first and then
// root to leaf. That is the order PAN-OS evaluates pre-rules in, and the order in
// which a descendant definition shadows an ancestor's.
//
// Source: PAN-OS documentation, "Device Group Policies".
func (h *Hierarchy) Chain(dg string) []config.Scope {
	var up []string
	for cur := dg; cur != ""; cur = h.parent[cur] {
		up = append(up, cur)
	}
	out := []config.Scope{{Sort: config.ScopeShared}}
	for i := len(up) - 1; i >= 0; i-- {
		out = append(out, config.Scope{Sort: config.ScopeDeviceGroup, Name: up[i]})
	}
	return out
}

// readParentDg reads /config/readonly/devices/entry/device-group/entry/parent-dg.
// A device group with no parent-dg maps to the empty string, so roots are known.
//
// The path is matched exactly. A template's nested configuration can hold its own
// readonly section, which describes that template rather than the Panorama device
// groups.
func readParentDg(root *config.Element) map[string]string {
	out := map[string]string{}
	for _, e := range root.Find("readonly", "devices", "entry", "device-group", "entry") {
		out[e.Attr("name")] = e.Child("parent-dg").TextOr("")
	}
	return out
}
