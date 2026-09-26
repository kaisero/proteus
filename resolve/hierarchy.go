// Package resolve applies Panorama semantics to a loaded configuration: the
// device-group hierarchy, which firewall inherits which policy, the order rules
// are evaluated in, and what a name means in a given scope.
package resolve

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
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
	parents, err := readParentDg(cfg.Path())
	if err != nil {
		return nil, err
	}
	h := &Hierarchy{parent: parents, children: map[string][]string{}}
	seen := map[string]bool{}
	for dg, p := range parents {
		seen[dg] = true
		if p == "" {
			continue
		}
		seen[p] = true
		h.children[p] = append(h.children[p], dg)
	}
	for dg := range seen {
		if parents[dg] == "" {
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
// Only the readonly section at the top level counts. A template's nested config
// can hold its own readonly section, which describes that template, not the
// Panorama device groups.
func readParentDg(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("resolve: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	out := map[string]string{}
	dec := xml.NewDecoder(f)
	var elems []string
	inConfig := false

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

			// Match exactly /config/readonly/devices/entry/device-group/entry.
			if !atTopLevelReadonlyDeviceGroupEntry(elems) {
				continue
			}
			name := ""
			for _, a := range tv.Attr {
				if a.Name.Local == "name" {
					name = a.Value
				}
			}
			var e struct {
				ParentDg string `xml:"parent-dg"`
			}
			if err := dec.DecodeElement(&e, &tv); err != nil {
				return nil, fmt.Errorf("resolve: read parent-dg for %q: %w", name, err)
			}
			out[name] = e.ParentDg
			elems = elems[:len(elems)-1]
		case xml.EndElement:
			if !inConfig || len(elems) == 0 {
				continue
			}
			elems = elems[:len(elems)-1]
			if len(elems) == 0 {
				return out, nil
			}
		}
	}
}

// wantParentDgPath is the only place a device group's parent is recorded.
var wantParentDgPath = []string{
	"config", "readonly", "devices", "entry", "device-group", "entry",
}

func atTopLevelReadonlyDeviceGroupEntry(elems []string) bool {
	if len(elems) != len(wantParentDgPath) {
		return false
	}
	for i := range elems {
		if elems[i] != wantParentDgPath[i] {
			return false
		}
	}
	return true
}
