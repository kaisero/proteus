package resolve

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
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
	path          string
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

// Scope returns the target's own scope.
func (t *Target) Scope() config.Scope {
	return config.Scope{Sort: config.ScopeDeviceGroup, Name: t.deviceGroup}
}

// Chain returns the scopes the target inherits from, shared first, then root to
// leaf.
func (t *Target) Chain() []config.Scope { return append([]config.Scope{}, t.chain...) }

// Targets returns every (serial, vsys) the configuration assigns to a device
// group.
func Targets(cfg *config.Config) ([]*Target, error) {
	h, err := NewHierarchy(cfg)
	if err != nil {
		return nil, err
	}
	assign, stacks, err := readAssignments(cfg.Path())
	if err != nil {
		return nil, err
	}
	out := make([]*Target, 0, len(assign))
	for k, dg := range assign {
		out = append(out, &Target{
			path:          cfg.Path(),
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
// Only the top-level sections count. A template's nested config and the readonly
// section both contain device-group elements of their own.
func readAssignments(path string) (map[devKey]string, map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	type devices struct {
		Entry []struct {
			Name string `xml:"name,attr"`
			Vsys struct {
				Entry []struct {
					Name string `xml:"name,attr"`
				} `xml:"entry"`
			} `xml:"vsys"`
		} `xml:"entry"`
	}

	assign := map[devKey]string{}
	stacks := map[string]string{}
	dec := xml.NewDecoder(f)
	var elems []string
	inConfig := false

	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			return assign, stacks, nil
		}
		if terr != nil {
			return nil, nil, fmt.Errorf("resolve: read %s: %w", path, terr)
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

			container, ok := topLevelContainer(elems)
			if !ok {
				continue
			}
			name := ""
			for _, a := range tv.Attr {
				if a.Name.Local == "name" {
					name = a.Value
				}
			}
			var e struct {
				Devices devices `xml:"devices"`
			}
			if err := dec.DecodeElement(&e, &tv); err != nil {
				return nil, nil, fmt.Errorf("resolve: read %s %q: %w", container, name, err)
			}
			for _, d := range e.Devices.Entry {
				switch container {
				case "device-group":
					if len(d.Vsys.Entry) == 0 {
						assign[devKey{d.Name, "vsys1"}] = name
						continue
					}
					for _, v := range d.Vsys.Entry {
						assign[devKey{d.Name, v.Name}] = name
					}
				case "template-stack":
					stacks[d.Name] = name
				}
			}
			elems = elems[:len(elems)-1]
		case xml.EndElement:
			if !inConfig || len(elems) == 0 {
				continue
			}
			elems = elems[:len(elems)-1]
			if len(elems) == 0 {
				return assign, stacks, nil
			}
		}
	}
}

// topLevelContainer reports whether the element just opened is an entry of a
// top-level device-group or template-stack, i.e. the path is exactly
// /config/devices/entry/<container>/entry.
func topLevelContainer(elems []string) (string, bool) {
	if len(elems) != 5 {
		return "", false
	}
	if elems[0] != "config" || elems[1] != "devices" || elems[2] != "entry" ||
		elems[4] != "entry" {
		return "", false
	}
	switch elems[3] {
	case "device-group", "template-stack":
		return elems[3], true
	}
	return "", false
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
