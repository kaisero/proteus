package resolve

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/okaiser/go-panos-schema/config"
)

// Object is one configuration object visible in a scope.
type Object struct {
	Name         string
	Kind         string // address, address-group, service, tag, ...
	Scope        config.Scope
	Value        string
	Tags         []string
	ShadowedFrom *config.Scope // the scope whose definition this one replaced
}

// Objects returns the objects of one kind visible to the target, with a
// descendant definition shadowing an ancestor's of the same name.
func (t *Target) Objects(kind string) ([]Object, error) {
	return objectsInChain(t.path, t.Chain(), kind)
}

// ObjectsInScope returns the objects of one kind visible in a scope and its
// ancestors.
func ObjectsInScope(cfg *config.Config, sc config.Scope, kind string) ([]Object, error) {
	chain, err := chainFor(cfg, sc)
	if err != nil {
		return nil, err
	}
	return objectsInChain(cfg.Path(), chain, kind)
}

// chainFor returns the scopes a scope inherits from, shared first.
func chainFor(cfg *config.Config, sc config.Scope) ([]config.Scope, error) {
	if sc.Sort == config.ScopeDeviceGroup {
		h, err := NewHierarchy(cfg)
		if err != nil {
			return nil, err
		}
		return h.Chain(sc.Name), nil
	}
	chain := []config.Scope{{Sort: config.ScopeShared}}
	if sc.Sort != config.ScopeShared {
		chain = append(chain, sc)
	}
	return chain, nil
}

// objectsInChain walks the chain root to leaf, so a later definition replaces an
// earlier one and the replacement is recorded.
func objectsInChain(path string, chain []config.Scope, kind string) ([]Object, error) {
	byName := map[string]Object{}
	var order []string
	for _, sc := range chain {
		objs, err := readObjects(path, sc, kind)
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			if prev, seen := byName[o.Name]; seen {
				prevScope := prev.Scope
				o.ShadowedFrom = &prevScope
			} else {
				order = append(order, o.Name)
			}
			byName[o.Name] = o
		}
	}
	out := make([]Object, 0, len(order))
	for _, n := range order {
		out = append(out, byName[n])
	}
	return out, nil
}

type rawObject struct {
	Name        string `xml:"name,attr"`
	IPNetmask   string `xml:"ip-netmask"`
	IPRange     string `xml:"ip-range"`
	FQDN        string `xml:"fqdn"`
	Description string `xml:"description"`
	Tag         struct {
		Member []string `xml:"member"`
	} `xml:"tag"`
	Static struct {
		Member []string `xml:"member"`
	} `xml:"static"`
	Dynamic struct {
		Filter string `xml:"filter"`
	} `xml:"dynamic"`
}

func (r rawObject) value() string {
	switch {
	case r.IPNetmask != "":
		return r.IPNetmask
	case r.IPRange != "":
		return r.IPRange
	case r.FQDN != "":
		return r.FQDN
	case len(r.Static.Member) > 0:
		return strings.Join(r.Static.Member, ", ")
	case r.Dynamic.Filter != "":
		return r.Dynamic.Filter
	}
	return ""
}

// readObjects reads one scope's objects of one kind.
func readObjects(path string, sc config.Scope, kind string) ([]Object, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("resolve: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	dec := xml.NewDecoder(f)
	var elems, entries []string
	inConfig := false
	var out []Object

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

			if !atObjectEntry(elems, entries, sc, kind) {
				continue
			}
			var raw rawObject
			if err := dec.DecodeElement(&raw, &tv); err != nil {
				return nil, fmt.Errorf("resolve: read %s %q: %w", kind, name, err)
			}
			out = append(out, Object{
				Name:  raw.Name,
				Kind:  kind,
				Scope: sc,
				Value: raw.value(),
				Tags:  raw.Tag.Member,
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

// atObjectEntry reports whether the entry just opened is an object of the wanted
// kind in the wanted scope.
//
// The paths are matched exactly, so a template's nested configuration cannot
// contribute objects to a device group. For a device group the name is the second
// entry on the path: the first belongs to devices/entry.
func atObjectEntry(elems, entries []string, sc config.Scope, kind string) bool {
	n := len(elems)
	if n < 3 || elems[n-1] != "entry" || elems[n-2] != kind || elems[0] != "config" {
		return false
	}
	switch sc.Sort {
	case config.ScopeShared:
		return n == 4 && elems[1] == "shared"
	case config.ScopeDeviceGroup:
		if n != 7 || elems[1] != "devices" || elems[2] != "entry" ||
			elems[3] != "device-group" || elems[4] != "entry" {
			return false
		}
		return len(entries) >= 2 && entries[1] == sc.Name
	case config.ScopeVsys:
		if n != 7 || elems[1] != "devices" || elems[2] != "entry" ||
			elems[3] != "vsys" || elems[4] != "entry" {
			return false
		}
		return len(entries) >= 2 && entries[1] == sc.Name
	default:
		return false
	}
}
