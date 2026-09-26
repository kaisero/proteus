package config

import (
	"fmt"
	"sort"
	"strings"
)

// ScopeSort is the kind of scope a configuration element sits in.
type ScopeSort int

// The scopes a name can resolve in.
const (
	ScopeShared ScopeSort = iota
	ScopeVsys
	ScopeDeviceGroup
	ScopeTemplate
	ScopeTemplateStack
	ScopeConfig // outside any of the above, e.g. mgt-config
)

var scopePrefix = map[ScopeSort]string{
	ScopeShared: "shared", ScopeVsys: "vsys", ScopeDeviceGroup: "dg",
	ScopeTemplate: "tpl", ScopeTemplateStack: "tplstack", ScopeConfig: "config",
}

// scopeNeedsName reports whether a scope of this sort is named.
func scopeNeedsName(s ScopeSort) bool {
	switch s {
	case ScopeVsys, ScopeDeviceGroup, ScopeTemplate, ScopeTemplateStack:
		return true
	}
	return false
}

// Scope names where a configuration element lives. A name means different things
// in different scopes, so nothing in this library resolves a name without one.
// See AGENTS.md R5 and R10.
type Scope struct {
	Sort ScopeSort
	Name string // empty for shared and config
}

func (s Scope) String() string {
	p := scopePrefix[s.Sort]
	if s.Name == "" {
		return p
	}
	return p + ":" + s.Name
}

// ParseScope reads a scope string such as dg:Branch-EMEA.
func ParseScope(s string) (Scope, error) {
	head, name, hasName := strings.Cut(s, ":")
	for sort, prefix := range scopePrefix {
		if prefix != head {
			continue
		}
		switch {
		case scopeNeedsName(sort) && name == "":
			return Scope{}, fmt.Errorf("config: scope %q needs a name, e.g. %s:<name>", s, prefix)
		case !scopeNeedsName(sort) && hasName:
			return Scope{}, fmt.Errorf("config: scope %q takes no name", s)
		}
		return Scope{Sort: sort, Name: name}, nil
	}
	return Scope{}, fmt.Errorf("config: unknown scope %q, want one of %s",
		s, strings.Join(knownScopes(), ", "))
}

func knownScopes() []string {
	out := make([]string, 0, len(scopePrefix))
	for s, p := range scopePrefix {
		if scopeNeedsName(s) {
			p += ":<name>"
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
