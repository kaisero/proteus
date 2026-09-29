// Package drift compares two configurations of one scope: which objects and rules
// were added, removed or changed between two snapshots. It answers "what changed
// since Tuesday" in the schema's terms rather than as an XML diff. Spec §15 C9.
package drift

import (
	"fmt"
	"sort"
	"strings"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// Op is what happened to one object or rule.
type Op string

// The operations a change can be.
const (
	Added   Op = "added"
	Removed Op = "removed"
	Changed Op = "changed"
)

// Change is one object or rule that differs.
type Change struct {
	Op   Op     `json:"op"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Old  string `json:"old,omitempty"`
	New  string `json:"new,omitempty"`
}

// Compare returns what differs between two configurations in one scope, sorted by
// kind and name.
//
// Only definitions in the scope itself count, so a vsys comparison does not repeat
// every shared change; compare shared for those. A rule is compared by action,
// disabled and its member lists. Its position is not compared: one inserted rule
// would otherwise mark every rule below it as changed.
func Compare(before, after *config.Config, sc config.Scope) ([]Change, error) {
	a, err := render(before, sc)
	if err != nil {
		return nil, err
	}
	b, err := render(after, sc)
	if err != nil {
		return nil, err
	}
	var out []Change
	for k, old := range a {
		nu, ok := b[k]
		switch {
		case !ok:
			out = append(out, Change{Op: Removed, Kind: k.kind, Name: k.name, Old: old})
		case nu != old:
			out = append(out, Change{Op: Changed, Kind: k.kind, Name: k.name, Old: old, New: nu})
		}
	}
	for k, nu := range b {
		if _, ok := a[k]; !ok {
			out = append(out, Change{Op: Added, Kind: k.kind, Name: k.name, New: nu})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

type key struct{ kind, name string }

// render reduces every object and rule defined in the scope to one comparable line.
func render(cfg *config.Config, sc config.Scope) (map[key]string, error) {
	out := map[key]string{}
	for _, kind := range resolve.ObjectKinds(cfg) {
		objs, err := resolve.ObjectsInScope(cfg, sc, kind)
		if err != nil {
			return nil, err
		}
		for _, o := range objs {
			if o.Scope != sc {
				continue
			}
			line := o.Value
			if len(o.Tags) > 0 {
				line += " tags=" + strings.Join(o.Tags, ",")
			}
			out[key{kind, o.Name}] = line
		}
	}
	tgs, err := resolve.Targets(cfg)
	if err != nil {
		return nil, err
	}
	for _, tg := range tgs {
		if sc.Sort == config.ScopeVsys && tg.Scope() != sc {
			continue
		}
		for _, rb := range []resolve.Rulebase{resolve.Security, resolve.NAT} {
			rules, err := tg.Rules(rb)
			if err != nil {
				return nil, err
			}
			for _, r := range rules {
				if r.Scope == sc {
					out[key{rb.String() + " rule", r.Name}] = renderRule(r)
				}
			}
		}
		if sc.Sort == config.ScopeShared {
			break // shared rules are the same in every vsys
		}
	}
	return out, nil
}

func renderRule(r resolve.Rule) string {
	fields := make([]string, 0, len(r.Fields))
	for f, v := range r.Fields {
		fields = append(fields, fmt.Sprintf("%s=%s", f, strings.Join(v, ",")))
	}
	sort.Strings(fields)
	s := r.Action
	if r.Disabled {
		s += " disabled"
	}
	return s + " " + strings.Join(fields, " ")
}
