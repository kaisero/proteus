package query

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/okaiser/proteus/internal/drift"
	"github.com/okaiser/proteus/internal/simulate"
	"github.com/okaiser/proteus/internal/simulate/nat"
	"github.com/okaiser/proteus/internal/simulate/pathpolicy"
	"github.com/okaiser/proteus/internal/simulate/routing"
	"github.com/okaiser/proteus/internal/simulate/securitypolicy"
)

// The answer builders (spec 2026-10-09 §3.3). Each result carries its answer:
// one line of the text output, verbatim and without colour. The text renderers
// print the same string, so a reader of the JSON and a reader of the text see
// one answer.

// PathAnswer is the verdict line of a path answer: the verdict, and where and
// why it was decided.
func PathAnswer(r pathpolicy.Result) string {
	if r.At == nil {
		return string(r.Verdict)
	}
	h, ok := PointHop(r)
	at := fmt.Sprintf("%s at hop %d: ", r.Verdict, r.At.Hop)
	switch {
	case !ok:
		return at + r.At.Reason.Text()
	case r.Verdict == pathpolicy.VerdictUndecided:
		return at + fmt.Sprintf("%s / %s, %s", h.Device, h.Vsys, r.At.Reason.Text())
	case r.At.Check == "routing":
		// The address the hop looked up: after a destination NAT, the
		// translated one.
		dst := h.Flow.Destination
		if h.PostNAT != nil {
			dst = h.PostNAT.Destination
		}
		return at + fmt.Sprintf("no route to %s on %s", dst, h.Device)
	}
	var action string
	for _, c := range r.Hops[r.At.Hop-1].Checks {
		if c.Name == r.At.Check {
			action = CheckAction(c)
		}
	}
	return at + fmt.Sprintf("%s / %s, rule %s (%s)", h.Device, h.Vsys, r.At.Rule, action)
}

// CheckAction is the action of the rule, or default rule, that decided a
// check.
func CheckAction(c pathpolicy.CheckResult) string {
	switch v := c.Security; {
	case v == nil:
		return ""
	case v.Rule != nil:
		return v.Rule.Action
	}
	return c.Security.DefaultAction
}

// FileAnswer is the decision line of simulate policy on a file: the undecided
// line when candidates in doubt come first, else the first match, the default
// rule, or that no enabled rule matches.
func FileAnswer(v securitypolicy.Verdict) string {
	if len(v.Undecided) > 0 {
		return "undecided: " + v.Undecided.Text()
	}
	return DecisionLine(v, func(s string) string { return s })
}

// DecisionLine is the first-match line of a file answer, the rule's name
// passed through name: a renderer colours it. Behind candidates in doubt the
// first match is only the first certain one. It is "" when no line applies.
func DecisionLine(v securitypolicy.Verdict, name func(string) string) string {
	lead := "first match:"
	if len(v.Undecided) > 0 {
		lead = "first certain match:"
	}
	switch {
	case v.Rule != nil:
		return fmt.Sprintf("%s %s (%s)", lead, name(v.Rule.Name), v.Rule.Action)
	case v.Default != "":
		return fmt.Sprintf("%s %s (%s), default rule (%s)", lead, name(v.Default), v.DefaultAction, v.DefaultSource)
	case len(v.Candidates) == 0:
		return "no enabled rule matches"
	}
	return ""
}

// RoutingAnswer is a path's end line with its runs of spaces collapsed: the
// text aligns it in columns, the answer is one sentence.
func RoutingAnswer(p routing.Path) string {
	return strings.Join(strings.Fields(p.End), " ")
}

// NATAnswer is the NAT rule a packet hits and what it translates:
// "<rule>: destination 198.18.250.10:8443 -> 198.18.10.100:443", or that no
// NAT rule matches.
func NATAnswer(r nat.Result, f simulate.Flow) string {
	switch {
	case r.Dropped != "":
		return "no NAT rule matches: " + r.Dropped
	case r.Rule == nil:
		return "no NAT rule matches"
	}
	var parts []string
	if s := r.Source; s != nil {
		parts = append(parts, "source "+SourceTranslation(EndpointText(f.Source), s))
	}
	if d := r.Destination; d != nil {
		parts = append(parts, fmt.Sprintf("destination %s:%s -> %s", f.Destination, PortNumber(f.DestPort), DestinationTranslation(d, f.DestPort)))
	}
	if len(parts) == 0 {
		parts = append(parts, "no translation")
	}
	return r.Rule.Name + ": " + strings.Join(parts, "; ")
}

// EndpointText is an endpoint as the NAT answer names it.
func EndpointText(e simulate.Endpoint) string {
	if e.Name == "" && len(e.Addrs) == 0 {
		return "(no source)"
	}
	return e.String()
}

// PortNumber is a port, or "(any)" for none.
func PortNumber(p uint16) string {
	if p == 0 {
		return "(any)"
	}
	return strconv.Itoa(int(p))
}

// SourceTranslation is a source NAT: the source before, its candidates after,
// and how the port is kept.
func SourceTranslation(from string, t *nat.Translation) string {
	s := from + " -> " + strings.Join(t.Candidates, ", ")
	switch t.Port {
	case nat.PortRuntime:
		s += ", port assigned at runtime"
	case nat.PortUnchanged:
		s += ", port unchanged"
	}
	if len(t.Fallback) > 0 {
		s += "; fallback " + strings.Join(t.Fallback, ", ")
	}
	return s
}

// DestinationTranslation is a destination NAT's address and port after.
func DestinationTranslation(d *nat.Translation, port uint16) string {
	p := PortNumber(port)
	if d.Port != nat.PortUnchanged {
		p = d.Port
	}
	s := d.Address.String() + ":" + p
	if !d.Address.IsValid() {
		s = "(no address)"
	}
	if len(d.Others) > 0 {
		s += " (also " + strings.Join(d.Others, ", ") + ", by distribution)"
	}
	return s
}

// FindingAnswer is one search finding: where, what, and the field that names
// it.
func FindingAnswer(t Target, kind, name, field string) string {
	s := fmt.Sprintf("%s: %s %s", where(t.Device, t.Vsys), kind, name)
	if field != "" {
		s += " (" + field + ")"
	}
	return s
}

// LookupAnswer is one card found: where, and its kind and name.
func LookupAnswer(t Target, kind, name string) string {
	return fmt.Sprintf("%s: %s %s", where(t.Device, t.Vsys), kind, name)
}

// DiffAnswer counts one scope's changes.
func DiffAnswer(device, scope string, changes []drift.Change) string {
	added, removed, changed := countChanges(changes)
	return fmt.Sprintf("%s/%s: %d added, %d removed, %d changed", device, scope, added, removed, changed)
}

// countChanges counts changes by kind.
func countChanges(changes []drift.Change) (added, removed, changed int) {
	for _, c := range changes {
		switch c.Op {
		case drift.Added:
			added++
		case drift.Removed:
			removed++
		case drift.Changed:
			changed++
		}
	}
	return added, removed, changed
}

// searchCount is search's count line; lookupCount is lookup's. A limit adds
// how many results it shows (cut).
func searchCount(s *Summary, holes int) string {
	return fmt.Sprintf("%d with results, %d without, %d holes", s.With, s.Without, holes)
}

func lookupCount(s *Summary, holes int) string {
	return fmt.Sprintf("%d with it, %d without, %d holes", s.With, s.Without, holes)
}

// diffCount is snapshot diff's count line, over devices.
func diffCount(s *Summary, holes int) string {
	return fmt.Sprintf("%d with changes, %d without, %d holes", s.With, s.Without, holes)
}
