// Command panos-explore answers questions about a PAN-OS or Panorama
// configuration file, so the library can be tried without writing any Go.
//
// Usage:
//
//	panos-explore info      <config.xml>
//	panos-explore groups    <config.xml>
//	panos-explore target    <config.xml> <serial> <vsys>
//	panos-explore lookup    <config.xml> <scope> <value>
//	panos-explore whereused <config.xml> <scope> <name>
//	panos-explore simulate  <config.xml> <scope> <source> <destination>
//	panos-explore group     <config.xml> <scope> <name>
//
// A scope is shared, vsys:<name> or dg:<name>. A value is an IP address, a
// prefix, or an object name.
package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/go-panos-schema/config"
	"github.com/okaiser/go-panos-schema/index"
	"github.com/okaiser/go-panos-schema/resolve"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "info":
		err = withConfig(args, 0, cmdInfo)
	case "groups":
		err = withConfig(args, 0, cmdGroups)
	case "target":
		err = withConfig(args, 2, cmdTarget)
	case "lookup":
		err = withConfig(args, 2, cmdLookup)
	case "reaches":
		err = withConfig(args, 3, cmdReaches)
	case "search":
		err = withConfig(args, 2, cmdSearch)
	case "uses":
		err = withConfig(args, 2, cmdUses)
	case "whereused":
		err = withConfig(args, 2, cmdWhereUsed)
	case "simulate":
		err = withConfig(args, 3, cmdSimulate)
	case "group":
		err = withConfig(args, 2, cmdGroup)
	case "version", "-version", "--version":
		fmt.Println(version)
		return
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "panos-explore: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  panos-explore info      <config.xml>
  panos-explore groups    <config.xml>
  panos-explore target    <config.xml> <serial> <vsys>
  panos-explore lookup    <config.xml> <scope> <value>
  panos-explore reaches   <config.xml> <scope> <field> <value>
  panos-explore search    <config.xml> <scope> <substring>
  panos-explore uses      <config.xml> <scope> <category|url>
  panos-explore whereused <config.xml> <scope> <name>
  panos-explore simulate  <config.xml> <scope> <source> <destination>
  panos-explore group     <config.xml> <scope> <name>

A scope is shared, vsys:<name> or dg:<name>.
A field is source, destination, category, application, service, from, to,
source-user or tag.
`)
	os.Exit(2)
}

// withConfig loads the configuration named by the first argument and reports how
// long it took, then runs the command with the rest.
func withConfig(args []string, extra int, fn func(*config.Config, []string) error) error {
	if len(args) != 1+extra {
		usage()
	}
	start := time.Now()
	cfg, rep, err := config.Load(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("loaded %s in %v: PAN-OS %s (%s), %s\n",
		args[0], time.Since(start).Round(time.Microsecond),
		cfg.Version(), cfg.DetailVersion(), cfg.Platform())
	if rep.HasUnknown() {
		fmt.Printf("  note: %s\n", rep)
	}
	fmt.Println()
	return fn(cfg, args[1:])
}

func cmdInfo(cfg *config.Config, _ []string) error {
	h, err := resolve.NewHierarchy(cfg)
	if err != nil {
		return err
	}
	fmt.Println("device-group tree")
	for _, root := range h.Roots() {
		printTree(h, root, 1)
	}

	tgs, err := resolve.Targets(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("\nfirewalls (%d), keyed by serial and vsys\n", len(tgs))
	if len(tgs) == 0 {
		fmt.Println("  none assigned to a device group")
	}
	for _, tg := range tgs {
		rules, err := tg.Rules(resolve.Security)
		if err != nil {
			return err
		}
		fmt.Printf("  %s / %-8s -> %-20s stack %-12s %d effective rules\n",
			tg.Serial(), tg.Vsys(), tg.DeviceGroup(), tg.TemplateStack(), len(rules))
	}
	return nil
}

func printTree(h *resolve.Hierarchy, dg string, depth int) {
	fmt.Printf("  %s%s\n", strings.Repeat("  ", depth), dg)
	for _, c := range h.Children(dg) {
		printTree(h, c, depth+1)
	}
}

func cmdGroups(cfg *config.Config, _ []string) error {
	h, err := resolve.NewHierarchy(cfg)
	if err != nil {
		return err
	}
	var all []string
	var walk func(string)
	walk = func(dg string) {
		all = append(all, dg)
		for _, c := range h.Children(dg) {
			walk(c)
		}
	}
	for _, r := range h.Roots() {
		walk(r)
	}

	fmt.Println("effective policy per device group")
	for _, dg := range all {
		rules, err := resolve.RulesForDeviceGroup(cfg, dg, resolve.Security)
		if err != nil {
			return err
		}
		fmt.Printf("\n  %s (%d rules)\n", dg, len(rules))
		for _, r := range rules {
			fmt.Printf("    %2d. [%-11s %-16s] %-24s src=%v dst=%v\n",
				r.Position, r.Layer, r.Scope, r.Name, r.Fields["source"], r.Fields["destination"])
		}
	}
	return nil
}

func cmdTarget(cfg *config.Config, args []string) error {
	tg, err := resolve.TargetFor(cfg, args[0], args[1])
	if err != nil {
		return err
	}
	fmt.Printf("%s / %s\n", tg.Serial(), tg.Vsys())
	fmt.Printf("  device group   %s\n", tg.DeviceGroup())
	fmt.Printf("  template stack %s\n", tg.TemplateStack())
	fmt.Printf("  inherits from  %s\n\n", scopeList(tg.Chain()))

	rules, err := tg.Rules(resolve.Security)
	if err != nil {
		return err
	}
	fmt.Printf("effective security policy, in evaluation order (%d rules)\n", len(rules))
	for _, r := range rules {
		state := ""
		if r.Disabled {
			state = " DISABLED"
		}
		fmt.Printf("  %2d. [%-11s %-16s] %-24s %-6s src=%v dst=%v app=%v%s\n",
			r.Position, r.Layer, r.Scope, r.Name, r.Action,
			r.Fields["source"], r.Fields["destination"], r.Fields["application"], state)
	}

	objs, err := tg.Objects("address")
	if err != nil {
		return err
	}
	fmt.Printf("\nvisible address objects (%d)\n", len(objs))
	for _, o := range objs {
		shadow := ""
		if o.ShadowedFrom != nil {
			shadow = fmt.Sprintf("  (shadows the definition in %s)", o.ShadowedFrom)
		}
		fmt.Printf("  %-26s %-20s %-16s tags=%v%s\n", o.Name, o.Value, o.Scope, o.Tags, shadow)
	}
	return nil
}

// cmdLookup is the reverse lookup: from a value to the objects that hold it, the
// groups that hold those, and the rules that name any of them.
func cmdLookup(cfg *config.Config, args []string) error {
	sc, err := config.ParseScope(args[0])
	if err != nil {
		return err
	}
	value := args[1]

	idx, err := index.For(cfg, sc)
	if err != nil {
		return err
	}
	in := idx.Interner()

	fmt.Printf("looking up %q in %s\n\n", value, sc)

	// Step 1: from the value to the objects that cover it.
	var objs []string
	if addr, err := netip.ParseAddr(value); err == nil {
		fmt.Printf("1. objects whose value covers %s\n", addr)
		for _, m := range idx.Containing(addr) {
			fmt.Printf("     %-26s %-18s %s\n", m.Name, m.Prefix, m.Scope)
			objs = append(objs, m.Name)
		}
	} else if p, err := netip.ParsePrefix(value); err == nil {
		fmt.Printf("1. objects overlapping %s\n", p)
		for _, m := range idx.Overlapping(p) {
			fmt.Printf("     %-26s %-18s %s\n", m.Name, m.Prefix, m.Scope)
			objs = append(objs, m.Name)
		}
	} else {
		fmt.Printf("1. treating %q as an object name\n", value)
		objs = append(objs, value)
	}
	if len(objs) == 0 {
		fmt.Println("     none — but a rule may still name a literal that covers it")
	}

	// Step 2: from the objects up through every level of group nesting.
	ids := make([]uint32, 0, len(objs))
	if len(objs) > 0 {
		fmt.Println("\n2. groups holding them, transitively")
	}
	for _, o := range objs {
		ids = append(ids, in.ID(o))
		groups := idx.GroupsOf(o)
		if len(groups) == 0 {
			fmt.Printf("     %-26s in no group\n", o)
			continue
		}
		fmt.Printf("     %-26s in %v\n", o, groups)
		for _, g := range groups {
			ids = append(ids, in.ID(g))
		}
	}

	// Step 3: from the object or any of its groups to the rules, and from the
	// address itself to any rule naming a literal that covers it.
	fmt.Println("\n3. rules naming any of them, or naming a literal that covers the address")
	rules := idx.Rules()
	printed := false
	for _, f := range []index.Field{index.Source, index.Destination} {
		b := idx.RulesWith(f, ids...)
		if addr, err := netip.ParseAddr(value); err == nil {
			b.Or(idx.RulesWithAddr(f, addr))
		} else if p, err := netip.ParsePrefix(value); err == nil {
			b.Or(idx.RulesWithPrefix(f, p))
		}
		for it := b.Iterator(); it.HasNext(); {
			r := rules[it.Next()]
			fmt.Printf("     %2d. %-24s as %-11s [%s]\n", r.Position, r.Name, f, r.Layer)
			printed = true
		}
	}
	if !printed {
		fmt.Println("     none")
	}
	if bad := idx.UnparsedFilters(); len(bad) > 0 {
		fmt.Printf("\nnote: %d dynamic group filter(s) could not be read, so their members\n", len(bad))
		fmt.Println("      are missing from the groups above:")
		for _, u := range bad {
			fmt.Printf("      %s: %s\n", u.Group, u.Filter)
		}
	}
	return nil
}

func cmdWhereUsed(cfg *config.Config, args []string) error {
	sc, err := config.ParseScope(args[0])
	if err != nil {
		return err
	}
	name := args[1]
	idx, err := index.For(cfg, sc)
	if err != nil {
		return err
	}

	refs := idx.Refs(name)
	fmt.Printf("%d reference(s) to %q in %s\n", len(refs), name, sc)
	for _, r := range refs {
		fmt.Printf("  %-16s %-12s %s\n", r.Scope, r.Field, r.From)
		fmt.Printf("  %-16s %-12s could be: %v\n", "", "", r.Candidates)
	}
	if groups := idx.GroupsOf(name); len(groups) > 0 {
		fmt.Printf("\nalso a member of %v\n", groups)
	}
	if members := idx.MembersOf(name); len(members) > 0 {
		fmt.Printf("\nit is a group holding %v\n", members)
	}
	return nil
}

// cmdGroup resolves an address group in a scope, static members and tag-matched
// members alike. The same shared dynamic group resolves differently in different
// device groups, because only the visible scope contributes members.
func cmdGroup(cfg *config.Config, args []string) error {
	sc, err := config.ParseScope(args[0])
	if err != nil {
		return err
	}
	m, err := resolve.GroupInScope(cfg, sc, args[1])
	if err != nil {
		return err
	}
	fmt.Printf("%s in %s\n", args[1], sc)
	if m.Filter != "" {
		fmt.Printf("  dynamic, filter %s\n", m.Filter)
		fmt.Printf("  members matched by tag: %v\n", m.ByTag)
	} else {
		fmt.Printf("  static members: %v\n", m.Static)
	}
	fmt.Printf("  note: %s\n", m.Note)
	return nil
}

// cmdSimulate finds the first rule that matches a source and destination. PAN-OS
// evaluates top to bottom and takes the first match, so the lowest bit wins.
func cmdSimulate(cfg *config.Config, args []string) error {
	sc, err := config.ParseScope(args[0])
	if err != nil {
		return err
	}
	idx, err := index.For(cfg, sc)
	if err != nil {
		return err
	}

	fmt.Printf("simulating %s -> %s in %s\n\n", args[1], args[2], sc)

	// One call per side. The library knows the four ways a rule field can reach a
	// value; the verdict below is this command's part.
	srcRules, srcRep := idx.Candidates(index.Source, args[1])
	dstRules, dstRep := idx.Candidates(index.Destination, args[2])
	explain(srcRep)
	explain(dstRep)
	warn(append(srcRep.Unresolved, dstRep.Unresolved...))
	cand := roaring.And(srcRules, dstRules)
	cand.AndNot(idx.Disabled())
	if cand.IsEmpty() {
		fmt.Println("no enabled rule matches both sides")
		fmt.Println("note: application, service and zones are not evaluated, so the device")
		fmt.Println("      may still pick a rule this does not")
		return nil
	}
	rules := idx.Rules()
	fmt.Printf("candidates in evaluation order (%d)\n", cand.GetCardinality())
	for it := cand.Iterator(); it.HasNext(); {
		r := rules[it.Next()]
		fmt.Printf("  %2d. %-24s %-6s [%-11s %s]\n", r.Position, r.Name, r.Action, r.Layer, r.Scope)
	}
	first := rules[cand.Minimum()]
	fmt.Printf("\nfirst match on addresses: %s (%s)\n", first.Name, first.Action)
	fmt.Println("note: application, service and zones are not evaluated, so this is a")
	fmt.Println("      candidate set. The device may report no match, or a different rule.")
	return nil
}

// explain prints why a side matched, so the reasoning can be checked rather than
// trusted.
func explain(rep index.Report) {
	if len(rep.Hits) == 0 && len(rep.Groups) == 0 {
		return
	}
	fmt.Printf("%s matched via\n", rep.Value)
	for _, h := range rep.Hits {
		fmt.Printf("  %-24s %-14s %s\n", h.Name, h.Kind, h.Via)
	}
	for _, g := range rep.Groups {
		fmt.Printf("  %-24s %s\n", g, "group holding one of those")
	}
	fmt.Println()
}

// cmdReaches asks which rules one field could match one value, whatever kind of
// value it is: an address, a prefix, a URL, or the name of an object.
func cmdReaches(cfg *config.Config, args []string) error {
	sc, err := config.ParseScope(args[0])
	if err != nil {
		return err
	}
	field, ok := fieldByName(args[1])
	if !ok {
		return fmt.Errorf("unknown field %q", args[1])
	}
	idx, err := index.For(cfg, sc)
	if err != nil {
		return err
	}

	value := args[2]
	fmt.Printf("which rules could %s match %s, in %s\n\n", field, value, sc)

	rules, rep := idx.Candidates(field, value)
	warn(rep.Unresolved)
	explain(rep)

	if rules.IsEmpty() {
		fmt.Println("no rule could match it")
		return nil
	}
	all := idx.Rules()
	fmt.Printf("rules in evaluation order (%d)\n", rules.GetCardinality())
	for it := rules.Iterator(); it.HasNext(); {
		r := all[it.Next()]
		fmt.Printf("  %3d. %-26s %-6s [%-11s %s]\n", r.Position, r.Name, r.Action, r.Layer, r.Scope)
	}
	if rep.ViaAny {
		fmt.Printf("\nsome of those match only because their %s is \"any\"\n", field)
	}
	return nil
}

// cmdSearch finds objects by a fragment of their value, which is the only way to find
// one whose name cannot hold its own value.
func cmdSearch(cfg *config.Config, args []string) error {
	sc, err := config.ParseScope(args[0])
	if err != nil {
		return err
	}
	idx, err := index.For(cfg, sc)
	if err != nil {
		return err
	}
	hits := idx.SearchValues(args[1])
	fmt.Printf("%d object(s) whose value contains %q in %s\n", len(hits), args[1], sc)
	for _, h := range hits {
		fmt.Printf("  %-26s %-20s %-10s %s\n", h.Name, h.Kind, h.Scope, h.Via)
	}
	if len(hits) > 0 {
		fmt.Println("\nthis is a search, not a match: use reaches to ask what a rule would do")
	}
	return nil
}

// cmdUses shows which rules apply a security profile that mentions a URL category.
func cmdUses(cfg *config.Config, args []string) error {
	sc, err := config.ParseScope(args[0])
	if err != nil {
		return err
	}
	idx, err := index.For(cfg, sc)
	if err != nil {
		return err
	}
	uses := idx.ProfileUses(args[1])
	fmt.Printf("%d profile path(s) reaching %q in %s\n", len(uses), args[1], sc)
	for _, u := range uses {
		via := u.Via
		if via == "" {
			via = "by name"
		}
		group := u.Group
		if group == "" {
			group = "-"
		}
		fmt.Printf("  rule %-24s pos %-4d group %-14s profile %-22s %-9s %-22s %s\n",
			u.Rule, u.Position, group, u.Profile, u.List, u.Category, via)
	}
	if len(uses) > 0 {
		fmt.Println("\nthese are not matches. A rule matches on addresses, zones, application and")
		fmt.Println("service; its profile then inspects the request. What the profile does with a")
		fmt.Println("match is not derivable from the configuration, so no verdict is given here.")
	}
	return nil
}

// fieldByName reads a field name as the library spells it.
func fieldByName(name string) (index.Field, bool) {
	for _, f := range []index.Field{
		index.Source, index.Destination, index.Application, index.Service,
		index.FromZone, index.ToZone, index.Category, index.SourceUser, index.Tag,
	} {
		if f.String() == name {
			return f, true
		}
	}
	return 0, false
}

// warn prints what the library could not evaluate.
//
// An incomplete answer is printed before the result, not after it, because the
// result on its own looks complete.
func warn(us []index.Unresolved) {
	if len(us) == 0 {
		return
	}
	fmt.Println("INCOMPLETE: this answer is missing matches.")
	for _, u := range us {
		fmt.Printf("  %s\n", u)
	}
	fmt.Println()
}

func scopeList(ss []config.Scope) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.String()
	}
	return strings.Join(out, " -> ")
}
