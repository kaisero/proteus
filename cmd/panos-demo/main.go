// Command panos-demo walks every feature of the library against one configuration
// file and narrates what it does, so the results can be checked by hand against
// the device.
//
// Usage:
//
//	panos-demo <config.xml> [-v] [-probe <address>]
//
// -v prints the reasoning behind each answer, including the paths read and the
// intermediate sets. -probe picks the address used for the lookup sections; by
// default the demo chooses one from the configuration itself.
package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
)

// version is set at build time via -ldflags.
var version = "dev"

var verbose bool

func main() {
	v := flag.Bool("v", false, "explain each answer, not just report it")
	probe := flag.String("probe", "", "address to use for the lookup sections")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: panos-demo <config.xml> [-v] [-probe <address>]")
		os.Exit(2)
	}
	verbose = *v

	if err := run(flag.Arg(0), *probe); err != nil {
		fmt.Fprintf(os.Stderr, "panos-demo: %v\n", err)
		os.Exit(1)
	}
}

func run(path, probe string) error {
	cfg, err := sectionLoad(path)
	if err != nil {
		return err
	}
	sectionSchema(cfg)
	if err := sectionHierarchy(cfg); err != nil {
		return err
	}
	targets, err := sectionTargets(cfg)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("\nNo policy target in this configuration, so the remaining")
		fmt.Println("sections have nothing to work on.")
		return nil
	}
	tg := targets[0]
	if err := sectionPolicy(tg); err != nil {
		return err
	}
	objs, err := sectionObjects(tg)
	if err != nil {
		return err
	}
	if err := sectionGroups(cfg, tg); err != nil {
		return err
	}
	idx, err := sectionIndex(cfg, tg)
	if err != nil {
		return err
	}
	addr, ok := pickProbe(probe, objs, idx)
	if !ok {
		fmt.Println("\nNo address anywhere in this scope to probe with.")
		fmt.Println("Pass -probe to choose one.")
		return nil
	}
	sectionLookup(idx, addr)
	sectionWhereUsed(idx, objs)
	sectionSimulate(idx, addr, objs)
	sectionCaveats(idx)
	return nil
}

// ---- output helpers ----

func heading(n int, title string) {
	fmt.Printf("\n%s\n%d. %s\n%s\n", strings.Repeat("=", 74), n, title, strings.Repeat("=", 74))
}

func why(format string, args ...any) {
	if verbose {
		fmt.Printf("    ~ "+format+"\n", args...)
	}
}

// ---- the sections ----

func sectionLoad(path string) (*config.Config, error) {
	heading(1, "Loading the configuration")
	why("a configuration arrives bare from an export, or wrapped in")
	why("<response><result> from the XML API; both are accepted")
	why("the version is read from the <config> element itself; a Panorama file is refused")

	start := time.Now()
	cfg, rep, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	first := time.Since(start)

	start = time.Now()
	if _, _, err := config.Load(path); err != nil {
		return nil, err
	}
	second := time.Since(start)

	fmt.Printf("  file        %s\n", path)
	fmt.Printf("  version     %s (patch %s)\n", cfg.Version(), cfg.DetailVersion())
	if rep.VersionGap != "" {
		fmt.Printf("  warning: %s\n", rep.VersionGap)
	}
	fmt.Printf("  load time   %v first, %v second\n",
		first.Round(time.Microsecond), second.Round(time.Microsecond))
	why("the first load decodes the schema digest and builds the reference table;")
	why("both are immutable, so every later load in the process skips them")

	if rep.HasUnknown() {
		fmt.Printf("  untyped     %s\n", rep)
		why("an element the model does not know is preserved and counted, never dropped")
	} else {
		fmt.Printf("  untyped     none\n")
	}
	return cfg, nil
}

func sectionSchema(cfg *config.Config) {
	heading(2, "What the schema says about this configuration")
	why("the schema is PAN-OS's own, taken off an appliance and reduced to a digest")

	root := cfg.Root()
	kinds := []string{"address", "address-group", "service", "tag", "custom-url-category"}
	fmt.Println("  object counts, per scope in the file")
	for _, container := range append(
		root.Find("shared"),
		root.Find("devices", "entry", "vsys", "entry")...) {
		name := container.Attr("name")
		if name == "" {
			name = container.Name
		}
		var parts []string
		for _, k := range kinds {
			if n := len(container.Find(k, "entry")); n > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", k, n))
			}
		}
		if len(parts) > 0 {
			fmt.Printf("    %-22s %s\n", name, strings.Join(parts, " "))
		}
	}
}

func sectionHierarchy(cfg *config.Config) error {
	heading(3, "Scopes in this configuration")
	vs, err := resolve.Vsyses(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("  %d vsys: %v\n", len(vs), vs)
	why("each vsys is its own policy scope, and every vsys sees shared")
	return nil
}

func sectionTargets(cfg *config.Config) ([]*resolve.Target, error) {
	heading(4, "Policy targets")
	tgs, err := resolve.Targets(cfg)
	if err != nil {
		return nil, err
	}
	why("the key is device and vsys: a multi-vsys firewall holds one policy per vsys")
	fmt.Printf("  %d target(s)\n", len(tgs))
	for _, tg := range tgs {
		fmt.Printf("    %-22s %s\n", tg.Serial(), tg.Vsys())
		why("    inherits from %s", scopeList(tg.Chain()))
	}
	return tgs, nil
}

func sectionPolicy(tg *resolve.Target) error {
	heading(5, "Effective policy for "+tg.Serial()+"/"+tg.Vsys())
	why("order: shared pre, the vsys's own rules, shared post, then the defaults")
	why("source: PAN-OS documentation, Device Group Policies")

	rules, err := tg.Rules(resolve.Security)
	if err != nil {
		return err
	}
	fmt.Printf("  %d rule(s), in the order the firewall evaluates them\n", len(rules))
	for _, r := range rules {
		state := ""
		if r.Disabled {
			state = "  DISABLED"
		}
		fmt.Printf("   %3d. [%-11s %-18s] %-26s %-6s%s\n",
			r.Position, r.Layer, r.Scope, r.Name, r.Action, state)
		why("       src=%v dst=%v app=%v svc=%v",
			r.Fields["source"], r.Fields["destination"],
			r.Fields["application"], r.Fields["service"])
	}
	if len(rules) == 0 {
		fmt.Println("    none")
	}
	return nil
}

func sectionObjects(tg *resolve.Target) ([]resolve.Object, error) {
	heading(6, "Visible objects, and what they shadow")
	why("a scope sees shared, then each ancestor, then its own; a descendant")
	why("definition replaces an ancestor's of the same name, and that is reported")

	objs, err := tg.Objects("address")
	if err != nil {
		return nil, err
	}
	fmt.Printf("  %d address object(s)\n", len(objs))
	for _, o := range objs {
		shadow := ""
		if o.ShadowedFrom != nil {
			shadow = fmt.Sprintf("  shadows the one in %s", o.ShadowedFrom)
		}
		fmt.Printf("    %-26s %-20s %-18s tags=%v%s\n",
			o.Name, orNone(o.Value), o.Scope, o.Tags, shadow)
	}
	if len(objs) == 0 {
		fmt.Println("    none")
	}
	return objs, nil
}

func sectionGroups(cfg *config.Config, tg *resolve.Target) error {
	heading(7, "Address groups, static and dynamic")
	why("a static group lists members; a dynamic one carries a tag filter, and its")
	why("members are the objects visible in THIS scope whose tags satisfy it")

	groups, err := tg.Objects("address-group")
	if err != nil {
		return err
	}
	if len(groups) == 0 {
		fmt.Println("  none")
		return nil
	}
	for _, g := range groups {
		m, err := resolve.GroupInScope(cfg, tg.Scope(), g.Name)
		if err != nil {
			return err
		}
		switch {
		case m.FilterError != "":
			fmt.Printf("    %-26s dynamic, filter %s\n", g.Name, m.Filter)
			fmt.Printf("    %-26s UNREADABLE: %s\n", "", m.FilterError)
		case m.Filter != "":
			fmt.Printf("    %-26s dynamic %-24s -> %v\n", g.Name, m.Filter, m.ByTag)
			why("    resolved by tag within %s only", tg.Scope())
		default:
			fmt.Printf("    %-26s static  -> %v\n", g.Name, m.Static)
		}
	}
	return nil
}

func sectionIndex(cfg *config.Config, tg *resolve.Target) (*index.Index, error) {
	heading(8, "Building the index for "+tg.Scope().String())
	why("an index belongs to one scope, because a name means different things in")
	why("different scopes; building it globally would merge sibling vsys")

	start := time.Now()
	idx, err := index.For(cfg, tg.Scope())
	if err != nil {
		return nil, err
	}
	cold := time.Since(start)
	start = time.Now()
	if _, err := index.For(cfg, tg.Scope()); err != nil {
		return nil, err
	}
	warm := time.Since(start)

	fmt.Printf("  scope        %s\n", idx.Scope())
	fmt.Printf("  build time   %v first, %v cached\n",
		cold.Round(time.Microsecond), warm.Round(time.Nanosecond))
	fmt.Printf("  interned     %d name(s)\n", idx.Interner().Len())
	fmt.Printf("  rules        %d, disabled %d\n",
		len(idx.Rules()), idx.Disabled().GetCardinality())
	why("rule position is the bit index in a compressed bitmap, so the first")
	why("matching rule is the lowest set bit")
	return idx, nil
}

func sectionLookup(idx *index.Index, addr netip.Addr) {
	heading(9, "Reverse lookup from a value: "+addr.String())
	why("four steps, each composing into the next")

	fmt.Println("  step 1  objects whose value covers the address")
	var ids []uint32
	in := idx.Interner()
	covering := idx.Containing(addr)
	for _, m := range covering {
		fmt.Printf("            %-26s %-18s %s\n", m.Name, m.Prefix, m.Scope)
		ids = append(ids, in.ID(m.Name))
	}
	if len(covering) == 0 {
		fmt.Println("            none")
		why("no object holds it, but a rule may still name a literal that does")
	}

	fmt.Println("  step 2  groups holding those objects, to any depth")
	inAGroup := false
	for _, m := range covering {
		gs := idx.GroupsOf(m.Name)
		if len(gs) == 0 {
			continue
		}
		inAGroup = true
		fmt.Printf("            %-26s in %v\n", m.Name, gs)
		for _, g := range gs {
			ids = append(ids, in.ID(g))
		}
	}
	if !inAGroup {
		fmt.Println("            none")
	}
	why("static nesting and dynamic tag membership both count here")

	fmt.Println("  step 3  rules naming the object, any of those groups, or a")
	fmt.Println("          literal address that covers the probe")
	rules := idx.Rules()
	printed := false
	for _, f := range []index.Field{index.Source, index.Destination} {
		b := idx.RulesWith(f, ids...)
		lit := idx.RulesWithAddr(f, addr)
		why("    %s: %d by name, %d by literal", f, b.GetCardinality(), lit.GetCardinality())
		b.Or(lit)
		for it := b.Iterator(); it.HasNext(); {
			r := rules[it.Next()]
			fmt.Printf("            %3d. %-26s as %-11s [%s]\n", r.Position, r.Name, f, r.Layer)
			printed = true
		}
	}
	if !printed {
		fmt.Println("            none")
	}
}

func sectionWhereUsed(idx *index.Index, objs []resolve.Object) {
	heading(10, "Where a name is used")
	why("edges come from the schema's memberof declarations, so no field list is")
	why("hand-maintained; the path names the instance, not the schema location")

	shown := 0
	for _, o := range objs {
		refs := idx.Refs(o.Name)
		if len(refs) == 0 {
			continue
		}
		fmt.Printf("    %s\n", o.Name)
		for _, r := range refs {
			fmt.Printf("      %-14s %-12s %s\n", r.Scope, r.Field, r.From)
			why("      the schema allows these kinds here: %v", r.Candidates)
		}
		shown++
		if shown == 3 {
			break
		}
	}
	if shown == 0 {
		fmt.Println("    no object in this scope is referenced")
	}
}

func sectionSimulate(idx *index.Index, addr netip.Addr, objs []resolve.Object) {
	heading(11, "Which rule wins")
	dstAddr, dst := pickDestination(idx, objs)
	if !dstAddr.IsValid() {
		fmt.Println("  no usable destination in this scope")
		return
	}
	fmt.Printf("  %s -> %s (%s)\n", addr, dstAddr, dst)
	why("addresses only: application, service and zones are not evaluated")
	why("a rule whose field is 'any' matches every address, so those count too;")
	why("leaving them out returns the wrong winner, because an any-rule is usually")
	why("earlier in the rulebase than a specific one")

	// The library supplies each side: every rule the address can reach, by object,
	// by group, by literal, or because the field is any. The verdict below is the
	// caller's part.
	src := idx.CandidatesFor(index.Source, addr)
	dstB := idx.CandidatesFor(index.Destination, dstAddr)
	cand := roaring.And(src, dstB)
	before := cand.GetCardinality()
	cand.AndNot(idx.Disabled())
	why("%d candidate(s), %d after removing disabled rules",
		before, cand.GetCardinality())

	if cand.IsEmpty() {
		fmt.Println("    no enabled rule names both sides")
		return
	}
	rules := idx.Rules()
	for it := cand.Iterator(); it.HasNext(); {
		r := rules[it.Next()]
		fmt.Printf("    %3d. %-26s %-6s [%-11s %s]\n", r.Position, r.Name, r.Action, r.Layer, r.Scope)
	}
	first := rules[cand.Minimum()]
	fmt.Printf("  first match on addresses: %s (%s)\n", first.Name, first.Action)
	why("the lowest set bit, because PAN-OS takes the first match top to bottom")
}

func sectionCaveats(idx *index.Index) {
	heading(12, "What this answer does not cover")

	// A value the index cannot resolve must not come back as a bare rule list.
	// Demonstrated with a URL, because a rulebase using custom URL categories is
	// exactly where this used to mislead: the rules whose category is "any" came
	// back and looked like the answer.
	probe := "superlong.example.azureapps.microsoft.com"
	rules, rep := idx.Candidates(index.Category, probe)
	fmt.Printf("  asking which rules a URL reaches: %s\n", probe)
	fmt.Printf("    %d rule(s) returned\n", rules.GetCardinality())
	for _, u := range rep.Unresolved {
		fmt.Printf("    INCOMPLETE: %s\n", u)
	}
	fmt.Println()

	for _, u := range idx.UnparsedFilters() {
		fmt.Printf("  dynamic group %s: filter %s could not be read (%s)\n",
			u.Group, u.Filter, u.Reason)
	}
	fmt.Println("  - application, service and zones are not evaluated when simulating,")
	fmt.Println("    so the device may pick a different rule than the address match does")
	fmt.Println("  - group members registered at runtime by User-ID or VM monitoring")
	fmt.Println("    are not in a configuration file, so they are missing")
	fmt.Println("  - NAT rules are read but translated addresses are not resolved")
}

// pickDestination chooses a destination worth demonstrating: an address some rule
// actually names as its destination, so the simulation has something to find.
// Failing that, any address in the scope.
func pickDestination(idx *index.Index, objs []resolve.Object) (netip.Addr, string) {
	named := map[string]bool{}
	for _, r := range idx.Rules() {
		for _, d := range r.Fields["destination"] {
			named[d] = true
		}
	}
	// An object a rule names, or a group holding one.
	for _, o := range objs {
		hit := named[o.Name]
		if !hit {
			for _, g := range idx.GroupsOf(o.Name) {
				if named[g] {
					hit = true
					break
				}
			}
		}
		if !hit {
			continue
		}
		if a, ok := firstAddr(o.Value); ok {
			return a, o.Name + ", which a rule names"
		}
	}
	// A literal a rule names directly.
	for d := range named {
		if a, ok := firstAddr(d); ok {
			return a, d + ", a literal in a rule"
		}
	}
	for _, o := range objs {
		if a, ok := firstAddr(o.Value); ok {
			return a, o.Name
		}
	}
	return netip.Addr{}, ""
}

func firstAddr(value string) (netip.Addr, bool) {
	if p, err := netip.ParsePrefix(value); err == nil {
		return p.Addr(), true
	}
	if a, err := netip.ParseAddr(value); err == nil {
		return a, true
	}
	return netip.Addr{}, false
}

// pickProbe chooses the address to demonstrate with: the flag if given, then an
// address object in the scope, then a literal a rule names.
//
// The last case matters. A configuration can be written entirely with literal
// addresses and no objects at all, which is how the lab Panorama is written.
func pickProbe(flagValue string, objs []resolve.Object, idx *index.Index) (netip.Addr, bool) {
	if flagValue != "" {
		if a, ok := firstAddr(flagValue); ok {
			return a, true
		}
		return netip.Addr{}, false
	}
	sorted := make([]resolve.Object, len(objs))
	copy(sorted, objs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, o := range sorted {
		if a, ok := firstAddr(o.Value); ok {
			return a, true
		}
	}
	// No objects. Take a literal from a rule's source, which is what a
	// literal-only configuration offers.
	var literals []string
	for _, r := range idx.Rules() {
		literals = append(literals, r.Fields["source"]...)
	}
	sort.Strings(literals)
	for _, v := range literals {
		if a, ok := firstAddr(v); ok {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func scopeList(ss []config.Scope) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.String()
	}
	return strings.Join(out, " -> ")
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
