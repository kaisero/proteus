// Package search answers "where does this value or name appear" in one scope, as one
// list of findings in five stages: objects whose value holds the term, objects with
// that name, the groups holding either, the references naming any of them, and the
// rules that write the term directly into a field. With the identity data, a stage
// between the objects and the groups gives the users, groups and mapped addresses
// that the term names.
//
// Rules whose field is "any" reach every value, but no object or reference leads to
// them, so search leaves them out. Which rule traffic would hit is a simulation
// question. Spec §15 C4 to C6.
//
// With the App-ID content data in Query.Providers.Apps, an application term finds
// more (spec 2026-10-16 §5.1): the filters that select the application, with the
// fields that select it; the containers that hold it; the path through nested
// application groups; and the allow rules that reach it only through the implicit
// use of another application. Without the data the search is as before (§4.8).
//
// With the identity data in Query.Providers.Users, the stage identity gives the
// user of a user term, its groups with their source and its mapped addresses,
// the group of a group term, and the mapped user of one address (spec
// 2026-10-17 §6.1). The rules that name the user or a group come through the
// reference stage. Without the data the search is as before (§5.5).
package search

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/kaisero/proteus/internal/card"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/identity"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/resolve"
)

// Mode is how the term is matched against values. Spec §15 C5.
type Mode int

// The match modes. Auto lets the term's type decide.
const (
	Auto     Mode = iota
	Exact         // the value equals the term
	Within        // the value lies inside the term; addresses only
	Contains      // the value or name holds the term as text; not a match
)

// Stage is the step of the search a finding came from.
type Stage string

// The stages, in the order they run and print.
const (
	StageObject    Stage = "object"
	StageIdentity  Stage = "identity"
	StageGroup     Stage = "group"
	StageReference Stage = "reference"
	StageLiteral   Stage = "literal"
)

// Stages lists every stage in order.
var Stages = []Stage{StageObject, StageIdentity, StageGroup, StageReference, StageLiteral}

// The kinds of the findings of the stage identity (spec 2026-10-17 §6.1).
// A user and a group have the kinds of their lookup cards.
const (
	KindIdentityUser  = card.KindIdentityUser  // a user of the identity data
	KindIdentityGroup = card.KindIdentityGroup // a group or a DUG of the identity data
	KindMapping       = "mapping"              // a user-to-IP mapping, by its address
)

// Query is one search.
type Query struct {
	Term   string
	Mode   Mode
	Kinds  []string // objects and groups of these kinds only; empty means every kind
	Fields []string // references and literals from these fields only; empty means every field
	Show   []Stage  // these stages only; empty means every stage
	Direct bool     // groups one level up only

	// Providers supply what a configuration does not hold: the directory groups a
	// user belongs to, the zones the device places an address in, and the App-ID
	// content data.
	Providers index.Providers
}

// Finding is one place the term appears.
type Finding struct {
	Stage Stage        `json:"stage" jsonschema:"the stage the finding came from: object, identity, group, reference or literal"`
	Kind  string       `json:"kind"`
	Name  string       `json:"name"`
	Scope config.Scope `json:"-"`
	Field string       `json:"field,omitempty"`
	Via   string       `json:"via,omitempty"`
	Path  string       `json:"path,omitempty"`
}

// ErrWithinNeedsAddress is returned when Within is asked of a term that is not an
// address, a prefix or a range.
var ErrWithinNeedsAddress = errors.New("search: within mode needs an address, a prefix or a range")

// Run searches one scope. Unresolved lists the objects the term cannot decide:
// a wildcard address object that may hold addresses of a prefix term.
func Run(cfg *config.Config, idx *index.Index, q Query) ([]Finding, []index.Unresolved, error) {
	s := &searcher{cfg: cfg, idx: idx, q: q, sc: idx.Scope()}
	s.term = parseTerm(q.Term)
	if q.Mode == Within && s.term.prefixes == nil {
		return nil, nil, ErrWithinNeedsAddress
	}
	s.objects()
	s.identity()
	s.groups()
	s.references()
	s.implicitUse()
	s.literals()
	return s.result(), s.unresolved, nil
}

type searcher struct {
	cfg  *config.Config
	idx  *index.Index
	q    Query
	sc   config.Scope
	term term

	found      []Finding
	unresolved []index.Unresolved
	// names maps an object or group found to the kinds it was found as. A name
	// can have several: a tag and an address group, an address group and a
	// service group.
	names map[string]map[string]bool
}

// foundAs records a name as found with a kind.
func (s *searcher) foundAs(name, kind string) {
	if s.names == nil {
		s.names = map[string]map[string]bool{}
	}
	if s.names[name] == nil {
		s.names[name] = map[string]bool{}
	}
	s.names[name][kind] = true
}

// namesFound lists the names found, sorted.
func (s *searcher) namesFound() []string {
	return slices.Sorted(maps.Keys(s.names))
}

// kindsByName maps every object name visible in the scope to its kinds, each with
// the scope that defines the object of that kind: shared, predefined or the vsys.
// A namesake of another kind in a nearer scope hides an object (L9, L10).
func (s *searcher) kindsByName() map[string][]kindIn {
	out := map[string][]kindIn{}
	for _, k := range resolve.ObjectKinds(s.cfg) {
		for _, o := range resolve.ObjectsOfKindsInScope(s.cfg, s.sc, resolve.Namesakes(k)...)[k] {
			out[o.Name] = append(out[o.Name], kindIn{kind: k, scope: o.Scope})
		}
	}
	return out
}

// kindIn is a kind of object and the scope that defines the object.
type kindIn struct {
	kind  string
	scope config.Scope
}

func (s *searcher) kindAllowed(kind string) bool {
	return len(s.q.Kinds) == 0 || slices.Contains(s.q.Kinds, kind)
}

func (s *searcher) fieldAllowed(field string) bool {
	return len(s.q.Fields) == 0 || slices.Contains(s.q.Fields, field)
}

// addObject records an object found in stage 1 or 2, when its kind is allowed.
func (s *searcher) addObject(kind, name string, scope config.Scope, via string) {
	if !s.kindAllowed(kind) {
		return
	}
	s.foundAs(name, kind)
	s.found = append(s.found, Finding{Stage: StageObject, Kind: kind, Name: name, Scope: scope, Via: via})
}

// objects is stages 1 and 2: objects by value, then objects by name.
func (s *searcher) objects() {
	switch {
	case s.term.prefixes != nil && s.q.Mode != Contains:
		s.addressObjects()
	case s.q.Mode == Contains:
		for _, h := range s.idx.SearchValues(s.q.Term) {
			s.addObject(h.Kind, h.Name, h.Scope, h.Via)
		}
	case s.q.Mode == Exact:
		for _, h := range s.idx.SearchValues(s.q.Term) {
			if strings.EqualFold(h.Via, s.q.Term) {
				s.addObject(h.Kind, h.Name, h.Scope, h.Via)
			}
		}
	default:
		// Every value space the schema wires to a rule field answers for itself: a
		// port finds services, a URL finds categories, a user finds groups.
		view := s.idx.With(s.q.Providers)
		for f := index.Source; f <= index.Tag; f++ {
			_, rep := view.Candidates(f, s.q.Term)
			for _, h := range rep.Hits {
				s.addObject(h.Kind, h.Name, h.Scope, h.Via)
			}
		}
		s.groupForms()
	}
	for name, kinds := range s.kindsByName() {
		match := name == s.q.Term
		if s.q.Mode == Contains {
			match = strings.Contains(strings.ToLower(name), strings.ToLower(s.q.Term))
		}
		if !match {
			continue
		}
		for _, k := range kinds {
			s.addObject(k.kind, name, k.scope, "name")
		}
	}
}

// groupForms adds, for a term that names a group or a DUG of the identity
// data, the source-user members of the rules that name the same group in
// another form: a DN in another case and a short name <domain>\<cn>, as
// observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17 M11, M12). The user value
// space matches a group term by its text only, as it takes --user (Review
// focus 3), so search adds the other forms here; the reference stage then
// reaches their rules (§6.1).
func (s *searcher) groupForms() {
	d := s.q.Providers.Users
	if d == nil {
		return
	}
	g, ok := identityGroup(d, s.q.Term)
	if !ok {
		return
	}
	// A member that several rules name gives one finding: result drops the
	// repeats.
	for _, r := range s.idx.Rules() {
		for _, m := range r.Fields[index.SourceUser.String()] {
			mem := d.Member(m)
			if (mem.Kind == identity.MemberGroup || mem.Kind == identity.MemberDUG) && strings.EqualFold(mem.Name, g.Name) {
				kind := "user-group"
				if mem.Kind == identity.MemberDUG {
					kind = "dynamic-user-group"
				}
				s.addObject(kind, m, s.sc, s.groupVia(g))
			}
		}
	}
}

// identityGroup is the group of the identity data that a name names: a group
// of groups[] by its name in any case or by its short name, or a DUG of the
// dynamic list (spec 2026-10-17 §5.2).
func identityGroup(d *identity.Data, name string) (identity.Group, bool) {
	if g, ok := d.Group(name); ok {
		return g, true
	}
	if mem := d.Member(name); mem.Kind == identity.MemberDUG {
		return identity.Group{Name: mem.Name, Source: mem.Source, Members: -1}, true
	}
	return identity.Group{}, false
}

// identity is the stage identity (spec 2026-10-17 §6.1, PD13). With the
// identity data, one address gives its mapping, a user term the user, its
// groups and its mapped addresses, and a group term the group. A user or a
// group that the object stage found, by any form of its name, gives no
// finding: that finding already names it, with its source and member count.
// The rules come through the reference stage; a rule that names any,
// known-user, unknown or pre-logon is no finding (the user value space skips
// them). A text match of the directory is no question this stage answers.
func (s *searcher) identity() {
	d := s.q.Providers.Users
	if d == nil || s.q.Mode == Contains {
		return
	}
	if s.term.prefixes != nil {
		if s.term.single && len(s.term.prefixes) == 1 {
			if m, ok := d.Mapping(s.term.prefixes[0].Addr()); ok {
				s.addIdentity(KindMapping, m.IP.String(), mappingVia(m))
			}
		}
		return
	}
	shown := s.shownByObjects(d)
	mapped := s.q.Term
	if u, ok := d.User(s.q.Term); ok {
		mapped = u.Name
		if !shown[strings.ToLower(u.Name)] {
			s.addIdentity(KindIdentityUser, u.Name, "directory user")
		}
		for _, name := range u.Groups {
			if shown[strings.ToLower(name)] {
				continue
			}
			g, ok := d.Group(name)
			if !ok {
				g = s.unlistedGroup(d, name)
			}
			shown[strings.ToLower(name)] = true
			s.addIdentity(KindIdentityGroup, name, s.groupVia(g))
		}
	} else if g, ok := identityGroup(d, s.q.Term); ok && !shown[strings.ToLower(g.Name)] {
		s.addIdentity(KindIdentityGroup, g.Name, s.groupVia(g))
	}
	// A mapping keeps its user as the device stores it, so a user outside
	// the directory has mappings too, as observed on fw01, PAN-OS 11.2.5
	// (spec 2026-10-17 M2, M3).
	for _, m := range d.MappingsOf(mapped) {
		s.addIdentity(KindMapping, m.IP.String(), mappingVia(m))
	}
}

// shownByObjects is the users and groups that the object stage shows, in
// lower case: each by the name a rule writes, and by the name of the user or
// group of the data that the name names (M11, M12, N2). When Show hides the
// object stage, it shows none, and the stage identity shows them all.
func (s *searcher) shownByObjects(d *identity.Data) map[string]bool {
	shown := map[string]bool{}
	if len(s.q.Show) > 0 && !slices.Contains(s.q.Show, StageObject) {
		return shown
	}
	for _, f := range s.found {
		if f.Stage != StageObject || (f.Kind != "user" && f.Kind != "user-group" && f.Kind != "dynamic-user-group") {
			continue
		}
		shown[strings.ToLower(f.Name)] = true
		shown[strings.ToLower(d.Member(f.Name).Name)] = true
	}
	return shown
}

// addIdentity records a finding of the stage identity, when its kind is
// allowed.
func (s *searcher) addIdentity(kind, name, via string) {
	if s.kindAllowed(kind) {
		s.found = append(s.found, Finding{Stage: StageIdentity, Kind: kind, Name: name, Scope: s.sc, Via: via})
	}
}

// mappingVia names the user of a mapping as the device stores it, its type
// and its timeout (U1).
func mappingVia(m identity.Mapping) string {
	return fmt.Sprintf("user %s, %s, timeout %d s", m.User, m.Type, m.Timeout)
}

// groupVia names the source of a group and its member count, as the user
// value space names a group that a rule names (spec 2026-10-17 §6.1). A group
// that groups[] lacks counts the users whose groups hold it (U3), as the data
// counted them once (MemberCount).
func (s *searcher) groupVia(g identity.Group) string {
	if g.Members < 0 {
		g.Members = s.q.Providers.Users.MemberCount(g.Name)
	}
	return g.Source + ", " + identity.MembersText(g.Members)
}

// unlistedGroup is a group of a user that groups[] lacks, such as while the
// part groups is missing: its source by its form (§3.3), and its member count
// to come (groupVia).
func (s *searcher) unlistedGroup(d *identity.Data, name string) identity.Group {
	return identity.Group{Name: name, Source: d.GroupSource(name), Members: -1}
}

// addressObjects matches an address, prefix or range term against address objects.
func (s *searcher) addressObjects() {
	if s.q.Mode == Exact || s.q.Mode == Within {
		s.wholeObjects()
		s.wildcards()
		return
	}
	for _, p := range s.term.prefixes {
		var ms []index.Match
		if s.term.single {
			ms = s.idx.Containing(p.Addr())
		} else {
			ms = s.idx.Overlapping(p)
		}
		for _, m := range ms {
			s.addObject("address", m.Name, m.Scope, m.Prefix.String())
		}
	}
	s.wildcards()
}

// wholeObjects is Exact and Within: they compare an object's whole value with
// the term, not one piece of it. A range is stored as the prefixes that cover
// it, and one of them can match the term while the others lie outside it.
// Exact wants the same prefixes as the term; Within wants every prefix inside
// the term. Both are written as the fewest aligned prefixes, so an aligned
// prefix inside the term lies inside one of the term's.
func (s *searcher) wholeObjects() {
	pieces := map[string][]netip.Prefix{}
	values := map[string]string{}
	for _, o := range resolve.ObjectsInScope(s.cfg, s.sc, "address") {
		pieces[o.Name], values[o.Name] = index.PrefixesOf(o.Value), o.Value
	}
	seen := map[string]bool{}
	for _, p := range s.term.prefixes {
		for _, m := range s.idx.Overlapping(p) {
			if seen[m.Name] {
				continue
			}
			seen[m.Name] = true
			whole := pieces[m.Name]
			if !s.wholeMatch(whole) {
				continue
			}
			via := m.Prefix.String()
			if len(whole) > 1 {
				via = values[m.Name]
			}
			s.addObject("address", m.Name, m.Scope, via)
		}
	}
}

// wholeMatch says whether a whole value, as its prefixes, matches the term in
// Exact or Within mode: the same prefixes, or every prefix inside the term.
func (s *searcher) wholeMatch(whole []netip.Prefix) bool {
	if s.q.Mode == Exact {
		return slices.Equal(whole, s.term.prefixes)
	}
	return s.term.holds(whole)
}

// wildcards matches the term against the wildcard address objects, which match by
// mask. One address decides them. Any other term, or a mode that compares
// values, cannot: an object that may hold an address of the term is unresolved
// (owner decision C1).
func (s *searcher) wildcards() {
	if !s.kindAllowed("address") {
		return
	}
	hits, un := s.idx.MatchWildcards(s.term.prefixes, s.term.single && s.q.Mode == Auto)
	for _, h := range hits {
		s.addObject(h.Kind, h.Name, h.Scope, h.Via)
	}
	s.unresolved = append(s.unresolved, un...)
}

// groups is stage 3: every group holding an object found. A name found as
// several kinds is asked once per kind, and each kind finds only the groups that
// can hold it: an address group holds addresses, a service group services.
func (s *searcher) groups() {
	for _, m := range s.namesFound() {
		for _, k := range slices.Sorted(maps.Keys(s.names[m])) {
			for _, g := range s.idx.GroupsHolding(k, m, s.q.Direct) {
				if !s.kindAllowed(g.Kind) {
					continue
				}
				s.foundAs(g.Name, g.Kind)
				s.found = append(s.found, Finding{Stage: StageGroup, Kind: g.Kind, Name: g.Name, Scope: g.Scope, Via: "holds " + s.groupPath(g, m)})
			}
		}
	}
}

// groupPath is what a group holds, as its finding names it: the member, or,
// with the App-ID data, the path from an application group down to the member
// through nested groups, "outer > inner > ssl" (spec 2026-10-16 §5.1, S8).
// The other group kinds keep the member.
func (s *searcher) groupPath(g index.Group, member string) string {
	if s.q.Providers.Apps == nil || g.Kind != "application-group" {
		return member
	}
	// The group holds the member, so the path is never empty.
	return strings.Join(s.idx.GroupPath(g.Kind, g.Name, member), " > ")
}

// references is stage 4: every place that names an object or group found.
//
// A reference counts only when the field can name a kind the name was found as.
// A tag and an address group can share a name, and a tag field naming the tag
// does not name the group. When the name was found as several kinds, the finding
// says which kind the field names.
func (s *searcher) references() {
	for _, n := range s.namesFound() {
		kinds := s.names[n]
		for _, r := range s.idx.Refs(n) {
			if !s.fieldAllowed(r.Field) {
				continue
			}
			var named []string
			for _, k := range r.Candidates {
				if kinds[k] {
					named = append(named, k)
				}
			}
			if len(named) == 0 {
				continue
			}
			via := r.Target
			if len(kinds) > 1 {
				slices.Sort(named)
				via += " (" + strings.Join(named, ", ") + ")"
			}
			rk, rn := referrer(r.From)
			s.found = append(s.found, Finding{
				Stage: StageReference, Kind: rk, Name: rn, Scope: r.Scope,
				Field: r.Field, Via: via, Path: r.From,
			})
		}
	}
	if s.term.prefixes != nil || !s.fieldAllowed("profile-setting") {
		return
	}
	// A URL or a category reaches a rule through its security profiles too.
	for _, u := range s.idx.ProfileUses(s.q.Term) {
		via := u.Profile + " " + u.List + " " + u.Category
		if u.Group != "" {
			via = u.Group + " > " + via
		}
		s.found = append(s.found, Finding{
			Stage: StageReference, Kind: "security rule", Name: u.Rule, Scope: u.Scope,
			Field: "profile-setting", Via: via,
		})
	}
}

// implicitUse is the allow rules that reach the application only through the
// implicit use of another application: an allow rule also matches the
// implicit-use-applications of its applications, as measured on the lab VM,
// PAN-OS 12.1.9 (spec 2026-10-16 I1). A deny rule never matches implicitly
// (I5). The any-rules stay out, as everywhere in search, and so do the rules
// the explicit findings hold: an explicit match wins (I2). It needs the
// App-ID data and a term the value spaces read as it is.
func (s *searcher) implicitUse() {
	apps := s.q.Providers.Apps
	if apps == nil || s.q.Mode != Auto || !s.fieldAllowed(index.Application.String()) {
		return
	}
	explicit := map[string]bool{}
	for _, f := range s.found {
		if f.Stage == StageReference && f.Kind == "security rule" && f.Field == index.Application.String() {
			explicit[f.Scope.String()+"/"+f.Name] = true
		}
	}
	rules := s.idx.Rules()
	view := s.idx.With(s.q.Providers)
	for _, member := range apps.ImpliedBy(s.q.Term) {
		b, _ := view.Candidates(index.Application, member)
		b.AndNot(s.idx.RulesWithAny(index.Application))
		for it := b.Iterator(); it.HasNext(); {
			r := rules[it.Next()]
			if r.Action != "allow" || explicit[r.Scope.String()+"/"+r.Name] {
				continue
			}
			s.found = append(s.found, Finding{
				Stage: StageReference, Kind: "security rule", Name: r.Name, Scope: r.Scope,
				Field: index.Application.String(), Via: "implicit use by " + member,
			})
		}
	}
}

// referrer reads the kind and name of the entry a reference path ends in:
// .../rulebase/<type>/rules/<name> is a "<type> rule", anything else is the
// container the entry sits in.
func referrer(path string) (string, string) {
	seg := strings.Split(path, "/")
	n := len(seg)
	if n < 2 {
		return "entry", path
	}
	if n >= 4 && seg[n-2] == "rules" && seg[n-4] == "rulebase" {
		return seg[n-3] + " rule", seg[n-1]
	}
	return seg[n-2], seg[n-1]
}

// literals is stage 5: rules that write the term into a field, with no object.
// In Exact and Within mode a written value counts only as a whole.
func (s *searcher) literals() {
	if s.term.prefixes == nil || s.q.Mode == Contains {
		return
	}
	rules := s.idx.Rules()
	for _, f := range []index.Field{index.Source, index.Destination} {
		if !s.fieldAllowed(f.String()) {
			continue
		}
		for _, p := range s.term.prefixes {
			b := s.idx.RulesWithPrefix(f, p)
			if s.term.single {
				b = s.idx.RulesWithAddr(f, p.Addr())
			}
			for it := b.Iterator(); it.HasNext(); {
				r := rules[it.Next()]
				// Exact and Within take a written value whole, as for objects.
				if (s.q.Mode == Exact || s.q.Mode == Within) && !slices.ContainsFunc(r.Fields[f.String()], func(v string) bool {
					return s.wholeMatch(index.PrefixesOf(v))
				}) {
					continue
				}
				s.found = append(s.found, Finding{
					Stage: StageLiteral, Kind: "security rule", Name: r.Name, Scope: r.Scope,
					Field: f.String(), Via: strings.Join(r.Fields[f.String()], ", "),
				})
			}
		}
	}
}

// result drops the stages not asked for, removes duplicates and orders the rest by
// stage, kind and name.
func (s *searcher) result() []Finding {
	show := map[Stage]bool{}
	for _, st := range s.q.Show {
		show[st] = true
	}
	rank := map[Stage]int{}
	for i, st := range Stages {
		rank[st] = i
	}
	seen := map[string]bool{}
	var out []Finding
	for _, f := range s.found {
		if len(show) > 0 && !show[f.Stage] {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s|%s|%s|%s", f.Stage, f.Kind, f.Name, f.Scope, f.Field, f.Via)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		return cmp.Or(
			cmp.Compare(rank[a.Stage], rank[b.Stage]),
			cmp.Compare(a.Kind, b.Kind),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Field, b.Field),
		)
	})
	return out
}

// term is the search term, read once.
type term struct {
	prefixes []netip.Prefix // an address, prefix or range; nil otherwise
	single   bool           // one address: an address, a /32 or a range of one address
}

// holds says whether every prefix lies inside one of the term's.
func (t term) holds(ps []netip.Prefix) bool {
	for _, q := range ps {
		if !slices.ContainsFunc(t.prefixes, func(p netip.Prefix) bool {
			return p.Bits() <= q.Bits() && p.Contains(q.Addr())
		}) {
			return false
		}
	}
	return len(ps) > 0
}

func parseTerm(s string) term {
	ps := index.PrefixesOf(s)
	if len(ps) == 0 {
		return term{}
	}
	return term{prefixes: ps, single: len(ps) == 1 && ps[0].IsSingleIP()}
}
