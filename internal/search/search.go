// Package search answers "where does this value or name appear" in one scope, as one
// list of findings in five stages: objects whose value holds the term, objects with
// that name, the groups holding either, the references naming any of them, and the
// rules that write the term directly into a field.
//
// Rules whose field is "any" reach every value, but no object or reference leads to
// them, so search leaves them out. Which rule traffic would hit is a simulation
// question. Spec §15 C4 to C6.
package search

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
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
	StageGroup     Stage = "group"
	StageReference Stage = "reference"
	StageLiteral   Stage = "literal"
)

// Stages lists every stage in order.
var Stages = []Stage{StageObject, StageGroup, StageReference, StageLiteral}

// Query is one search.
type Query struct {
	Term   string
	Mode   Mode
	Kinds  []string // objects and groups of these kinds only; empty means every kind
	Fields []string // references and literals from these fields only; empty means every field
	Show   []Stage  // these stages only; empty means every stage
	Direct bool     // groups one level up only

	// Providers supply what a configuration does not hold: the directory groups a
	// user belongs to, and the zones the device places an address in.
	Providers index.Providers
}

// Finding is one place the term appears.
type Finding struct {
	Stage Stage        `json:"stage"`
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

// Run searches one scope.
func Run(cfg *config.Config, idx *index.Index, q Query) ([]Finding, error) {
	s := &searcher{cfg: cfg, idx: idx, q: q, sc: idx.Scope()}
	s.term = parseTerm(q.Term)
	if q.Mode == Within && s.term.prefixes == nil {
		return nil, ErrWithinNeedsAddress
	}
	s.objects()
	s.groups()
	s.references()
	s.literals()
	return s.result(), nil
}

type searcher struct {
	cfg  *config.Config
	idx  *index.Index
	q    Query
	sc   config.Scope
	term term

	found  []Finding
	names  map[string]string // an object or group found, to its kind
	byName map[string][]string
}

// kindsByName maps every object name visible in the scope to its kinds, once.
func (s *searcher) kindsByName() map[string][]string {
	if s.byName != nil {
		return s.byName
	}
	s.byName = map[string][]string{}
	for _, k := range resolve.ObjectKinds(s.cfg) {
		objs := resolve.ObjectsInScope(s.cfg, s.sc, k)
		for _, o := range objs {
			s.byName[o.Name] = append(s.byName[o.Name], k)
		}
	}
	return s.byName
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
	if s.names == nil {
		s.names = map[string]string{}
	}
	s.names[name] = kind
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
			s.addObject(k, name, s.sc, "name")
		}
	}
}

// addressObjects matches an address, prefix or range term against address objects.
func (s *searcher) addressObjects() {
	for _, p := range s.term.prefixes {
		var ms []index.Match
		if s.term.single && s.q.Mode == Auto {
			ms = s.idx.Containing(p.Addr())
		} else {
			ms = s.idx.Overlapping(p)
		}
		for _, m := range ms {
			switch s.q.Mode {
			case Exact:
				if m.Prefix != p {
					continue
				}
			case Within:
				if m.Prefix.Bits() < p.Bits() || !p.Contains(m.Prefix.Addr()) {
					continue
				}
			}
			s.addObject("address", m.Name, m.Scope, m.Prefix.String())
		}
	}
}

// groups is stage 3: every group holding an object found.
func (s *searcher) groups() {
	members := make([]string, 0, len(s.names))
	for n := range s.names {
		members = append(members, n)
	}
	slices.Sort(members)
	for _, m := range members {
		var gs []string
		if s.q.Direct {
			gs = s.idx.DirectGroupsOf(m)
		} else {
			gs = s.idx.GroupsOf(m)
		}
		for _, g := range gs {
			kind := s.groupKind(g)
			if !s.kindAllowed(kind) {
				continue
			}
			if _, seen := s.names[g]; !seen {
				s.names[g] = kind
			}
			s.found = append(s.found, Finding{Stage: StageGroup, Kind: kind, Name: g, Scope: s.sc, Via: "holds " + m})
		}
	}
}

// groupKind names the kind of a group by the kinds its name is defined as, preferring
// a group kind.
func (s *searcher) groupKind(name string) string {
	kinds := s.kindsByName()[name]
	for _, k := range kinds {
		if strings.Contains(k, "group") {
			return k
		}
	}
	if len(kinds) > 0 {
		return kinds[0]
	}
	return "group"
}

// references is stage 4: every place that names an object or group found.
//
// A reference counts only when the field can name the found object's kind. A tag
// and an address group can share a name, and a tag field naming the tag does not
// name the group.
func (s *searcher) references() {
	names := make([]string, 0, len(s.names))
	for n := range s.names {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		kind := s.names[n]
		for _, r := range s.idx.Refs(n) {
			if !slices.Contains(r.Candidates, kind) || !s.fieldAllowed(r.Field) {
				continue
			}
			rk, rn := referrer(r.From)
			s.found = append(s.found, Finding{
				Stage: StageReference, Kind: rk, Name: rn, Scope: r.Scope,
				Field: r.Field, Via: r.Target, Path: r.From,
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
	single   bool           // one address
}

func parseTerm(s string) term {
	if a, err := netip.ParseAddr(s); err == nil {
		return term{prefixes: []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}, single: true}
	}
	if ps := index.PrefixesOf(s); len(ps) > 0 {
		return term{prefixes: ps}
	}
	return term{}
}
