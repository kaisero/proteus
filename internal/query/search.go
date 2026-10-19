package query

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/estate"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/runlog"
	"github.com/kaisero/proteus/internal/search"
	"github.com/kaisero/proteus/internal/simulate"
)

// SearchInput is search: every place a value or name appears.
type SearchInput struct {
	Term string `json:"term" jsonschema:"the value or name to search for: an address, a prefix, a port, a name, an application, a user or a group"`
	// Mode overrides the match the term's type sets: exact, within or contains.
	Mode string `json:"mode,omitempty" jsonschema:"exact, within or contains; empty lets the term's type decide"`
	// Kinds, Fields and Show narrow the findings; Direct keeps groups one level
	// up.
	Kinds  []string `json:"kinds,omitempty" jsonschema:"object kinds to search; empty for every kind"`
	Fields []string `json:"fields,omitempty" jsonschema:"rule fields to search; empty for every field"`
	Show   []string `json:"show,omitempty" jsonschema:"finding stages to show: objects, identity, groups, refs, literals"`
	Direct bool     `json:"direct,omitempty" jsonschema:"follow groups one level up only"`
	// Selection is what the search runs against.
	Selection Selection `json:"selection" jsonschema:"the file or the devices to search"`
	ResultLimit
}

// searchModes are the modes a search takes, by name.
var searchModes = map[string]search.Mode{"exact": search.Exact, "within": search.Within, "contains": search.Contains}

// showNames are the stages a search shows, by name (spec 2026-09-27 §15 C6,
// spec 2026-10-17 §6.1).
var showNames = map[string]search.Stage{
	"objects": search.StageObject, "identity": search.StageIdentity, "groups": search.StageGroup,
	"refs": search.StageReference, "literals": search.StageLiteral,
}

// Validate holds search's input rules: one known mode, known stages to show, no
// limit below zero, and a file without the store's selectors.
func (in SearchInput) Validate() *UsageError {
	if strings.TrimSpace(in.Term) == "" {
		return usage("give a search term", "")
	}
	if _, ok := searchModes[in.Mode]; !ok && in.Mode != "" {
		return usage(fmt.Sprintf("mode %q: want exact, within or contains", in.Mode), "")
	}
	for _, st := range in.Show {
		if _, ok := showNames[st]; !ok {
			return usage(fmt.Sprintf("--show %q: want objects, identity, groups, refs or literals", st),
				fmt.Sprintf("show %q: want objects, identity, groups, refs or literals", st))
		}
	}
	if u := in.checkLimit(); u != nil {
		return u
	}
	return in.Selection.validateFile()
}

// validateFile refuses the store's selectors with a file: --file reads one
// configuration.
func (sel Selection) validateFile() *UsageError {
	if sel.File == "" {
		return nil
	}
	for _, f := range []struct {
		given bool
		flag  string
	}{{len(sel.Device) > 0, "device"}, {len(sel.Label) > 0, "label"}, {sel.At != "", "at"}, {sel.Fresh, "fresh"}} {
		if f.given {
			return usage(fmt.Sprintf("--%s selects from the store; --file reads one configuration", f.flag),
				f.flag+" selects from the store; file reads one configuration")
		}
	}
	return nil
}

// checkKinds refuses a kind that no selected configuration can hold, before
// any target runs: a misspelt kind would find nothing and read as an answer.
// The kinds a configuration can hold come from its schema digest; with several
// targets, a kind is valid when any of them knows it. The kinds of the stage
// identity come from the identity data, so every target knows them (spec
// 2026-10-17 §6.1).
func (in SearchInput) checkKinds(ts []estate.Target) *UsageError {
	if len(in.Kinds) == 0 || len(ts) == 0 {
		return nil
	}
	known := map[string]bool{search.KindIdentityUser: true, search.KindIdentityGroup: true, search.KindMapping: true}
	for _, t := range ts {
		for _, k := range resolve.ObjectKinds(t.Config) {
			known[k] = true
		}
	}
	var lines, toolLines []string
	for _, k := range in.Kinds {
		if known[k] {
			continue
		}
		hint := "no kind is close"
		if near := nearKinds(k, known); len(near) > 0 {
			hint = "did you mean " + strings.Join(near, ", ") + "?"
		}
		lines = append(lines, fmt.Sprintf("--kind %q: %s", k, hint))
		toolLines = append(toolLines, fmt.Sprintf("kind %q: %s", k, hint))
	}
	if len(lines) == 0 {
		return nil
	}
	list := "known kinds: " + strings.Join(slices.Sorted(maps.Keys(known)), ", ")
	return usage(strings.Join(append(lines, list), "\n"), strings.Join(append(toolLines, list), "\n"))
}

// nearKinds lists the known kinds closest to an unknown one, at most five: a
// kind that starts with it or that it starts with, or one at most two edits
// away. The closest come first.
func nearKinds(k string, known map[string]bool) []string {
	k = strings.ToLower(k)
	dist := map[string]int{}
	for c := range known {
		d := editDistance(k, c)
		if d <= 2 || strings.HasPrefix(c, k) || strings.HasPrefix(k, c) {
			dist[c] = d
		}
	}
	near := slices.SortedFunc(maps.Keys(dist), func(a, b string) int {
		return cmp.Or(cmp.Compare(dist[a], dist[b]), cmp.Compare(a, b))
	})
	return near[:min(len(near), 5)]
}

// editDistance is the Levenshtein distance of two strings, by byte.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// query is the search query the input asks.
func (in SearchInput) query() search.Query {
	q := search.Query{Term: in.Term, Kinds: in.Kinds, Fields: in.Fields, Direct: in.Direct, Mode: searchModes[in.Mode]}
	for _, st := range in.Show {
		q.Show = append(q.Show, showNames[st])
	}
	return q
}

// portTerm is a port, bare or with its protocol: 443, tcp/443.
var portTerm = regexp.MustCompile(`^((tcp|udp|sctp)/)?[0-9]+$`)

// nameShaped says whether a term has the shape of a name: no address, prefix
// or range, no port, and no slash or space. Only such a term can name an
// application, so only it loads the App-ID data (spec 2026-10-16 D11).
func nameShaped(term string) bool {
	return len(index.PrefixesOf(term)) == 0 && !portTerm.MatchString(term) && !strings.ContainsAny(term, "/ ")
}

// canonicalApp is the name of the application a term names in any case, and
// whether the term names one: the custom application's name as configured, or
// the content name (spec 2026-10-16 P14). Refs and the interner match names
// exactly, so the search runs on it (D17). Any other term stays as it is.
func canonicalApp(t estate.Target, apps *appid.Data, term string) (string, bool) {
	for _, a := range resolve.Applications(t.Config, t.Scope) {
		if strings.EqualFold(a.Name, term) {
			return a.Name, true
		}
	}
	if apps != nil {
		if a, ok := apps.App(term); ok {
			return a.Name, true
		}
	}
	return term, false
}

// Matching says how the term is matched: the mode asked, or what the term's type
// sets: covers, overlaps or matches.
func (in SearchInput) Matching() string {
	if in.Mode != "" {
		return in.Mode
	}
	switch ps := index.PrefixesOf(in.Term); {
	case len(ps) == 1 && ps[0].IsSingleIP(), portTerm.MatchString(in.Term):
		return "covers"
	case len(ps) > 0:
		return "overlaps"
	}
	return "matches"
}

// Finding is one finding with the target it came from. TargetIndex is the
// target's place in the envelope's Targets, for a renderer.
type Finding struct {
	Answer string `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Target
	search.Finding
	Scope string `json:"scope" jsonschema:"the configuration scope the result came from"`

	TargetIndex int `json:"-"`
}

// Detail is the last column of a finding's line: where it was found.
func Detail(f search.Finding) string {
	switch f.Stage {
	case search.StageReference:
		return f.Field + " -> " + f.Via
	case search.StageLiteral:
		return f.Field + " " + f.Via
	}
	return f.Via
}

// Search runs the query on each selected target. A target whose index cannot be
// built becomes a hole. The summary counts the findings and the targets with
// and without one. A limit keeps the first findings over all targets.
func Search(ctx context.Context, env Env, in SearchInput) (Envelope[SearchInput, Finding], error) {
	var none Envelope[SearchInput, Finding]
	if u := in.Validate(); u != nil {
		return none, u
	}
	q := in.query()
	ts, holes, err := Targets(ctx, env, in.Selection)
	if err != nil {
		return none, err
	}
	if u := in.checkKinds(ts); u != nil {
		return none, u
	}
	e := envelope[SearchInput, Finding]("search", in)
	e.Holes, e.Targets, e.Read, e.Summary = holes, ts, readOf(ts), &Summary{}
	matching := in.Matching()
	sets := indexSets{}
	for i, t := range ts {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		q.Providers = index.Providers{}
		if t.Snapshot != nil {
			if z, err := t.Snapshot.Zones(); err == nil {
				q.Providers.Zones = z
			}
		}
		idx, err := sets.of(t).Index(t.Scope, resolve.Security)
		if err != nil {
			e.Holes = append(e.Holes, estate.NewHole(t.Device, t.Vsys, reason.New("gap.load-failed", err.Error())))
			continue
		}
		q.Term = in.Term
		if nameShaped(in.Term) {
			var notes simulate.Reasons
			q.Providers.Apps, notes = appsFor(t, noAppDataSearch)
			// A copy: the target's notes may share their array with a cached load.
			ts[i].Notes = append(slices.Clone(t.Notes), notes...)
			q.Term, _ = canonicalApp(t, q.Providers.Apps, in.Term)
		}
		// The identity data loads for a term that can name a user, a group
		// or a mapped address, and else for a term the first search finds
		// nothing for (spec 2026-10-17 §4.2, PD10).
		withIdentity := func() {
			var notes simulate.Reasons
			q.Providers.Users, notes = identityFor(t, env.MaxAge, env.now())
			ts[i].Notes = append(slices.Clone(ts[i].Notes), notes...)
			q.Term = userTerm(t, q.Providers.Users, q.Providers.Apps, q.Term)
		}
		loaded := searchNeedsIdentity(in.Term, idx.Rules())
		if loaded {
			withIdentity()
		}
		fs, un, err := search.Run(t.Config, idx, q)
		if err == nil && len(fs) == 0 && !loaded {
			withIdentity()
			if q.Providers.Users != nil {
				fs, un, err = search.Run(t.Config, idx, q)
			}
		}
		if err != nil {
			// Only a term --within cannot read is the caller's to fix.
			if errors.Is(err, search.ErrWithinNeedsAddress) {
				return none, usageOf(err, "--within: "+err.Error(), "mode within: "+err.Error())
			}
			return none, err
		}
		env.Log.Infof(runlog.TagFind, "%s/%s: %d findings for %q (%s)", t.Device, t.Vsys, len(fs), q.Term, matching)
		for _, f := range fs {
			env.Log.Debugf(runlog.TagFind, "%s/%s: %s %s %s %s", t.Device, t.Vsys, f.Stage, f.Kind, f.Name, Detail(f))
			tg := TargetOf(t)
			e.Results = append(e.Results, Finding{
				Answer: FindingAnswer(tg, f.Kind, f.Name, f.Field), Target: tg, Finding: f, Scope: f.Scope.String(), TargetIndex: i,
			})
		}
		for _, u := range un {
			e.Unresolved = append(e.Unresolved, Unresolved{Device: t.Device, Vsys: t.Vsys, Value: u.Value, Reason: u.Reason, Code: u.Code})
		}
		e.Summary.count(len(fs))
	}
	e.Summary.Without = len(ts) - e.Summary.With
	e.Summary.Answer = searchCount(e.Summary, len(e.Holes))
	e.Notes = TargetNotes(ts)
	cut(&e, in.ResultLimit, "device, vsys or kind")
	return e, nil
}

// count adds one target's results.
func (s *Summary) count(n int) {
	s.Found += n
	if n > 0 {
		s.With++
	}
}
