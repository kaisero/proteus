package query

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/search"
)

// SearchInput is search: every place a value or name appears.
type SearchInput struct {
	Term string `json:"term" jsonschema:"the value or name to search for: an address, a prefix, a port or a name"`
	// Mode overrides the match the term's type sets: exact, within or contains.
	Mode string `json:"mode,omitempty" jsonschema:"exact, within or contains; empty lets the term's type decide"`
	// Kinds, Fields and Show narrow the findings; Direct keeps groups one level
	// up.
	Kinds  []string `json:"kinds,omitempty" jsonschema:"object kinds to search; empty for every kind"`
	Fields []string `json:"fields,omitempty" jsonschema:"rule fields to search; empty for every field"`
	Show   []string `json:"show,omitempty" jsonschema:"finding stages to show: objects, groups, refs, literals"`
	Direct bool     `json:"direct,omitempty" jsonschema:"follow groups one level up only"`
	// Selection is what the search runs against.
	Selection Selection `json:"selection" jsonschema:"the file or the devices to search"`
}

// searchModes are the modes a search takes, by name.
var searchModes = map[string]search.Mode{"exact": search.Exact, "within": search.Within, "contains": search.Contains}

// showNames are the stages a search shows, by name (spec 2026-09-27 §15 C6).
var showNames = map[string]search.Stage{
	"objects": search.StageObject, "groups": search.StageGroup,
	"refs": search.StageReference, "literals": search.StageLiteral,
}

// Validate holds search's input rules: one known mode, known stages to show, and
// a file without the store's selectors.
func (in SearchInput) Validate() *UsageError {
	if strings.TrimSpace(in.Term) == "" {
		return usage("give a search term", "")
	}
	if _, ok := searchModes[in.Mode]; !ok && in.Mode != "" {
		return usage(fmt.Sprintf("mode %q: want exact, within or contains", in.Mode), "")
	}
	for _, st := range in.Show {
		if _, ok := showNames[st]; !ok {
			return usage(fmt.Sprintf("--show %q: want objects, groups, refs or literals", st),
				fmt.Sprintf("show %q: want objects, groups, refs or literals", st))
		}
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
// and without one.
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
	users, err := env.users()
	if err != nil {
		return none, err
	}
	e := envelope[SearchInput, Finding]("search", in)
	e.Holes, e.Targets, e.Read, e.Summary = holes, ts, readOf(ts), &Summary{}
	matching := in.Matching()
	sets := indexSets{}
	for i, t := range ts {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		q.Providers = index.Providers{Users: users}
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
		fs, un, err := search.Run(t.Config, idx, q)
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
	un, notes := TargetQualifiers(ts)
	e.Unresolved, e.Notes = append(un, e.Unresolved...), notes
	return e, nil
}

// count adds one target's results.
func (s *Summary) count(n int) {
	s.Found += n
	if n > 0 {
		s.With++
	}
}
