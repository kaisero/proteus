package query

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/card"
	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/runlog"
)

// LookupInput is lookup: the whole rule or object a name refers to.
type LookupInput struct {
	Name string `json:"name" jsonschema:"the rule or object name"`
	// Kind picks one kind when several share the name: security-rule or an
	// object kind.
	Kind string `json:"kind,omitempty" jsonschema:"pick one kind when several share the name: security-rule or an object kind"`
	// Expand and Full shape the rendered card; the result always holds all of it.
	Expand bool `json:"expand,omitempty" jsonschema:"expand groups in the text card"`
	Full   bool `json:"full,omitempty" jsonschema:"show every field in the text card"`
	// Selection is what the lookup runs against.
	Selection Selection `json:"selection" jsonschema:"the file or the devices to read"`
}

// Validate holds lookup's input rules: a file without the store's selectors.
func (in LookupInput) Validate() *UsageError {
	if strings.TrimSpace(in.Name) == "" {
		return usage("give a name to look up", "")
	}
	return in.Selection.validateFile()
}

// LookupResult is one card with the target it came from. TargetIndex is the
// target's place in the envelope's Targets, for a renderer.
type LookupResult struct {
	Answer string `json:"answer" jsonschema:"one line that says what the result found, as the text output prints it"`
	Target
	Scope string    `json:"scope" jsonschema:"the configuration scope the result came from"`
	Card  card.Card `json:"card" jsonschema:"the rule or object with every field"`

	TargetIndex int `json:"-"`
}

// Lookup finds the element on each selected target. A name that means
// different kinds on different targets is a usage error: the caller has to pick
// one. The summary counts the cards and the targets with and without one.
func Lookup(ctx context.Context, env Env, in LookupInput) (Envelope[LookupInput, LookupResult], error) {
	var none Envelope[LookupInput, LookupResult]
	if u := in.Validate(); u != nil {
		return none, u
	}
	ts, holes, err := Targets(ctx, env, in.Selection)
	if err != nil {
		return none, err
	}
	e := envelope[LookupInput, LookupResult]("lookup", in)
	e.Holes, e.Targets, e.Summary = holes, ts, &Summary{}
	kinds := map[string][]string{} // kind -> where it was found
	sets := indexSets{}
	for i, t := range ts {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		idx, err := sets.of(t).Index(t.Scope, resolve.Security)
		if err != nil {
			e.Holes = append(e.Holes, estate.NewHole(t.Device, t.Vsys, reason.New("gap.load-failed", err.Error())))
			continue
		}
		cs, err := card.Find(t.Config, idx, in.Name, in.Kind)
		if err != nil {
			return none, usageOf(err, "--kind: "+err.Error(), "kind: "+err.Error())
		}
		var here []string
		for _, cd := range cs {
			here = append(here, cd.Kind)
			kinds[cd.Kind] = append(kinds[cd.Kind], where(t.Device, t.Vsys))
			tg := TargetOf(t)
			e.Results = append(e.Results, LookupResult{
				Answer: LookupAnswer(tg, cd.Kind, cd.Name), Target: tg, Scope: cd.Scope.String(), Card: cd, TargetIndex: i,
			})
		}
		e.Summary.count(len(cs))
		env.Log.Infof(runlog.TagFind, "%s/%s: lookup %q found %v", t.Device, t.Vsys, in.Name, here)
	}
	if len(kinds) > 1 {
		var lines []string
		for _, k := range slices.Sorted(maps.Keys(kinds)) {
			lines = append(lines, fmt.Sprintf("  %s on %s", k, strings.Join(kinds[k], ", ")))
		}
		list := strings.Join(lines, "\n")
		return none, usage(fmt.Sprintf("%q names more than one kind; pick one with --kind:\n%s", in.Name, list),
			fmt.Sprintf("%q names more than one kind; pick one with kind:\n%s", in.Name, list))
	}
	e.Summary.Without = len(ts) - e.Summary.With
	e.Summary.Answer = lookupCount(e.Summary, len(e.Holes))
	e.Unresolved, e.Notes = TargetQualifiers(ts)
	return e, nil
}

// where names a device's vsys, or the device alone.
func where(device, vsys string) string {
	if vsys == "" {
		return device
	}
	return device + "/" + vsys
}
