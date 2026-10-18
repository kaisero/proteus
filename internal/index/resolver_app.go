package index

import (
	"slices"
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
)

// appResolver answers the application value space, which a configuration can only
// partly describe.
//
// A custom application and an application group are in the file, and an application
// group's membership resolves through the ordinary group closure. Two kinds are not: an
// application filter selects predefined applications by their category, risk and
// behaviour, and an application container groups them, and all of that metadata lives in
// the content database a firewall downloads rather than in its configuration.
//
// With that content data in Providers.Apps, the resolver answers both: the filters
// that select an application and the containers that hold it are hits, and a rule
// naming one, or a group holding one, is a candidate. Without it their membership is
// reported, never guessed (spec 2026-10-16 §4.8).
//
// Naming a predefined application works either way, because a name is a name: asking
// for "ssl" finds the rules naming it through the ordinary name path.
type appResolver struct {
	custom  map[string]customApp // by lower-case name
	filters []resolve.ApplicationFilter
	tags    map[string][]string // application -> tags application-tag adds (S12)
	// The gaps without data: one per filter and one per container of the
	// configuration.
	filterGaps, containerGaps []Unresolved
}

// customApp is a custom application with its hit.
type customApp struct {
	hit Hit
	app appid.App
}

const kindApplication = "application"

// predefinedScope is the scope of a content application or container: the
// device defines them.
var predefinedScope = config.Scope{Sort: config.ScopePredefined}

func newAppResolver(custom []resolve.Application, filters []resolve.ApplicationFilter,
	tags map[string][]string, containers []resolve.Object,
) *appResolver {
	r := &appResolver{custom: map[string]customApp{}, filters: filters, tags: tags}
	for _, a := range custom {
		r.custom[strings.ToLower(a.Name)] = customApp{
			hit: Hit{Name: a.Name, Kind: kindApplication, Scope: a.Scope, Via: a.Name},
			app: a.App,
		}
	}
	for _, f := range filters {
		r.filterGaps = append(r.filterGaps, NewUnresolved(f.Name, "application-filter", reason.New("gap.application-filter",
			"an application filter selects predefined applications by category, risk "+
				"and behaviour, and that metadata is in the content database a firewall "+
				"downloads rather than in the configuration, so which applications it holds "+
				"cannot be determined here")))
	}
	for _, c := range containers {
		r.containerGaps = append(r.containerGaps, NewUnresolved(c.Name, "application-container", reason.New("gap.application-container",
			"an application container groups predefined applications, and its members "+
				"are in the content database rather than the configuration")))
	}
	return r
}

func (r *appResolver) kinds() []string {
	return []string{kindApplication, "application-group", "application-filter", "application-container"}
}

// resolve reports the application a name means, and, with the content data,
// the filters that select it and the containers that hold it. Each hit keeps
// the scope that defines it (AGENTS.md R5): a custom application or a filter
// its configured scope, a content application or a container the predefined
// scope.
//
// An application name has no distinguishing shape, so anything that is not plainly
// another kind of value is treated as one. Without data the limits are attached
// either way, because a rule naming a filter could match an application this cannot
// see. With data and without the containers, the container limits stay (§2.2).
func (r *appResolver) resolve(value string, p Providers) ([]Hit, []Unresolved, bool) {
	name := strings.TrimSpace(value)
	if name == "" || strings.ContainsAny(name, "/ ") {
		return nil, nil, false
	}
	var hits []Hit
	c, found := r.custom[strings.ToLower(name)]
	app := c.app
	if found {
		hits = append(hits, c.hit)
	}
	if p.Apps == nil {
		return hits, append(slices.Clone(r.filterGaps), r.containerGaps...), true
	}
	var limits []Unresolved
	if !p.Apps.HasContainers() {
		limits = slices.Clone(r.containerGaps)
	}
	if !found {
		// The device matches a flow's application without regard to case,
		// and content names are lower case (spec 2026-10-16 P14, F14): the
		// hit names the content name.
		a, ok := p.Apps.App(name)
		if !ok {
			return hits, limits, true
		}
		app = a
		hits = append(hits, Hit{Name: a.Name, Kind: kindApplication, Scope: predefinedScope, Via: "predefined"})
	}
	// A filter counts the tags application-tag adds (S12), and selects
	// custom applications too (S5).
	tagged := app
	tagged.Tags = append(slices.Clone(app.Tags), r.tags[app.Name]...)
	for _, f := range r.filters {
		if sel := f.Filter.Selects(tagged); sel.Selected {
			hits = append(hits, Hit{Name: f.Name, Kind: "application-filter", Scope: f.Scope, Via: sel.Via})
		}
	}
	// A container in a rule matches each of its functions (S9). The answer
	// is empty when the data lacks the containers.
	for _, cont := range p.Apps.ContainersOf(app.Name) {
		hits = append(hits, Hit{Name: cont, Kind: "application-container", Scope: predefinedScope, Via: "holds " + app.Name})
	}
	return hits, limits, true
}

// literalRules returns nothing: a rule's application field names applications.
func (r *appResolver) literalRules(Field, string) *roaring.Bitmap { return roaring.New() }

func (r *appResolver) search(substr string) []Hit {
	want := strings.ToLower(substr)
	var out []Hit
	for key, c := range r.custom {
		if strings.Contains(key, want) {
			out = append(out, c.hit)
		}
	}
	return out
}
