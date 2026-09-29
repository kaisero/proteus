package index

import (
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/resolve"
)

// appResolver answers the application value space, which a configuration can only
// partly describe.
//
// A custom application and an application group are in the file, and an application
// group's membership resolves through the ordinary group closure. Two kinds are not: an
// application filter selects predefined applications by their category, risk and
// behaviour, and an application container groups them, and all of that metadata lives in
// the content database a firewall downloads rather than in its configuration. Their
// membership is therefore reported, never guessed.
//
// Naming a predefined application still works, because a name is a name: asking for
// "ssl" finds the rules naming it through the ordinary name path.
type appResolver struct {
	custom  map[string]Hit
	limits  []Unresolved
	filters int
}

const kindApplication = "application"

func newAppResolver(apps, filters, containers []resolve.Object) *appResolver {
	r := &appResolver{custom: map[string]Hit{}}
	for _, a := range apps {
		r.custom[strings.ToLower(a.Name)] = Hit{
			Name: a.Name, Kind: kindApplication, Scope: a.Scope, Via: a.Name,
		}
	}
	for _, f := range filters {
		r.filters++
		r.limits = append(r.limits, Unresolved{
			Value: f.Name,
			Kind:  "application-filter",
			Reason: "an application filter selects predefined applications by category, risk " +
				"and behaviour, and that metadata is in the content database a firewall " +
				"downloads rather than in the configuration, so which applications it holds " +
				"cannot be determined here",
		})
	}
	for _, c := range containers {
		r.limits = append(r.limits, Unresolved{
			Value: c.Name,
			Kind:  "application-container",
			Reason: "an application container groups predefined applications, and its members " +
				"are in the content database rather than the configuration",
		})
	}
	return r
}

func (r *appResolver) kinds() []string {
	return []string{kindApplication, "application-group", "application-filter", "application-container"}
}

// resolve reports a custom application by name, and always reports the kinds whose
// membership is not in the file.
//
// An application name has no distinguishing shape, so anything that is not plainly
// another kind of value is treated as one. The limits are attached either way, because a
// rule naming a filter could match an application this cannot see.
func (r *appResolver) resolve(value string, _ Providers) ([]Hit, []Unresolved, bool) {
	name := strings.TrimSpace(value)
	if name == "" || strings.ContainsAny(name, "/ ") {
		return nil, nil, false
	}
	var hits []Hit
	if h, ok := r.custom[strings.ToLower(name)]; ok {
		hits = append(hits, h)
	}
	return hits, r.limitsCopy(), true
}

func (r *appResolver) limitsCopy() []Unresolved {
	return append([]Unresolved{}, r.limits...)
}

// literalRules returns nothing: a rule's application field names applications.
func (r *appResolver) literalRules(Field, string) *roaring.Bitmap { return roaring.New() }

func (r *appResolver) search(substr string) []Hit {
	want := strings.ToLower(substr)
	var out []Hit
	for key, h := range r.custom {
		if strings.Contains(key, want) {
			out = append(out, h)
		}
	}
	return out
}
