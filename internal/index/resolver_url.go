package index

import (
	"strings"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/proteus/internal/resolve"
)

// urlResolver answers the URL value space: which custom URL categories cover a URL.
//
// A category name is not this resolver's business. Looking a name up is generic, and
// the index already did that correctly before any of this existed — the gap was
// always the value.
type urlResolver struct {
	exact      map[string][]Hit
	patterns   []patternHit
	unresolved []Unresolved
}

// patternHit pairs a wildcard member with the category it belongs to.
type patternHit struct {
	pattern resolve.URLPattern
	hit     Hit
	plain   bool // a member with no wildcard, also held in exact for search
}

const (
	kindCustomURLCategory = "custom-url-category"
	typeCategoryMatch     = "Category Match"
)

func newURLResolver(cats []resolve.Object) *urlResolver {
	r := &urlResolver{exact: map[string][]Hit{}}
	for _, c := range cats {
		// A "Category Match" category lists predefined PAN-DB categories rather than
		// URLs, and what those hold lives in Palo Alto's cloud database, not in the
		// configuration. Its membership is unknowable here, so it is reported rather
		// than guessed at.
		if strings.EqualFold(c.Subtype, typeCategoryMatch) {
			r.unresolved = append(r.unresolved, Unresolved{
				Value: c.Name,
				Kind:  kindCustomURLCategory,
				Reason: "a Category Match category lists predefined URL categories, whose " +
					"contents are in the PAN-DB cloud and not in the configuration, so a URL " +
					"cannot be matched against it",
			})
			continue
		}
		for _, m := range splitMembers(c.Value) {
			hit := Hit{Name: c.Name, Kind: kindCustomURLCategory, Scope: c.Scope, Via: m}
			p, err := resolve.ParseURLPattern(m)
			if err != nil {
				// A member this build cannot read contributes no match and is
				// reported, the same way an unreadable tag filter is.
				r.unresolved = append(r.unresolved, Unresolved{
					Value:  m,
					Kind:   kindCustomURLCategory,
					Reason: "in category " + c.Name + ": " + err.Error(),
				})
				continue
			}
			// A plain member still matches as a pattern: its path matches as a prefix,
			// so "example.com" covers "example.com/cart". Holding it only for exact
			// lookup matched nothing below the host.
			plain := isPlainURL(m)
			if plain {
				r.exact[strings.ToLower(p.Raw())] = append(r.exact[strings.ToLower(p.Raw())], hit)
			}
			r.patterns = append(r.patterns, patternHit{pattern: p, hit: hit, plain: plain})
		}
	}
	return r
}

func (r *urlResolver) kinds() []string { return []string{kindCustomURLCategory} }

func (r *urlResolver) resolve(value string, _ Providers) ([]Hit, []Unresolved, bool) {
	// A URL has a dot or a slash. Without one the value is a name, and the generic
	// name path handles it; matching it here would report every category as a hit
	// for a bare word.
	if !strings.ContainsAny(value, "./") {
		return nil, nil, false
	}
	var hits []Hit
	for _, p := range r.patterns {
		if p.pattern.Match(strings.TrimSpace(value)) {
			hits = append(hits, p.hit)
		}
	}
	return hits, r.unresolved, true
}

// literalRules returns nothing: a rule's category field names a category and never
// holds a URL itself.
func (r *urlResolver) literalRules(Field, string) *roaring.Bitmap { return roaring.New() }

// search finds a category by a fragment of one of its members. This is the case the
// category name limit creates: a name may be 31 characters and a member 255, so a long
// URL cannot be in the name of its category.
func (r *urlResolver) search(substr string) []Hit {
	want := strings.ToLower(substr)
	var out []Hit
	for value, hits := range r.exact {
		if strings.Contains(value, want) {
			out = append(out, hits...)
		}
	}
	for _, p := range r.patterns {
		if !p.plain && strings.Contains(strings.ToLower(p.pattern.Raw()), want) {
			out = append(out, p.hit)
		}
	}
	return out
}

// splitMembers undoes the joining that Object.Value does. A URL cannot contain a
// space, so the separator is unambiguous here.
func splitMembers(value string) []string {
	var out []string
	for m := range strings.SplitSeq(value, ", ") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// isPlainURL reports whether a member has no wildcard, so it can go in the map
// rather than the pattern list.
func isPlainURL(m string) bool {
	return !strings.ContainsAny(m, "*^")
}
