package index

import (
	"strings"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/resolve"
)

// ProfileUse is one path from a rule to a URL category through its security
// profiles.
//
// A rule reaches a category two ways, and they mean different things. Its category
// field takes part in matching the rule. Its profile setting does not: the rule
// matches on addresses, zones, application and service, and only then does the URL
// filtering profile inspect the request. So this is not a match, and it is kept apart
// from the rule bitmaps for that reason.
//
// List names which action list the category sits in — block, alert, allow, continue,
// override. What the profile then does is deliberately not modelled: it depends on
// the response the site gives and on what the session carries, and neither is in a
// configuration file.
type ProfileUse struct {
	Rule     string
	Position int
	Group    string // the profile group, empty when the rule names the profile directly
	Profile  string
	List     string
	Category string
	Via      string // the category member that matched, empty for a query by name
	Scope    config.Scope
}

// profileIndex answers which rules apply a profile naming a category.
type profileIndex struct {
	// byCategory maps a category name to every path reaching it.
	byCategory map[string][]ProfileUse
}

func newProfileIndex(
	rules []resolve.Rule,
	profiles []resolve.URLFilteringProfile,
	groups []resolve.ProfileGroup,
) *profileIndex {
	byProfile := make(map[string]resolve.URLFilteringProfile, len(profiles))
	for _, p := range profiles {
		byProfile[p.Name] = p
	}
	byGroup := make(map[string]resolve.ProfileGroup, len(groups))
	for _, g := range groups {
		byGroup[g.Name] = g
	}

	idx := &profileIndex{byCategory: map[string][]ProfileUse{}}
	for _, r := range rules {
		// A rule names a profile group, or names profiles directly. Both reach the
		// same url-filtering profiles.
		for _, gname := range r.ProfileGroups {
			g, ok := byGroup[gname]
			if !ok {
				continue
			}
			for _, pname := range g.Kinds["url-filtering"] {
				idx.add(r, gname, byProfile[pname], pname)
			}
		}
		for _, pname := range r.Profiles["url-filtering"] {
			idx.add(r, "", byProfile[pname], pname)
		}
	}
	return idx
}

func (p *profileIndex) add(r resolve.Rule, group string, prof resolve.URLFilteringProfile, pname string) {
	for list, cats := range prof.Lists {
		for _, cat := range cats {
			if config.Keywords[cat] {
				continue
			}
			p.byCategory[cat] = append(p.byCategory[cat], ProfileUse{
				Rule:     r.Name,
				Position: r.Position,
				Group:    group,
				Profile:  pname,
				List:     list,
				Category: cat,
				Scope:    r.Scope,
			})
		}
	}
}

// ProfileUses returns the paths by which a rule's security profiles reach a URL
// category, for a category name or for a URL that one of its members covers.
//
// This answers a different question from Candidates. Candidates says which rules
// could match a value. This says which rules apply a profile that mentions it, which
// is how URL filtering is normally deployed: on a lab firewall every rule has
// "category any" and all URL policy runs through profile settings, so a
// category-field-only answer reports nothing about it.
func (i *Index) ProfileUses(value string) []ProfileUse {
	var out []ProfileUse
	if uses, ok := i.profiles.byCategory[value]; ok {
		// A query by category name.
		out = append(out, uses...)
	}
	// A query by URL: find the categories covering it, then the paths reaching those.
	if strings.ContainsAny(value, "./") {
		for _, r := range i.resolversFor(Category) {
			hits, _, _ := r.resolve(value, Providers{})
			for _, h := range hits {
				for _, u := range i.profiles.byCategory[h.Name] {
					u.Via = h.Via
					out = append(out, u)
				}
			}
		}
	}
	return out
}
