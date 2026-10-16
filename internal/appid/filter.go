package appid

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// Filter is an application filter of the configuration.
type Filter struct {
	Name string
	// Criteria maps a filter field, as the configuration names it, to its
	// members. A flag holds ["yes"]. The tags are under tag, the name the
	// schema gives them below tagging; tagging, the name S10 uses, reads the
	// same. FilterField decides what a field reads.
	Criteria map[string][]string
	// Exclude names applications and containers the filter leaves out.
	Exclude []string
}

// Selection is the answer of a filter for one application.
type Selection struct {
	Selected bool
	// Via names the fields that select the application, in schema field
	// order: "category=media, risk=4" (spec 2026-10-16 §5.1). It is empty when
	// the filter does not select the application.
	Via string
}

// Selects reports whether the filter selects a. The caller adds to a.Tags the
// tags that application-tag gives a in the configuration: they count with the
// predefined tags (S12). a can be a custom application: a filter selects the
// custom applications that meet its criteria (S5).
//
// The facts are those measured on the lab VM, PAN-OS 12.1.9 (spec 2026-10-16
// S1-S15). Different fields combine with AND (S2). A field the package cannot
// read, or a field without members, selects nothing. Obsolete applications
// count as any other (S15). No lab fact covers a filter without criteria; the
// AND over no field holds for every application.
func (f Filter) Selects(a App) Selection {
	// exclude removes the named applications (S4). A container name removes
	// each of its functions (S13); a function names its container (F15).
	if slices.Contains(f.Exclude, a.Name) || a.Container != "" && slices.Contains(f.Exclude, a.Container) {
		return Selection{}
	}
	fields := make([]string, 0, len(f.Criteria))
	for k := range f.Criteria {
		if _, ok := filterIndex[k]; !ok {
			return Selection{}
		}
		fields = append(fields, k)
	}
	slices.SortFunc(fields, func(x, y string) int { return cmp.Compare(filterIndex[x], filterIndex[y]) })
	var via []string
	for _, field := range fields {
		matched, ok := criterion(field, f.Criteria[field], a)
		if !ok {
			return Selection{}
		}
		if matched != "" {
			via = append(via, field+"="+matched)
		}
	}
	return Selection{Selected: true, Via: strings.Join(via, ", ")}
}

// criterion reports whether a meets one field of a filter, and the text Via
// shows for it.
func criterion(field string, members []string, a App) (string, bool) {
	if field == "no-tag" {
		// tagging no-tag yes adds no restriction (S14).
		return "", true
	}
	if len(members) == 0 {
		return "", false
	}
	app := filterFields[filterIndex[field]].app
	switch {
	case app == "category" || app == "subcategory" || app == "technology" || app == "risk":
		// Values in one field combine with OR (S1).
		v := orValue(app, a)
		return v, v != "" && slices.Contains(members, v)
	case app == "tag":
		// Tags combine with AND and match verbatim, brackets included (S3,
		// F9).
		return all(members, func(m string) bool { return slices.Contains(a.Tags, m) })
	case field == "saas-risk":
		// The yes children of the saas block, with AND (S6, S11, F8).
		return all(members, func(m string) bool { return slices.Contains(a.SaaS.Risks, m) })
	case field == "saas-certifications":
		// The yes children of saas/certifications, with AND (S6, S11).
		// no-certifications selects the SaaS applications without a
		// certification; an application with is-saas yes and no saas block
		// has none (S6, F17).
		return all(members, func(m string) bool {
			if m == "no-certifications" {
				return a.Flags["is-saas"] && len(a.SaaS.Certifications) == 0
			}
			return slices.Contains(a.SaaS.Certifications, m)
		})
	default:
		// A flag selects the applications whose field holds yes (S7, S10).
		// The schema allows yes only.
		return all(members, func(m string) bool { return m == "yes" && a.Flags[app] })
	}
}

// orValue is the value of a field whose filter values combine with OR.
func orValue(app string, a App) string {
	switch app {
	case "category":
		return a.Category
	case "subcategory":
		return a.Subcategory
	case "technology":
		return a.Technology
	default:
		return strconv.Itoa(a.Risk)
	}
}

// all reports whether every member meets ok, with the members as Via text.
func all(members []string, ok func(string) bool) (string, bool) {
	for _, m := range members {
		if !ok(m) {
			return "", false
		}
	}
	return strings.Join(members, ","), true
}
