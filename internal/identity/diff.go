package identity

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// Change is one identity change between two snapshots (spec 2026-10-17
// §6.3).
type Change struct {
	// Op is added, removed or changed.
	Op string
	// Kind is user or source.
	Kind string
	// Name is the primary name of a user, or a source as a group source names
	// it: ldap:<profile> or cie:<profile>.
	Name string
	// Added and Removed are the groups and DUGs that a user gained and lost,
	// by name. An added user gained all its groups, and a removed user lost
	// them.
	Added, Removed []string
	// Old and New are the line of a removed or an added source, or the group
	// count of a source before and after.
	Old, New string
}

// The ops and the kinds of a change.
const (
	opAdded    = "added"
	opRemoved  = "removed"
	opChanged  = "changed"
	kindUser   = "user"
	kindSource = "source"
)

// Diff gives the identity changes from before to after, by kind and name
// (spec 2026-10-17 §6.3): per user, the groups and DUGs that it gained and
// lost, and the users that came and went; per source, the sources that came
// and went, and a change of the group count of a source. Users compare by
// primary name and groups by name, in any case (N1, M11, X2). Diff never
// compares mappings: the table changes all day (D9). Tags, alternate names,
// emails and the group list give no change either.
//
// A part that is missing in either snapshot gives no change: a part that did
// not arrive would show its entries as removed or added (PD19, SG8). The
// users need users.groups and users.names, the LDAP sources sources.ldap, and
// the CIE sources sources.cie. A nil side gives no change; the caller notes
// it (SG8).
func Diff(before, after *Data) []Change {
	if before == nil || after == nil {
		return nil
	}
	whole := func(parts ...string) bool {
		for _, p := range parts {
			if !before.Complete(p) || !after.Complete(p) {
				return false
			}
		}
		return true
	}
	var out []Change
	if whole(PartUserGroups, PartUserNames) {
		out = userChanges(before, after)
	}
	if whole(PartLDAP) {
		out = append(out, sourceChanges(ldapSources(before), ldapSources(after))...)
	}
	if whole(PartCIE) {
		out = append(out, sourceChanges(cieSources(before), cieSources(after))...)
	}
	slices.SortFunc(out, func(a, b Change) int {
		return cmp.Or(strings.Compare(a.Kind, b.Kind), byName(a.Name, b.Name))
	})
	return out
}

// userChanges gives the users that came and went, and the groups that a user
// of both gained and lost.
func userChanges(before, after *Data) []Change {
	var out []Change
	for _, u := range after.file.Users {
		i, ok := before.users[strings.ToLower(u.Name)]
		if !ok {
			out = append(out, Change{Op: opAdded, Kind: kindUser, Name: u.Name, Added: missingFrom(u.Groups, nil)})
			continue
		}
		was := before.file.Users[i].Groups
		added, removed := missingFrom(u.Groups, was), missingFrom(was, u.Groups)
		if len(added) > 0 || len(removed) > 0 {
			out = append(out, Change{Op: opChanged, Kind: kindUser, Name: u.Name, Added: added, Removed: removed})
		}
	}
	for _, u := range before.file.Users {
		if _, ok := after.users[strings.ToLower(u.Name)]; !ok {
			out = append(out, Change{Op: opRemoved, Kind: kindUser, Name: u.Name, Removed: missingFrom(u.Groups, nil)})
		}
	}
	return out
}

// missingFrom gives the names of a that b does not hold, in any case (M11,
// X2), each once, by name.
func missingFrom(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	for _, n := range b {
		seen[strings.ToLower(n)] = true
	}
	var out []string
	for _, n := range a {
		if k := strings.ToLower(n); !seen[k] {
			seen[k] = true
			out = append(out, n)
		}
	}
	slices.SortFunc(out, byName)
	return out
}

// source is one identity source as Diff compares it.
type source struct {
	name   string // ldap:<profile> or cie:<profile>
	line   string
	groups int
}

func ldapSources(d *Data) []source {
	var out []source
	for _, s := range d.file.Sources.LDAP {
		out = append(out, source{SourceLDAP + ":" + s.Name, sourceLine(s.Domain, s.Base, s.Groups), s.Groups})
	}
	return out
}

func cieSources(d *Data) []source {
	var out []source
	for _, s := range d.file.Sources.CIE {
		out = append(out, source{SourceCIE + ":" + s.Name, sourceLine(s.Domain, "", s.Groups), s.Groups})
	}
	return out
}

// sourceLine is the short line of a source, in the key=value form of drift:
// its domain and its base when the data knows them, and its group count.
func sourceLine(domain, base string, groups int) string {
	var fields []string
	if domain != "" {
		fields = append(fields, "domain="+domain)
	}
	if base != "" {
		fields = append(fields, "base="+base)
	}
	return strings.Join(append(fields, "groups="+strconv.Itoa(groups)), " ")
}

// sourceChanges gives the sources that came and went, and a change of the
// group count of a source of both. A profile name compares in exact case: it
// is the name of a configuration entry.
func sourceChanges(before, after []source) []Change {
	var out []Change
	for _, a := range after {
		i := slices.IndexFunc(before, func(b source) bool { return b.name == a.name })
		switch {
		case i < 0:
			out = append(out, Change{Op: opAdded, Kind: kindSource, Name: a.name, New: a.line})
		case before[i].groups != a.groups:
			out = append(out, Change{
				Op: opChanged, Kind: kindSource, Name: a.name,
				Old: strconv.Itoa(before[i].groups), New: strconv.Itoa(a.groups),
			})
		}
	}
	for _, b := range before {
		if !slices.ContainsFunc(after, func(a source) bool { return a.name == b.name }) {
			out = append(out, Change{Op: opRemoved, Kind: kindSource, Name: b.name, Old: b.line})
		}
	}
	return out
}
