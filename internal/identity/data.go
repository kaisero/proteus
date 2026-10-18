package identity

import (
	"slices"
	"time"
)

// Data is the identity file of one snapshot. It is read-only once built
// (AGENTS.md R2), and it answers for one user or group at a time (R11, SG11).
type Data struct {
	file File
}

// New builds the Data of a file. It keeps its own copy of every list. It
// stores each group and tag name once: the groups of a user, the DUGs and the
// tags of a user point to that one copy, so a membership holds no copy of the
// name (spec 2026-10-17 §8).
func New(f File) *Data {
	names := map[string]string{}
	intern := func(s string) string {
		if c, ok := names[s]; ok {
			return c
		}
		names[s] = s
		return s
	}
	internAll := func(ss []string) []string {
		return cloneWith(ss, intern)
	}
	// The groups come first, so the names of groups[] are the copies that the
	// memberships point to.
	groups := cloneWith(f.Groups, func(g Group) Group {
		g.Name = intern(g.Name)
		return g
	})
	return &Data{file: File{
		Format:  f.Format,
		TakenAt: f.TakenAt,
		Sources: Sources{LDAP: slices.Clone(f.Sources.LDAP), CIE: slices.Clone(f.Sources.CIE)},
		Groups:  groups,
		DUGs:    internAll(f.DUGs),
		Users: cloneWith(f.Users, func(u User) User {
			u.Alt = slices.Clone(u.Alt)
			u.Groups = internAll(u.Groups)
			return u
		}),
		Tags: cloneWith(f.Tags, func(t Tags) Tags {
			t.Tags = internAll(t.Tags)
			return t
		}),
		Mappings:        slices.Clone(f.Mappings),
		MappingsPartial: f.MappingsPartial,
		PartsMissing:    slices.Clone(f.PartsMissing),
	}}
}

// cloneWith copies s, each element through f. A nil s stays nil.
func cloneWith[T any](s []T, f func(T) T) []T {
	if s == nil {
		return nil
	}
	out := make([]T, len(s))
	for i, v := range s {
		out[i] = f(v)
	}
	return out
}

// File returns the file of the data. Callers must not change its lists: they
// belong to the Data.
func (d *Data) File() File { return d.file }

// TakenAt is the time of the fetch that took the data.
func (d *Data) TakenAt() time.Time { return d.file.TakenAt }

// PartsMissing names the parts of the fetch that did not arrive whole, sorted
// (§3.4). The caller gets a copy.
func (d *Data) PartsMissing() []string { return slices.Clone(d.file.PartsMissing) }

// Counts are the sizes of the data, by which the MCP cache sizes it (§8).
type Counts struct {
	Users, Groups int
	// Memberships are the user-group pairs, the DUGs of a user among them
	// (D13).
	Memberships int
	Mappings    int
	Tags        int // the entries of U9: users with registered tags
}

// Counts counts the users, groups, memberships, mappings and tag entries.
func (d *Data) Counts() Counts {
	c := Counts{Users: len(d.file.Users), Groups: len(d.file.Groups), Mappings: len(d.file.Mappings), Tags: len(d.file.Tags)}
	for _, u := range d.file.Users {
		c.Memberships += len(u.Groups)
	}
	return c
}
