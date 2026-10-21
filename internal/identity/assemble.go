package identity

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"
)

// Parts are the parsed answers of one fetch (spec 2026-10-17 §3.2).
type Parts struct {
	LDAP     []LDAPSource        // U6: statistics joined with state
	CIE      []CIESource         // U7
	UserIDs  map[string][]string // U3: primary name -> groups and DUGs
	Attrs    []Attributes        // U8
	Groups   []string            // U5: the full list
	DUGs     []string            // U5: the dynamic list
	Tags     []Tags              // U9
	Mappings []Mapping           // U1, every page
	// MappingsPartial: the fetch cut the table or read it while it moved
	// (SG13). Assemble copies it.
	MappingsPartial bool
	// Missing names the parts that did not arrive whole.
	Missing []string
}

// Domains are the domains of the identity sources, by profile name. The fetch
// reads them from the configuration of the snapshot (R1): the domain of a
// group-mapping profile (ruling Q1) and the domain of a CIE profile (SG2). A
// profile without one has an unknown domain.
type Domains struct {
	LDAP map[string]string
	CIE  map[string]string
}

// Assemble joins the parts of one fetch into an identity file taken at
// takenAt (spec 2026-10-17 §3.3, §4.1).
//
// It merges U3 and U8 by primary name, in any case; a user of U8 alone has
// no group and no DUG (D13). Each source takes its domain from domains, and a
// CIE profile without a domain makes sources.cie missing (SG2). Each group of
// U5 takes its source from Classify and counts the users whose groups hold
// it. The file lists users and groups by name, DUGs, tags by user and
// mappings by address, so it is stable whatever the order of the answers.
// Every name keeps its case.
func Assemble(p Parts, domains Domains, takenAt time.Time) File {
	missing := map[string]bool{}
	for _, m := range p.Missing {
		missing[m] = true
	}
	ldap := make([]LDAPSource, len(p.LDAP))
	for i, s := range p.LDAP {
		s.Domain = domains.LDAP[s.Name]
		ldap[i] = s
	}
	cie := make([]CIESource, len(p.CIE))
	for i, s := range p.CIE {
		s.Domain = domains.CIE[s.Name]
		if s.Domain == "" {
			missing[PartCIE] = true // SG2
		}
		cie[i] = s
	}
	slices.SortFunc(ldap, func(a, b LDAPSource) int { return byName(a.Name, b.Name) })
	slices.SortFunc(cie, func(a, b CIESource) int { return byName(a.Name, b.Name) })
	users := mergeUsers(p.UserIDs, p.Attrs)
	source := func(group string) string {
		return Classify(group, ldap, missing[PartLDAP], p.DUGs, cie, missing[PartCIE])
	}
	return withLists(File{
		Format:          Format,
		TakenAt:         takenAt.UTC(),
		Sources:         Sources{LDAP: ldap, CIE: cie},
		Users:           users,
		Groups:          groups(p.Groups, users, source),
		DUGs:            sortedNames(p.DUGs),
		Tags:            sortedTags(p.Tags),
		Mappings:        sortedMappings(p.Mappings),
		MappingsPartial: p.MappingsPartial,
		PartsMissing:    slices.Sorted(maps.Keys(missing)),
	})
}

// mergeUsers joins U3 and U8 by primary name, in any case (spec §3.3). The U3
// name stays; of two U3 lines of one user in two cases, the first in byte
// order. A user of U8 alone has no group and no DUG (D13). A name that a
// second line adds in another case only is the same name and goes.
func mergeUsers(ids map[string][]string, attrs []Attributes) []User {
	index := map[string]int{}
	var users []User
	for _, name := range slices.Sorted(maps.Keys(ids)) {
		k := strings.ToLower(name)
		if i, ok := index[k]; ok {
			users[i].Groups = appendNew(users[i].Groups, ids[name])
			continue
		}
		index[k] = len(users)
		users = append(users, User{Name: name, Groups: clone(ids[name])})
	}
	for _, a := range attrs {
		k := strings.ToLower(a.Primary)
		i, ok := index[k]
		if !ok {
			index[k] = len(users)
			users = append(users, User{Name: a.Primary, Email: a.Email, Alt: clone(a.Alt)})
			continue
		}
		u := &users[i]
		if u.Email == "" {
			u.Email = a.Email
		}
		u.Alt = appendNew(u.Alt, a.Alt)
	}
	slices.SortFunc(users, func(a, b User) int { return byName(a.Name, b.Name) })
	return users
}

// groups gives each group of U5 once, with its source and the number of
// users whose groups hold it, in any case (spec §4.1, M11, X2).
func groups(names []string, users []User, source func(string) string) []Group {
	members := map[string]int{}
	for _, u := range users {
		seen := map[string]bool{}
		for _, g := range u.Groups {
			k := strings.ToLower(g)
			if !seen[k] {
				seen[k] = true
				members[k]++
			}
		}
	}
	var out []Group
	listed := map[string]bool{}
	for _, name := range names {
		if listed[name] {
			continue
		}
		listed[name] = true
		out = append(out, Group{Name: name, Source: source(name), Members: members[strings.ToLower(name)]})
	}
	slices.SortFunc(out, func(a, b Group) int { return byName(a.Name, b.Name) })
	return out
}

// sortedNames is names by name, each once.
func sortedNames(names []string) []string {
	out := slices.Clone(names)
	slices.SortFunc(out, byName)
	return slices.Compact(out)
}

// sortedTags is the tags by user; each user keeps the order of its tags.
func sortedTags(in []Tags) []Tags {
	out := cloneWith(in, func(t Tags) Tags {
		t.Tags = slices.Clone(t.Tags)
		return t
	})
	slices.SortStableFunc(out, func(a, b Tags) int { return byName(a.User, b.User) })
	return out
}

// sortedMappings is the mappings by address, IPv4 first.
func sortedMappings(in []Mapping) []Mapping {
	out := slices.Clone(in)
	slices.SortStableFunc(out, func(a, b Mapping) int { return a.IP.Compare(b.IP) })
	return out
}

// byName orders names in any case, then by their bytes, so the order is
// total.
func byName(a, b string) int {
	return cmp.Or(strings.Compare(strings.ToLower(a), strings.ToLower(b)), strings.Compare(a, b))
}

// clone copies a list of names; an empty one becomes nil, as a file without
// the key reads.
func clone(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return slices.Clone(s)
}

// appendNew appends each name of add that list does not hold in any case.
func appendNew(list, add []string) []string {
	for _, v := range add {
		if !slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, v) }) {
			list = append(list, v)
		}
	}
	return list
}

// Classify gives the source of a group by its form, in the order of spec
// 2026-10-17 §3.3:
//
//   - a DN that ends with the base of an LDAP profile, in any case:
//     ldap:<profile>; the longest base wins. As observed on fw01, PAN-OS
//     11.2.5, every LDAP group with members is a DN that ends with the base
//     of its profile (U11), and a DN matches in any case (M11);
//   - a DN while sources.ldap is missing: ldap, an LDAP group of an unknown
//     profile (D9);
//   - a name of the dynamic list, in any case: dug. U4 reports a DUG with
//     source type xmlapi, so only the dynamic list tells it apart (U10);
//   - <domain>\<group> with the domain of a CIE profile, in any case:
//     cie:<profile>;
//   - <domain>\<group> while a CIE profile has no known domain, or while
//     sources.cie is missing: cie, a CIE group of an unknown profile (SG2,
//     ruling Q2);
//   - any other name: xmlapi.
//
// A short name <domain>\<cn> of an LDAP group has no rule here: the caller
// resolves it to its DN first (M12).
func Classify(group string, ldap []LDAPSource, ldapMissing bool, dugs []string, cie []CIESource, cieMissing bool) string {
	if isDN(group) {
		if profile, ok := ldapProfile(group, ldap); ok {
			return SourceLDAP + ":" + profile
		}
		if ldapMissing {
			return SourceLDAP
		}
	}
	if slices.ContainsFunc(dugs, func(d string) bool { return strings.EqualFold(d, group) }) {
		return SourceDUG
	}
	if domain, ok := domainOf(group); ok {
		unknown := cieMissing
		for _, c := range cie {
			switch {
			case c.Domain == "":
				unknown = true
			case strings.EqualFold(c.Domain, domain):
				return SourceCIE + ":" + c.Name
			}
		}
		if unknown {
			return SourceCIE
		}
	}
	return SourceXMLAPI
}

// ldapProfile names the profile whose base the DN ends with, in any case and
// at a part boundary; the longest base wins.
func ldapProfile(dn string, ldap []LDAPSource) (string, bool) {
	best, name := -1, ""
	for _, s := range ldap {
		if s.Base == "" || len(s.Base) <= best {
			continue
		}
		if strings.EqualFold(dn, s.Base) || hasSuffixFold(dn, ","+s.Base) {
			best, name = len(s.Base), s.Name
		}
	}
	return name, best >= 0
}

// hasSuffixFold reports whether s ends with suffix, in any case.
func hasSuffixFold(s, suffix string) bool {
	return len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix)
}

// isDN reports whether name is a DN: parts of the form <key>=<value> that
// commas split, such as cn=payroll,ou=groups,dc=example,dc=com (spec §3.3). A
// backslash escapes the next character, so an escaped comma belongs to its
// value. A key is a letter, then letters, digits and hyphens (RFC 4514).
func isDN(name string) bool {
	for _, part := range splitDN(name) {
		key, _, ok := strings.Cut(part, "=")
		if !ok || !attributeType(strings.TrimSpace(key)) {
			return false
		}
	}
	return true
}

// splitDN splits a DN at its commas; a backslash escapes the next character.
func splitDN(dn string) []string {
	var parts []string
	start, escaped := 0, false
	for i := range len(dn) {
		switch {
		case escaped:
			escaped = false
		case dn[i] == '\\':
			escaped = true
		case dn[i] == ',':
			parts = append(parts, dn[start:i])
			start = i + 1
		}
	}
	return append(parts, dn[start:])
}

// attributeType reports a key of a DN part: a letter, then letters, digits
// and hyphens.
func attributeType(key string) bool {
	for i, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && (r >= '0' && r <= '9' || r == '-'):
		default:
			return false
		}
	}
	return key != ""
}

// domainOf gives the domain of a name of the form <domain>\<group>. A domain
// holds no = and no comma, so a DN is no such name.
func domainOf(name string) (string, bool) {
	domain, group, ok := strings.Cut(name, `\`)
	if !ok || domain == "" || group == "" || strings.ContainsAny(domain, "=,") {
		return "", false
	}
	return domain, true
}
