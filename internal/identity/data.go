package identity

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
)

// The two email decisions (spec 2026-10-17 §5.2, PD18). Each cites its fact,
// and TestEmailConstantsFollowTheFacts pins both.
const (
	// InputEmail: an email resolves to its user in --user and in a search
	// term, through Resolve. fw01, PAN-OS 11.2.5, could not show N7 in lab
	// round 3: every email there equals a UPN. So an email resolves, and an
	// answer whose user came from an email is inferred (PD21).
	InputEmail = true
	// RuleEmail: the email member of a rule resolves to its user, through
	// Member. No fact shows that the device resolves one (SG4, N7), so it
	// does not. It becomes true only on the owner's word.
	RuleEmail = false
)

// Data is the identity file of one snapshot. It is read-only once built
// (AGENTS.md R2), and it answers for one user or group at a time (R11, SG11).
//
// Its queries read names as the device compares them, in any case: user
// names (N1, X2) and group names (M11, X2). New builds their lower-case maps
// once. A query finds a name in a map; InGroup then reads the groups of one
// user, and only Members reads the groups of every user. MemberCount reads
// the count that New takes.
type Data struct {
	file File

	// The keys of the maps are lower case. An int is an index into a list of
	// the file.
	users  map[string]int      // primary name -> user
	alts   map[string]int      // alternate name -> user
	emails map[string]int      // email -> user
	held   map[string]int      // the groups and DUGs that U3 lists for the users -> their users
	groups map[string]int      // group name -> group
	cns    map[string][]int    // the cn of an LDAP group DN -> groups: the <cn> of a short name (M12)
	dugs   map[string]int      // DUG name -> DUG
	tags   map[string][]string // tag user -> the tags of every entry of the user (X2)
	mapped map[string][]int    // mapped user -> mappings, in address order
}

// New builds the Data of a file. It keeps its own copy of every list. It
// stores each group and tag name once: the groups of a user, the DUGs and the
// tags of a user point to that one copy, so a membership holds no copy of the
// name (spec 2026-10-17 §8). It sorts its copy of the mappings by address,
// as Assemble does; of two mappings of one address, the later one stays
// later. It builds the maps of the queries once.
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
	d := &Data{file: File{
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
		Mappings:        sortedMappings(f.Mappings),
		MappingsPartial: f.MappingsPartial,
		PartsMissing:    slices.Clone(f.PartsMissing),
	}}
	d.index()
	return d
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

// parts are the parts of a fetch (§3.2).
var parts = []string{PartLDAP, PartCIE, PartUserGroups, PartUserNames, PartGroups, PartTags, PartMappings}

// Complete reports whether a part of the fetch arrived whole: parts_missing
// does not name it, and for mappings, the fetch neither cut the table nor
// read it while it moved (spec 2026-10-17 §3.2, SG13). A name that is no part
// is never complete. The queries answer from the data that arrived; the
// caller keeps in doubt what a part that is not complete would judge (PD19).
func (d *Data) Complete(part string) bool {
	if !slices.Contains(parts, part) || (part == PartMappings && d.file.MappingsPartial) {
		return false
	}
	return !slices.Contains(d.file.PartsMissing, part)
}

// Counts are the sizes of the data, by which the MCP cache sizes it (§8).
type Counts struct {
	Users, Groups int
	// Memberships are the user-group pairs, the DUGs of a user among them
	// (D13).
	Memberships int
	Mappings    int
	Tags        int // the entries of U9: users with registered tags
	TagPairs    int // the user-tag pairs of U9: the tags of every entry
}

// Counts counts the users, groups, memberships, mappings, tag entries and
// user-tag pairs.
func (d *Data) Counts() Counts {
	c := Counts{Users: len(d.file.Users), Groups: len(d.file.Groups), Mappings: len(d.file.Mappings), Tags: len(d.file.Tags)}
	for _, u := range d.file.Users {
		c.Memberships += len(u.Groups)
	}
	for _, t := range d.file.Tags {
		c.TagPairs += len(t.Tags)
	}
	return c
}

// index builds the lower-case maps of the queries. Of two entries with one
// name in any case, the first in the file counts. It counts the users of each
// group that U3 lists: a user that lists a group in two cases counts once
// (M11).
func (d *Data) index() {
	d.users, d.alts, d.emails = map[string]int{}, map[string]int{}, map[string]int{}
	d.held = map[string]int{}
	counted := map[string]int{} // group -> the last user counted, plus one
	for i, u := range d.file.Users {
		first(d.users, u.Name, i)
		for _, a := range u.Alt {
			first(d.alts, a, i)
		}
		first(d.emails, u.Email, i)
		for _, g := range u.Groups {
			if k := strings.ToLower(g); counted[k] != i+1 {
				counted[k] = i + 1
				d.held[k]++
			}
		}
	}
	d.groups, d.cns = map[string]int{}, map[string][]int{}
	for i, g := range d.file.Groups {
		first(d.groups, g.Name, i)
		if cn, ok := ldapCN(g); ok {
			d.cns[cn] = append(d.cns[cn], i)
		}
	}
	d.dugs = map[string]int{}
	for i, g := range d.file.DUGs {
		first(d.dugs, g, i)
	}
	d.tags = map[string][]string{}
	for _, t := range d.file.Tags {
		k := strings.ToLower(t.User)
		d.tags[k] = appendTags(d.tags[k], t.Tags)
	}
	d.mapped = map[string][]int{}
	ms := d.file.Mappings
	for i, m := range ms {
		if i+1 < len(ms) && ms[i+1].IP == m.IP {
			continue // the later mapping of the address counts (Mapping)
		}
		k := strings.ToLower(m.User)
		d.mapped[k] = append(d.mapped[k], i)
	}
}

// first maps the name, in lower case, to i, unless an earlier entry holds
// the name. An empty name is no key: most users have no email.
func first(m map[string]int, name string, i int) {
	if name == "" {
		return
	}
	k := strings.ToLower(name)
	if _, ok := m[k]; !ok {
		m[k] = i
	}
}

// appendTags appends each tag of add that list does not hold. Tag names
// compare in exact case, as observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17
// M14).
func appendTags(list, add []string) []string {
	for _, t := range add {
		if !slices.Contains(list, t) {
			list = append(list, t)
		}
	}
	return list
}

// ldapCN gives the cn of an LDAP group, in lower case: the <cn> of its short
// name <domain>\<cn> (U4, M12). A group of another source, or a DN whose
// first part is no cn, has no short name.
func ldapCN(g Group) (string, bool) {
	if g.Source != SourceLDAP && !strings.HasPrefix(g.Source, SourceLDAP+":") {
		return "", false
	}
	key, value, _ := strings.Cut(splitDN(g.Name)[0], "=")
	if !strings.EqualFold(strings.TrimSpace(key), "cn") {
		return "", false
	}
	return strings.ToLower(value), true
}

// user finds the user of a name, in any case: by its primary name, then by
// an alternate name, then by its email when email holds. A primary name
// comes first, so the UPN of one user that is the email of another names the
// first user.
func (d *Data) user(name string, email bool) (int, bool) {
	k := strings.ToLower(name)
	if i, ok := d.users[k]; ok {
		return i, true
	}
	if i, ok := d.alts[k]; ok {
		return i, true
	}
	if email {
		i, ok := d.emails[k]
		return i, ok
	}
	return 0, false
}

// Resolve gives the primary name of a user of the data, as the device reads
// a user name (spec 2026-10-17 §5.2, D7). A primary name or an alternate name
// gives it, in any case: as observed on fw01, PAN-OS 11.2.5, a rule matches
// the primary name in any case (N1), and a UPN resolves to the primary name
// (N2). An email gives it while InputEmail holds (N7, PD21). A name of no
// user gives nothing: U8 by the NetBIOS form example\alice answers nothing
// (N5), and a mapped user outside the directory is no user of the data (M2,
// M3). --user, a search term and User take this one rule (PD18).
func (d *Data) Resolve(name string) (string, bool) {
	i, ok := d.user(name, InputEmail)
	if !ok {
		return "", false
	}
	return d.file.Users[i].Name, true
}

// User gives the user of a name: Resolve gives its primary name, which names
// the user (PD18). The caller gets a copy.
func (d *Data) User(name string) (User, bool) {
	primary, ok := d.Resolve(name)
	if !ok {
		return User{}, false
	}
	u := d.file.Users[d.users[strings.ToLower(primary)]]
	u.Alt = slices.Clone(u.Alt)
	u.Groups = slices.Clone(u.Groups)
	return u, true
}

// GroupsOf gives the groups and the DUGs of a primary name, in any case
// (N1), in the order of U3: U3 holds every group of a user, nested groups
// and DUGs among them (U3, X3, D13). Any other name gives nil: as observed on
// fw01, PAN-OS 11.2.5, a mapping in the stored form example\alice matches no
// group (spec 2026-10-17 M2). The caller resolves an alternate name first.
// The caller gets a copy.
func (d *Data) GroupsOf(user string) []string {
	i, ok := d.users[strings.ToLower(user)]
	if !ok {
		return nil
	}
	return slices.Clone(d.file.Users[i].Groups)
}

// InGroup reports whether the groups of a primary name hold a group or a DUG
// (spec 2026-10-17 §5.3). Both compare in any case, as observed on fw01,
// PAN-OS 11.2.5: a DN in another case names the same group (M11), and an XML
// API group and a DUG match the primary name in any case (X2). DUG membership
// comes from U3 only, so a user that U3 does not list is in no DUG (D13). The
// group of a short name is the group of its DN (M12).
func (d *Data) InGroup(user, group string) bool {
	i, ok := d.users[strings.ToLower(user)]
	return ok && holds(d.file.Users[i].Groups, d.groupName(group))
}

// holds reports whether groups hold the group, in any case (M11, X2).
func holds(groups []string, group string) bool {
	return slices.ContainsFunc(groups, func(g string) bool { return strings.EqualFold(g, group) })
}

// Group gives the group of groups[] that a name names: by its name, in any
// case, so also a DN in another case (M11); or by its short name
// <domain>\<cn>, as observed on fw01, PAN-OS 11.2.5: a rule that names the
// short name matches the members of the group (spec 2026-10-17 M12). A short
// name that the data cannot resolve gives no group.
func (d *Data) Group(name string) (Group, bool) {
	if i, ok := d.groups[strings.ToLower(name)]; ok {
		return d.file.Groups[i], true
	}
	if i, s := d.shortName(name); s == shortResolved {
		return d.file.Groups[i], true
	}
	return Group{}, false
}

// groupName gives the name of the group that a name names (Group), else the
// name itself: U3 can hold a group that groups[] lacks (§5.5).
func (d *Data) groupName(name string) string {
	if g, ok := d.Group(name); ok {
		return g.Name
	}
	return name
}

// Members gives the primary names of the users whose groups hold a group, in
// any case (U3, M11, X2), in name order. The group is a name, a DN in any
// case or a short name (Group). A DUG holds the users that U3 lists in it
// (D13).
func (d *Data) Members(group string) []string {
	name := d.groupName(group)
	var out []string
	for _, u := range d.file.Users {
		if holds(u.Groups, name) {
			out = append(out, u.Name)
		}
	}
	slices.SortFunc(out, byName)
	return out
}

// MemberCount is the number of users that Members gives for a group, without
// the list: New counts them once (spec 2026-10-17 §8).
func (d *Data) MemberCount(group string) int {
	return d.held[strings.ToLower(d.groupName(group))]
}

// TagsOf gives the registered tags of a user, by the user name of the
// registration in any case, as observed on fw01, PAN-OS 11.2.5 (spec
// 2026-10-17 M8, X2). Two entries of one user in two cases give the tags of
// both. The tags feed lookup only: DUG membership comes from U3 (D13). The
// caller gets a copy.
func (d *Data) TagsOf(user string) []string {
	return slices.Clone(d.tags[strings.ToLower(user)])
}

// Mapping gives the mapping of an address (U1); an IPv6 address is found by
// its address too. Of two mappings of one address, the later one counts, as
// the fetch keeps the later entry of an address (spec 2026-10-17 §3.2). The
// user of a mapping is as the device stores it (M2, N4).
func (d *Data) Mapping(ip netip.Addr) (Mapping, bool) {
	ms := d.file.Mappings
	j := sort.Search(len(ms), func(k int) bool { return ms[k].IP.Compare(ip) > 0 })
	if j == 0 || ms[j-1].IP != ip {
		return Mapping{}, false
	}
	return ms[j-1], true
}

// MappingsOf gives the mappings of a user, by the stored name in any case, in
// address order with IPv4 first. It does not resolve the name: as observed on
// fw01, PAN-OS 11.2.5, a mapping in the stored form example\alice is no
// mapping of example.com\alice (spec 2026-10-17 M2). A mapping that a later
// mapping of its address replaces is no mapping of its user (Mapping).
func (d *Data) MappingsOf(user string) []Mapping {
	var out []Mapping
	for _, i := range d.mapped[strings.ToLower(user)] {
		out = append(out, d.file.Mappings[i])
	}
	return out
}

// Known reports whether a name is a user, a group or a mapped user of the
// data, in any case: a name that Resolve resolves, a group that Group finds,
// a group or a DUG that U3 lists for a user, or the stored user of a mapping
// (M3, M17). search takes such a term as a user term, also when its shape is
// no user shape, such as a group DN with spaces (spec 2026-10-17 §6.1).
func (d *Data) Known(name string) bool {
	if _, ok := d.Resolve(name); ok {
		return true
	}
	if _, ok := d.Group(name); ok {
		return true
	}
	k := strings.ToLower(name)
	_, mapped := d.mapped[k]
	return mapped || d.held[k] > 0
}

// MemberKind is what a source-user member of a rule names (spec 2026-10-17
// §5.2, §5.3).
type MemberKind int

// The kinds of a member.
const (
	// MemberUnknown names no user, group or DUG of the data. As observed on
	// fw01, PAN-OS 11.2.5, it matches no directory user (M13), and a mapped
	// user of the same text matches it (M17).
	MemberUnknown MemberKind = iota
	// MemberUser names a user by its primary name or an alternate name, in
	// any case (N1, N2).
	MemberUser
	// MemberGroup names an LDAP or XML API group of the data (U3, M7, M11,
	// M12).
	MemberGroup
	// MemberDUG names a dynamic user group. Its members come from U3 (D13).
	MemberDUG
	// MemberCIE names a CIE group, or a group of source cie (D1, U16, SG2).
	MemberCIE
	// MemberInDoubt names a short name <domain>\<cn> that the data resolves
	// to no one LDAP group: the domain of the profile is unknown (ruling Q1),
	// sources.ldap is missing (D9), or two groups have the short name. The
	// device can resolve it to a group, so the caller keeps the rule in
	// doubt (PD19).
	MemberInDoubt
)

// Member is what one source-user member of a rule names.
type Member struct {
	Kind MemberKind
	// Name is the primary name of a user and the name of a group as the data
	// stores it; else the member as the rule writes it.
	Name string
	// Source is the source of a group (§3.3): ldap for a short name in doubt.
	// It is empty for a user and an unknown name.
	Source string
}

// Member reads a source-user member of a rule as the device does (spec
// 2026-10-17 §5.2, §5.3), in this order:
//
//   - a primary name or an alternate name, in any case: the user (N1, N2).
//     An email names its user while RuleEmail holds (SG4);
//   - a name of the dynamic list, in any case: the DUG (U10, D13);
//   - a group of groups[] by its name, in any case, or by its short name
//     (Group): an LDAP or XML API group (U3, M7, M11, M12), or a CIE group by
//     its source (D1);
//   - a short name that the data resolves to no one group: in doubt (ruling
//     Q1);
//   - a name that Classify gives a CIE source, also when groups[] lacks it:
//     a CIE group (D1, U16, SG2);
//   - anything else: unknown (M13, M17).
//
// Member judges by the data that arrived. While a part that judges the
// member is missing, it gives the kind that the data still shows; the caller
// asks Complete (PD19).
func (d *Data) Member(name string) Member {
	if i, ok := d.user(name, RuleEmail); ok {
		return Member{Kind: MemberUser, Name: d.file.Users[i].Name}
	}
	if i, ok := d.dugs[strings.ToLower(name)]; ok {
		return Member{Kind: MemberDUG, Name: d.file.DUGs[i], Source: SourceDUG}
	}
	if g, ok := d.Group(name); ok {
		kind := MemberGroup
		if isCIE(g.Source) {
			kind = MemberCIE
		}
		return Member{Kind: kind, Name: g.Name, Source: g.Source}
	}
	if _, s := d.shortName(name); s == shortInDoubt {
		return Member{Kind: MemberInDoubt, Name: name, Source: SourceLDAP}
	}
	f := &d.file
	if s := Classify(name, f.Sources.LDAP, !d.Complete(PartLDAP), f.DUGs, f.Sources.CIE, !d.Complete(PartCIE)); isCIE(s) {
		return Member{Kind: MemberCIE, Name: name, Source: s}
	}
	return Member{Kind: MemberUnknown, Name: name}
}

// isCIE reports whether a group source is a CIE source: cie:<profile>, or cie
// for an unknown profile (§3.3).
func isCIE(source string) bool {
	return source == SourceCIE || strings.HasPrefix(source, SourceCIE+":")
}

// shortState is what a name gives as a short name <domain>\<cn>.
type shortState int

const (
	shortNone     shortState = iota // the short name of no LDAP group of the data
	shortResolved                   // the short name of one group
	shortInDoubt                    // a short name that the data resolves to no one group
)

// shortName resolves a short name <domain>\<cn> to its LDAP group (M12): the
// group whose DN has that cn, in any case, and whose profile has that domain,
// in any case. The device prints the short name of an LDAP group with the
// domain of its group-mapping profile (U4); the configuration gives that
// domain (ruling Q1). A profile without a known domain can have the domain of
// the name, and two groups can have one short name: the data then resolves
// the name to no one group, and the name is in doubt.
func (d *Data) shortName(name string) (int, shortState) {
	domain, ok := domainOf(name)
	if !ok {
		return 0, shortNone
	}
	_, cn, _ := strings.Cut(name, `\`)
	found, doubt := -1, false
	for _, i := range d.cns[strings.ToLower(cn)] {
		pd, known := d.profileDomain(d.file.Groups[i].Source)
		switch {
		case !known:
			doubt = true
		case strings.EqualFold(pd, domain):
			doubt = doubt || found >= 0
			found = i
		}
	}
	switch {
	case doubt:
		return 0, shortInDoubt
	case found >= 0:
		return found, shortResolved
	}
	return 0, shortNone
}

// profileDomain gives the domain of the LDAP profile that a group source
// ldap:<profile> names. The source ldap names no profile (D9), and a profile
// that sources.ldap lacks, or that has no domain, has no known domain (ruling
// Q1).
func (d *Data) profileDomain(source string) (string, bool) {
	profile, ok := strings.CutPrefix(source, SourceLDAP+":")
	if !ok {
		return "", false
	}
	for _, s := range d.file.Sources.LDAP {
		if s.Name == profile {
			return s.Domain, s.Domain != ""
		}
	}
	return "", false
}
