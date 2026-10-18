package identity

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// PartError is a device answer that does not read: its part is then missing
// (spec 2026-10-17 §3.3, §3.4). It names the entry of an XML answer or the
// line of a text answer, and never quotes a value of the answer (§3.5).
type PartError struct {
	Part  string // a part of §3.2, such as PartMappings
	Line  int    // the line of a text answer, from 1; 0 when it names none
	Entry int    // the entry of an XML answer, from 1; 0 when it names none
	Why   string // a fixed reason, with counts at most
}

func (e *PartError) Error() string {
	switch {
	case e.Entry > 0:
		return fmt.Sprintf("%s: entry %d: %s", e.Part, e.Entry, e.Why)
	case e.Line > 0:
		return fmt.Sprintf("%s: line %d: %s", e.Part, e.Line, e.Why)
	}
	return e.Part + ": " + e.Why
}

// response is the envelope of an op answer: <response status="success"> and
// its result (X1).
type response[T any] struct {
	XMLName xml.Name
	Status  string `xml:"status,attr"`
	Result  T      `xml:"result"`
}

// readAnswer reads the result of an answer. An answer that is no XML, or no
// success response, is a *PartError of part.
func readAnswer[T any](b []byte, part string) (T, error) {
	var r response[T]
	if err := xml.Unmarshal(b, &r); err != nil {
		var zero T
		pe := &PartError{Part: part, Why: "the answer is no XML"}
		if se, ok := errors.AsType[*xml.SyntaxError](err); ok {
			pe.Line = se.Line
		}
		return zero, pe
	}
	if r.XMLName.Local != "response" || r.Status != "success" {
		var zero T
		return zero, &PartError{Part: part, Why: "the answer is no success response"}
	}
	return r.Result, nil
}

// textResult is the result of a text answer: CDATA for U3, U4, U5 and U6
// state all, plain text for U7 and U8 (X1).
type textResult struct {
	Text     string     `xml:",chardata"`
	Elements []xml.Name `xml:",any"`
}

// textLines reads a text answer as lines; line n is lines[n-1].
func textLines(b []byte, part string) ([]string, error) {
	r, err := readAnswer[textResult](b, part)
	if err != nil {
		return nil, err
	}
	if len(r.Elements) > 0 {
		return nil, &PartError{Part: part, Why: "the answer holds an element, not text"}
	}
	return strings.Split(r.Text, "\n"), nil
}

// noText refuses text in the result of an XML answer: no known form holds it.
func noText(text, part string) error {
	if strings.TrimSpace(text) != "" {
		return &PartError{Part: part, Why: "the answer holds text of no known form"}
	}
	return nil
}

// blank reports a line of white space only.
func blank(s string) bool { return strings.TrimSpace(s) == "" }

// spaces reports a column gap: spaces only.
func spaces(s string) bool { return strings.Trim(s, " ") == "" }

// dashes reports a separator line.
func dashes(s string) bool { return s != "" && strings.Trim(s, "-") == "" }

// number reads a count, an index or a time in seconds: a number of 0 or more.
func number(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil && n >= 0
}

// count reads the count or the total of an XML answer; an absent one is 0.
func count(s string) (int, bool) {
	if blank(s) {
		return 0, true
	}
	return number(s)
}

// MappingPage is one page of the mapping table: its entries, and the count
// and total that follow them (U1). An answer without them gives 0: U1 by
// address has neither, and U2 has no total (round 3).
type MappingPage struct {
	Entries      []Mapping
	Count, Total int
}

// mappingResult is the result of U1 and U2.
type mappingResult struct {
	Entries []struct {
		IP      string `xml:"ip"`
		User    string `xml:"user"`
		Type    string `xml:"type"`
		Timeout string `xml:"timeout"`
	} `xml:"entry"`
	Count string `xml:"count"`
	Total string `xml:"total"`
	Text  string `xml:",chardata"`
}

// noMapping is the answer of U1 by address for an address without a mapping
// (round 3).
const noMapping = "No matched record"

// ParseMappings reads a page of
// <show><user><ip-user-mapping-mp><all/>…</ip-user-mapping-mp></user></show>:
// result/entry with ip, vsys, type, user, timeout in seconds and origin, then
// count and total, as observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17 U1,
// X1). It reads the dataplane table of U2 too, with idle_timeout and without
// origin, and the answer of U1 by address. An entry that does not read is a
// *PartError of mappings with its index (Review focus 2).
func ParseMappings(b []byte) (MappingPage, error) {
	r, err := readAnswer[mappingResult](b, PartMappings)
	if err != nil {
		return MappingPage{}, err
	}
	if text := strings.TrimSpace(r.Text); text != "" && text != noMapping {
		return MappingPage{}, &PartError{Part: PartMappings, Why: "the answer holds text of no known form"}
	}
	var page MappingPage
	var ok bool
	if page.Count, ok = count(r.Count); !ok {
		return MappingPage{}, &PartError{Part: PartMappings, Why: "the count is no number"}
	}
	if page.Total, ok = count(r.Total); !ok {
		return MappingPage{}, &PartError{Part: PartMappings, Why: "the total is no number"}
	}
	for i, e := range r.Entries {
		fail := func(why string) (MappingPage, error) {
			return MappingPage{}, &PartError{Part: PartMappings, Entry: i + 1, Why: why}
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(e.IP))
		if err != nil {
			return fail("the address does not read")
		}
		timeout, ok := number(e.Timeout)
		if !ok {
			return fail("the timeout is no number of seconds")
		}
		if e.User == "" {
			return fail("the entry has no user")
		}
		page.Entries = append(page.Entries, Mapping{IP: ip, User: e.User, Type: e.Type, Timeout: timeout})
	}
	return page, nil
}

// The columns of the U3 table, as observed on fw01, PAN-OS 11.2.5 (spec
// 2026-10-17 X1, and the long names of the Task 4 fix round). The header holds
// User Name at 0, Vsys at 34 and Groups at 42. A user line holds the name in a
// field of 32 characters, two spaces, the vsys in a field of 30 characters,
// two spaces and the first group: the vsys at 34 and the first group at 66. A
// name of 33 characters or more is printed whole and moves the vsys to two
// places after the name; the first group stays 32 places after the vsys. A
// further group is a line of its own at 64, whatever the length of the name.
const (
	nameWidth        = 32
	vsysColumn       = 34
	headerGroupsCol  = 42
	firstGroupOffset = 32 // from the vsys to the first group
	moreGroupsColumn = 64
)

// customLegend ends the tables of U3 and U5: it explains the custom-group
// marker * (X1).
const customLegend = "* : Custom Group"

// userTable is the U3 table: the groups of each user as printed, the number
// of user lines, and the total with its line.
type userTable struct {
	groups    map[string][]string
	users     int
	total     int
	totalLine int // 0 when the table has no total
}

// readUserTable reads the U3 table in the columns of X1. A line that does not
// fit them is a *PartError at its line, never a guess.
func readUserTable(b []byte) (userTable, error) {
	lines, err := textLines(b, PartUserGroups)
	if err != nil {
		return userTable{}, err
	}
	fail := func(n int, why string) (userTable, error) {
		return userTable{}, &PartError{Part: PartUserGroups, Line: n, Why: why}
	}
	t := userTable{groups: map[string][]string{}}
	header := false
	user := "" // the user of the lines above; none after a blank line
	for i, line := range lines {
		n := i + 1
		switch {
		case blank(line):
			user = ""
		case !header:
			if !strings.HasPrefix(line, "User Name") {
				return fail(n, "the answer holds no user table")
			}
			if len(line) < headerGroupsCol+len("Groups") ||
				line[vsysColumn:vsysColumn+len("Vsys")] != "Vsys" ||
				line[headerGroupsCol:headerGroupsCol+len("Groups")] != "Groups" {
				return fail(n, "the header does not fit the columns")
			}
			header = true
		case dashes(line), line == customLegend:
		case strings.HasPrefix(line, "Total: "):
			if t.totalLine != 0 {
				return fail(n, "the table has two totals")
			}
			total, ok := number(strings.TrimPrefix(line, "Total: "))
			if !ok {
				return fail(n, "the total is no number")
			}
			t.total, t.totalLine = total, n
		case t.totalLine != 0:
			return fail(n, "a line follows the total")
		case line[0] == ' ':
			if user == "" {
				return fail(n, "a group line has no user")
			}
			group, ok := moreGroups(line)
			if !ok {
				return fail(n, "a group line does not fit the columns")
			}
			t.groups[user] = append(t.groups[user], group)
		default:
			name, group, ok := userLine(line)
			if !ok {
				return fail(n, "a user line does not fit the columns")
			}
			t.users++
			t.groups[name] = append(t.groups[name], group)
			user = name
		}
	}
	if !header {
		return fail(0, "the answer holds no user table")
	}
	return t, nil
}

// userLine reads a user line of U3 in the columns above. A name that fits its
// field gives the vsys at 34. A longer name ends at the first two spaces after
// the field, and the vsys follows them. Every user line holds a first group:
// no device showed one without.
func userLine(line string) (name, group string, ok bool) {
	if len(line) <= vsysColumn {
		return "", "", false
	}
	v := vsysColumn
	if !spaces(line[nameWidth:vsysColumn]) || line[vsysColumn] == ' ' {
		i := strings.Index(line[nameWidth:], "  ")
		if i < 0 {
			return "", "", false
		}
		v = nameWidth + i + len("  ")
	}
	g := v + firstGroupOffset
	if len(line) <= g || line[v] == ' ' || line[g] == ' ' {
		return "", "", false
	}
	vsys, _, _ := strings.Cut(line[v:], " ")
	if v+len(vsys) >= g || !spaces(line[v+len(vsys):g]) {
		return "", "", false
	}
	group = groupName(line[g:])
	return strings.TrimRight(line[:v-len("  ")], " "), group, group != ""
}

// moreGroups reads a further group line of U3: the group at 64 (X1).
func moreGroups(line string) (string, bool) {
	if len(line) <= moreGroupsColumn || !spaces(line[:moreGroupsColumn]) || line[moreGroupsColumn] == ' ' {
		return "", false
	}
	group := groupName(line[moreGroupsColumn:])
	return group, group != ""
}

// groupName is a group as U3 and U5 print it. Each group line ends with one
// space, and the custom-group marker * goes (X1). No captured line carried
// the marker, so its place is not observed: a trailing " *" goes.
func groupName(s string) string {
	s = strings.TrimSuffix(s, " ")
	if s == "*" {
		return ""
	}
	return strings.TrimSuffix(s, " *")
}

// ParseUserIDs reads <show><user><user-ids><all/></user-ids></user></show>:
// the groups of each user by the name as printed, the DUGs of the user among
// them (D13). The table lists every user that group mapping knows, and a user
// outside the directory whom an XML API group holds, as observed on fw01,
// PAN-OS 11.2.5 (spec 2026-10-17 U3, X1, M15). A user count that differs from
// Total: N is a *PartError (O3).
func ParseUserIDs(b []byte) (map[string][]string, error) {
	t, err := readUserTable(b)
	switch {
	case err != nil:
		return nil, err
	case t.totalLine == 0:
		return nil, &PartError{Part: PartUserGroups, Why: "the table has no total"}
	case t.users != t.total:
		return nil, &PartError{
			Part: PartUserGroups, Line: t.totalLine,
			Why: fmt.Sprintf("the table lists %d users and its total is %d", t.users, t.total),
		}
	}
	return t.groups, nil
}

// ParseUserIDsMatch reads
// <show><user><user-ids><match-user>U</match-user></user-ids></user></show>:
// the U3 table with one user line, as observed on fw01, PAN-OS 11.2.5 (spec
// 2026-10-17 X1). Its Total counts all users, so it is not compared. A table
// without a user line reads as no user.
func ParseUserIDsMatch(b []byte) (map[string][]string, error) {
	t, err := readUserTable(b)
	if err != nil {
		return nil, err
	}
	return t.groups, nil
}

// ParseGroupList reads <show><user><group><list/></group></user></show> and
// its dynamic list: one name per line, then Total: N and the legend, as
// observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17 U5, X1). The full list
// holds the LDAP, XML API and CIE groups and the DUGs; the dynamic list the
// DUGs only (U10). Both fw01 lists held exactly Total names (round 3), so a
// list that differs from its total is a *PartError, as a U3 table is (O3).
func ParseGroupList(b []byte) ([]string, error) {
	lines, err := textLines(b, PartGroups)
	if err != nil {
		return nil, err
	}
	fail := func(n int, why string) ([]string, error) {
		return nil, &PartError{Part: PartGroups, Line: n, Why: why}
	}
	var names []string
	total, totalLine := 0, 0
	for i, line := range lines {
		n := i + 1
		switch {
		case blank(line), line == customLegend:
		case strings.HasPrefix(line, "Total: "):
			if totalLine != 0 {
				return fail(n, "the list has two totals")
			}
			var ok bool
			if total, ok = number(strings.TrimPrefix(line, "Total: ")); !ok {
				return fail(n, "the total is no number")
			}
			totalLine = n
		case totalLine != 0:
			return fail(n, "a line follows the total")
		default:
			name := groupName(line)
			if name == "" {
				return fail(n, "a line holds no group name")
			}
			names = append(names, name)
		}
	}
	switch {
	case totalLine == 0:
		return fail(0, "the list has no total")
	case len(names) != total:
		return fail(totalLine, fmt.Sprintf("the list holds %d groups and its total is %d", len(names), total))
	}
	return names, nil
}

// statisticsResult is the result of U6 statistics.
type statisticsResult struct {
	Entries []struct {
		Name   string `xml:"name"`
		Groups string `xml:"groups"`
	} `xml:"entry"`
	Text string `xml:",chardata"`
}

// ParseGroupMappingStatistics reads
// <show><user><group-mapping><statistics/></group-mapping></user></show>: one
// entry per group-mapping profile with name, vsys, groups, last and next, as
// observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17 U6, X1). It gives the name
// and the group count of each profile; the state answer gives the base.
func ParseGroupMappingStatistics(b []byte) ([]LDAPSource, error) {
	r, err := readAnswer[statisticsResult](b, PartLDAP)
	if err != nil {
		return nil, err
	}
	if err := noText(r.Text, PartLDAP); err != nil {
		return nil, err
	}
	var out []LDAPSource
	for i, e := range r.Entries {
		if e.Name == "" {
			return nil, &PartError{Part: PartLDAP, Entry: i + 1, Why: "the entry has no name"}
		}
		groups, ok := number(e.Groups)
		if !ok {
			return nil, &PartError{Part: PartLDAP, Entry: i + 1, Why: "the group count is no number"}
		}
		out = append(out, LDAPSource{Name: e.Name, Groups: groups})
	}
	return out, nil
}

// LDAPState is what U6 state all tells of one group-mapping profile: its
// base. The answer holds no domain line (X1); the domain of a profile comes
// from the configuration (ruling Q1).
type LDAPState struct {
	Base string
}

// mappingHeader starts the block of a profile in U6 state all (X1).
const mappingHeader = "Group Mapping("

// ParseGroupMappingState reads
// <show><user><group-mapping><state>all</state></group-mapping></user></show>:
// CDATA text with one block per profile, as observed on fw01, PAN-OS 11.2.5
// (spec 2026-10-17 U6, X1). A block starts with
// "Group Mapping(<vsys>, type: <type>): <profile> ", then come tab-indented
// lines such as "Base       : <base>", the servers with two tabs and their
// action times with three, "Number of Groups: N", and one group DN per line.
// It gives the base by profile; a block without a base is a *PartError.
func ParseGroupMappingState(b []byte) (map[string]LDAPState, error) {
	lines, err := textLines(b, PartLDAP)
	if err != nil {
		return nil, err
	}
	fail := func(n int, why string) (map[string]LDAPState, error) {
		return nil, &PartError{Part: PartLDAP, Line: n, Why: why}
	}
	out := map[string]LDAPState{}
	profile, start, inGroups := "", 0, false
	noBase := func() bool { return profile != "" && out[profile].Base == "" }
	for i, line := range lines {
		n := i + 1
		switch {
		case blank(line):
		case strings.HasPrefix(line, mappingHeader):
			if noBase() {
				return fail(start, "a group mapping has no base")
			}
			_, after, ok := strings.Cut(line, "): ")
			name := strings.TrimSuffix(after, " ")
			if !ok || name == "" {
				return fail(n, "a group mapping header does not fit")
			}
			if _, twice := out[name]; twice {
				return fail(n, "a group mapping shows twice")
			}
			out[name] = LDAPState{}
			profile, start, inGroups = name, n, false
		case profile == "":
			return fail(n, "a line comes before the first group mapping")
		case strings.HasPrefix(line, "\t\t"):
			// A server, or its action times; the group list holds none.
			if inGroups {
				return fail(n, "a line of a group mapping does not fit")
			}
		case strings.HasPrefix(line, "\t"):
			if inGroups {
				continue // a group DN of the profile; U5 gives the groups
			}
			key, value, ok := strings.Cut(line[1:], ":")
			if !ok {
				return fail(n, "a line of a group mapping does not fit")
			}
			switch strings.TrimSpace(key) {
			case "Base":
				out[profile] = LDAPState{Base: strings.TrimPrefix(value, " ")}
			case "Number of Groups":
				inGroups = true
			}
		default:
			return fail(n, "a line of a group mapping does not fit")
		}
	}
	if noBase() {
		return fail(start, "a group mapping has no base")
	}
	return out, nil
}

// cieColumns are the columns of the U7 table (X1).
var cieColumns = []string{"Name", "Vsys", "Groups", "Last-Action", "Next-Action"}

// ParseCIEStatus reads
// <show><user><cloud-identity-engine><status><all/></status></cloud-identity-engine></user></show>:
// plain text with the tab-separated columns Name, Vsys, Groups, Last-Action
// and Next-Action, a line of dashes and one row per CIE profile, as observed
// on fw01, PAN-OS 11.2.5 (spec 2026-10-17 U7, X1). It gives the name, the
// group count and the last action of each profile. The answer has no domain
// column; the domain comes from the configuration (SG2). An empty answer
// lists no profile.
func ParseCIEStatus(b []byte) ([]CIESource, error) {
	lines, err := textLines(b, PartCIE)
	if err != nil {
		return nil, err
	}
	fail := func(n int, why string) ([]CIESource, error) {
		return nil, &PartError{Part: PartCIE, Line: n, Why: why}
	}
	var out []CIESource
	header := false
	for i, line := range lines {
		n := i + 1
		switch {
		case blank(line):
		case !header:
			if !slices.Equal(tabFields(line), cieColumns) {
				return fail(n, "the answer holds no CIE table")
			}
			header = true
		case dashes(line):
		default:
			f := tabFields(line)
			if len(f) != len(cieColumns) {
				return fail(n, "a row does not fit the columns")
			}
			groups, ok := number(f[2])
			if !ok {
				return fail(n, "the group count is no number")
			}
			out = append(out, CIESource{Name: f[0], Groups: groups, Last: f[3]})
		}
	}
	return out, nil
}

// tabFields splits a line of U7 at its tabs and drops the padding (X1).
func tabFields(line string) []string {
	var out []string
	for f := range strings.SplitSeq(line, "\t") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Attributes are the names of one user in U8, as printed: the primary name,
// the email and the alternate names.
type Attributes struct {
	Primary, Email string
	Alt            []string
}

// ParseUserAttributes reads
// <show><user><user-attributes><user>all</user></user-attributes></user></show>:
// plain-text blocks split by an empty line, each "Primary: <name>" and a tab,
// "Email: <mail>" on the same line when set, then "Alt User Names:" and
// numbered lines, as observed on fw01, PAN-OS 11.2.5 (spec 2026-10-17 U8,
// X1). A block that a User-ID groups message rewrote holds the primary name
// only (U18).
func ParseUserAttributes(b []byte) ([]Attributes, error) {
	lines, err := textLines(b, PartUserNames)
	if err != nil {
		return nil, err
	}
	fail := func(n int, why string) ([]Attributes, error) {
		return nil, &PartError{Part: PartUserNames, Line: n, Why: why}
	}
	var out []Attributes
	inBlock, inAlt := false, false
	for i, line := range lines {
		n := i + 1
		switch {
		case blank(line):
			inBlock, inAlt = false, false
		case strings.HasPrefix(line, "Primary: "):
			if inBlock {
				return fail(n, "a block holds two primary names")
			}
			a, ok := primaryLine(line)
			if !ok {
				return fail(n, "a primary line does not fit")
			}
			out = append(out, a)
			inBlock = true
		case !inBlock:
			return fail(n, "a line comes before a primary name")
		case strings.TrimRight(line, " ") == "Alt User Names:":
			inAlt = true
		case strings.HasPrefix(line, "Email: "):
			a := &out[len(out)-1]
			if a.Email != "" {
				return fail(n, "a block holds two emails")
			}
			a.Email = strings.TrimPrefix(line, "Email: ")
		case inAlt:
			name, ok := altName(line)
			if !ok {
				return fail(n, "an alternate name line does not fit")
			}
			a := &out[len(out)-1]
			a.Alt = append(a.Alt, name)
		default:
			return fail(n, "a line of a block does not fit")
		}
	}
	return out, nil
}

// primaryLine reads "Primary: <name>" and a tab, with "Email: <mail>" after
// the tab when set (X1).
func primaryLine(line string) (Attributes, bool) {
	name, rest, _ := strings.Cut(strings.TrimPrefix(line, "Primary: "), "\t")
	a := Attributes{Primary: name}
	switch {
	case name == "":
		return a, false
	case strings.HasPrefix(rest, "Email: "):
		a.Email = strings.TrimPrefix(rest, "Email: ")
	case !blank(rest):
		return a, false
	}
	return a, true
}

// altName reads "<n>) <name>" of the alternate names (X1).
func altName(line string) (string, bool) {
	index, name, ok := strings.Cut(line, ") ")
	if _, isNumber := number(index); !ok || !isNumber || name == "" {
		return "", false
	}
	return name, true
}

// registeredResult is the result of U9.
type registeredResult struct {
	Entries []struct {
		User string   `xml:"user,attr"`
		Tags []string `xml:"tag>member"`
	} `xml:"entry"`
	Text string `xml:",chardata"`
}

// ParseRegisteredUsers reads
// <show><object><registered-user><all/></registered-user></object></show>:
// result/entry user="<name>" with tag/member, then count, as observed on
// fw01, PAN-OS 11.2.5 (spec 2026-10-17 U9, X1). It gives the tags of each
// user as printed.
func ParseRegisteredUsers(b []byte) ([]Tags, error) {
	r, err := readAnswer[registeredResult](b, PartTags)
	if err != nil {
		return nil, err
	}
	if err := noText(r.Text, PartTags); err != nil {
		return nil, err
	}
	var out []Tags
	for i, e := range r.Entries {
		if e.User == "" {
			return nil, &PartError{Part: PartTags, Entry: i + 1, Why: "the entry has no user"}
		}
		out = append(out, Tags{User: e.User, Tags: e.Tags})
	}
	return out, nil
}

// GroupAnswer is the answer of U4 for one group: the short name of an LDAP
// group, the source type and the source, the group type of a DUG, and the
// members, as printed.
type GroupAnswer struct {
	ShortName, SourceType, Source string
	Type                          string // "Dynamic" for a DUG (U4, round 3)
	Members                       []string
}

// ParseGroupName reads <show><user><group><name>G</name></group></user></show>:
// CDATA text with "short name:" (LDAP only), "source type:", "source:",
// "Group type:" for a DUG and one "[n] <member>" line per member, the
// members of a nested group flat, as observed on fw01, PAN-OS 11.2.5 (spec
// 2026-10-17 U4). A group without members answers "User group 'G' does not
// exist or does not have members", which reads as no member. The lab tool
// reads it; the fetch does not ask it (D3).
func ParseGroupName(b []byte) (GroupAnswer, error) {
	lines, err := textLines(b, PartGroups)
	if err != nil {
		return GroupAnswer{}, err
	}
	var g GroupAnswer
	for i, line := range lines {
		switch {
		case blank(line), noGroup(line):
		case strings.HasPrefix(line, "short name:"):
			g.ShortName = after(line, "short name:")
		case strings.HasPrefix(line, "source type:"):
			g.SourceType = after(line, "source type:")
		case strings.HasPrefix(line, "source:"):
			g.Source = after(line, "source:")
		case strings.HasPrefix(line, "Group type:"):
			g.Type = after(line, "Group type:")
		default:
			member, ok := memberLine(line)
			if !ok {
				return GroupAnswer{}, &PartError{Part: PartGroups, Line: i + 1, Why: "a line does not fit"}
			}
			g.Members = append(g.Members, member)
		}
	}
	return g, nil
}

// after is the value of a key line of U4, without the padding of the key.
func after(line, key string) string {
	return strings.TrimLeft(strings.TrimPrefix(line, key), " ")
}

// memberLine reads "[n     ] <member>" of U4.
func memberLine(line string) (string, bool) {
	index, member, ok := strings.Cut(strings.TrimPrefix(line, "["), "] ")
	if _, isNumber := number(index); !ok || !isNumber || !strings.HasPrefix(line, "[") || member == "" {
		return "", false
	}
	return member, true
}

// noGroup reports the answer of U4 for a group without members.
func noGroup(line string) bool {
	return strings.HasPrefix(line, "User group '") && strings.HasSuffix(line, "' does not exist or does not have members")
}
