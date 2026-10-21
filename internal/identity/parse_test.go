package identity_test

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/identity"
)

// The group names of the answer fixtures.
const (
	domainUsers  = "cn=domain users,cn=users,dc=example,dc=com"
	payroll      = "cn=payroll,ou=groups,dc=example,dc=com"
	emptyGroup   = "cn=empty,ou=groups,dc=example,dc=com"
	workstations = "cn=workstations,ou=groups,dc=example,dc=com"
	branchStaff  = "cn=branch staff,ou=branch,dc=example,dc=com"
)

// answer reads one device answer of testdata/identity/.
func answer(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(fixtures + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// partError asserts that err is a *PartError of part and returns it.
func partError(t *testing.T, err error, part string) *identity.PartError {
	t.Helper()
	pe, ok := errors.AsType[*identity.PartError](err)
	if !ok {
		t.Fatalf("err %v, want a *PartError of %s", err, part)
	}
	if pe.Part != part {
		t.Errorf("part %q, want %q", pe.Part, part)
	}
	return pe
}

// cdata is a text answer as the device sends it: CDATA in result (X1).
func cdata(body string) []byte {
	return []byte(`<response status="success"><result><![CDATA[` + body + `]]></result></response>`)
}

// plain is an answer whose result holds plain text or XML (X1).
func plain(body string) []byte {
	return []byte(`<response status="success"><result>` + body + `</result></response>`)
}

func mapping(ip, user string, timeout int) identity.Mapping {
	return identity.Mapping{IP: netip.MustParseAddr(ip), User: user, Type: "XMLAPI", Timeout: timeout}
}

// U1, X1: a page of ip-user-mapping-mp holds its entries, then count and
// total. U2: the dataplane table reads too, without origin and total. U1 by
// address holds one entry without count and total, and an address without a
// mapping answers a text (round 3).
func TestParseMappingsReadsAPage(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]identity.MappingPage{
		"answer-mappings-1.xml": {Entries: []identity.Mapping{
			mapping("198.51.100.11", `example.com\alice`, 14400),
			mapping("198.51.100.10", `example\alice`, 14400),
			mapping("198.51.100.13", `example.com\carol`, 14400),
			mapping("198.51.100.12", `other\ghost`, 14400),
		}, Count: 4, Total: 6},
		"answer-mappings-2.xml": {Entries: []identity.Mapping{
			mapping("2001:db8::11", `example.com\bob`, 14400),
			mapping("198.51.100.14", `example.com\dave`, 14400),
		}, Count: 2, Total: 6},
		"answer-mappings-dp.xml": {Entries: []identity.Mapping{
			mapping("198.51.100.12", `other\ghost`, 14357),
			mapping("198.51.100.11", `example.com\alice`, 14357),
			mapping("198.51.100.14", `example.com\dave`, 14357),
			mapping("198.51.100.10", `example\alice`, 14357),
			mapping("2001:db8::11", `example.com\bob`, 14357),
			mapping("198.51.100.13", `example.com\carol`, 14357),
		}, Count: 6},
		"answer-mapping-ip.xml":      {Entries: []identity.Mapping{mapping("198.51.100.11", `example.com\alice`, 14400)}},
		"answer-mapping-ip-none.xml": {},
	} {
		got, err := identity.ParseMappings(answer(t, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !slices.Equal(got.Entries, want.Entries) || got.Count != want.Count || got.Total != want.Total {
			t.Errorf("%s: %+v\nwant %+v", name, got, want)
		}
	}
}

// Review focus 2, §3.5: an entry that does not read is a *PartError of
// mappings with the entry index. The text names no address and no user.
func TestParseMappingsRefusesAnUnreadableEntry(t *testing.T) {
	t.Parallel()
	const good = `<entry><ip>198.51.100.11</ip><vsys>vsys1</vsys><type>XMLAPI</type>` +
		`<user>example.com\alice</user><timeout>14400</timeout></entry>`
	entry := func(ip, user, timeout string) string {
		return `<entry><ip>` + ip + `</ip><vsys>vsys1</vsys><type>XMLAPI</type><user>` + user +
			`</user><timeout>` + timeout + `</timeout></entry>`
	}
	for name, c := range map[string]struct{ entry, why string }{
		"timeout Never":    {entry("198.51.100.12", `other\ghost`, "Never"), "the timeout is no number of seconds"},
		"negative timeout": {entry("198.51.100.12", `other\ghost`, "-1"), "the timeout is no number of seconds"},
		"ip x":             {entry("x", `other\ghost`, "14400"), "the address does not read"},
		"no user":          {entry("198.51.100.12", "", "14400"), "the entry has no user"},
	} {
		_, err := identity.ParseMappings(plain(good + "\n" + c.entry + "\n<count>2</count>\n<total>2</total>\n"))
		pe := partError(t, err, identity.PartMappings)
		if pe.Entry != 2 || pe.Line != 0 {
			t.Errorf("%s: entry %d, line %d, want entry 2", name, pe.Entry, pe.Line)
		}
		if got, want := err.Error(), "mappings: entry 2: "+c.why; got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	for name, b := range map[string][]byte{
		"count": plain(good + "<count>four</count><total>1</total>"),
		"total": plain(good + "<count>1</count><total>-1</total>"),
		"text":  plain("No matched record for example.com\\alice\n"),
	} {
		_, err := identity.ParseMappings(b)
		if pe := partError(t, err, identity.PartMappings); strings.Contains(pe.Error(), "alice") {
			t.Errorf("%s: %q quotes the answer", name, pe)
		}
	}
}

const userHeader = "User Name                         Vsys    Groups"

// userTable is a U3 answer in the layout of fw01 (X1 and the long names of
// the Task 4 fix round). A row is a user and its groups. The user line holds
// the name in a field of 32, two spaces, the vsys in a field of 30, two
// spaces and the first group; a further group is at 64.
func userTable(total int, rows ...[]string) []byte {
	var b strings.Builder
	b.WriteString("\n" + userHeader + "\n" + strings.Repeat("-", 66) + "\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "%-32s  %-30s  %s \n", r[0], "vsys1", r[1])
		for _, g := range r[2:] {
			fmt.Fprintf(&b, "%64s%s \n", "", g)
		}
	}
	fmt.Fprintf(&b, "\nTotal: %d\n* : Custom Group\n\n", total)
	return cdata(b.String())
}

// U3, X1, D13: the table in fixed columns. A user line holds the name at 0,
// the vsys at 34 and the first group at 66; a further group is a line of its
// own at 64. A group name can hold spaces. U3 lists the DUGs of a user among
// its groups, and a user outside the directory with the XML API group that
// holds it (M15). The custom-group marker * goes; it is synthetic, as no
// captured line carried one.
func TestParseUserIDsReadsTheTable(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseUserIDs(answer(t, "answer-user-ids.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		`example.com\alice`: {domainUsers, payroll},
		`example.com\pc01$`: {workstations},
		`other\ghost`:       {"engineering"},
		`example.com\bob`:   {domainUsers, "team-x", "help desk"},
		`example.com\carol`: {domainUsers, "engineering", "dug-a", "dug-ab", "custom-a"},
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("users %v\nwant %v", got, want)
	}
	// C7: the empty table of a device without User-ID data.
	none, err := identity.ParseUserIDs(cdata("\n" + userHeader + "\n" + strings.Repeat("-", 66) + "\n\nTotal: 0\n* : Custom Group\n\n"))
	if err != nil || len(none) != 0 {
		t.Errorf("the empty table: %v, %v", none, err)
	}
}

// The long names of the Task 4 fix round, as observed on fw01, PAN-OS
// 11.2.5: a name of 33 characters or more is printed whole and moves the vsys
// to two places after the name, and the first group stays 32 places after
// the vsys. A further group stays at 64. The names of the fixture have 32,
// 33, 40 and 63 characters; 63 was the longest name that fw01 took as an XML
// API member.
func TestParseUserIDsReadsLongNames(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseUserIDs(answer(t, "answer-user-ids-long.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		`example.com\alice`:                            {domainUsers},
		`example.com\bob.` + strings.Repeat("x", 16):   {"team-x"},
		`example.com\carol.` + strings.Repeat("x", 15): {domainUsers, "engineering"},
		`example.com\dave.` + strings.Repeat("x", 23):  {"team-x", "help desk", "dug-a"},
		`other\ghost.` + strings.Repeat("x", 51):       {"engineering"},
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("users %v\nwant %v", got, want)
	}
	// match-user answers a long name in the same layout.
	long := `example.com\dave.` + strings.Repeat("x", 23)
	match, err := identity.ParseUserIDsMatch(userTable(26, []string{long, "team-x", "help desk"}))
	if err != nil || !slices.Equal(match[long], []string{"team-x", "help desk"}) || len(match) != 1 {
		t.Errorf("match-user of a long name: %v, %v", match, err)
	}
}

// O3: a user count that differs from Total: N is a *PartError of
// users.groups, at the line of the total.
func TestParseUserIDsChecksTheTotal(t *testing.T) {
	t.Parallel()
	_, err := identity.ParseUserIDs(userTable(3, []string{`example.com\alice`, domainUsers}, []string{`example.com\bob`, domainUsers}))
	pe := partError(t, err, identity.PartUserGroups)
	if pe.Line != 7 {
		t.Errorf("line %d, want 7", pe.Line)
	}
	if got, want := err.Error(), "users.groups: line 7: the table lists 2 users and its total is 3"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

// A U3 table that does not fit the layout of X1 is a *PartError of
// users.groups at its line, never a guess.
func TestParseUserIDsRefusesABrokenTable(t *testing.T) {
	t.Parallel()
	head := "\n" + userHeader + "\n" + strings.Repeat("-", 66) + "\n"
	alice := fmt.Sprintf("%-34s%-32s%s \n", `example.com\alice`, "vsys1", domainUsers)
	long := `example.com\alice.` + strings.Repeat("x", 22) // 40 characters
	for name, c := range map[string]struct {
		body string
		line int
	}{
		"empty":                {"\n\n", 0},
		"no table":             {"\nexample.com\\alice\n", 2},
		"header shifted":       {"\nUser Name     Vsys    Groups\n", 2},
		"name runs into vsys":  {head + fmt.Sprintf("%-34s%-32s%s \n", `example.com\`+strings.Repeat("a", 30), "vsys1", domainUsers), 4},
		"long name, one space": {head + fmt.Sprintf("%s %-30s  %s \n", long, "vsys1", domainUsers), 4},
		"long name, no vsys":   {head + long + "\n", 4},
		"long name, group off": {head + fmt.Sprintf("%s  %-31s  %s \n", long, "vsys1", domainUsers), 4},
		// Two spaces at the end of the name field read as the short layout, and
		// the rest of the name then fills the gap before the first group.
		"spaces at the field end": {head + fmt.Sprintf("%-32s  %s  %-30s  %s \n", `example.com\alice.`+strings.Repeat("x", 14), "tail", "vsys1", domainUsers), 4},
		"short line":              {head + `example.com\alice` + "\n", 4},
		"no group":                {head + fmt.Sprintf("%-34s%s\n", `example.com\dave`, "vsys1"), 4},
		"no group, padded":        {head + fmt.Sprintf("%-34s%-32s\n", `example.com\dave`, "vsys1"), 4},
		"vsys too long":           {head + fmt.Sprintf("%-34s%s %s \n", `example.com\alice`, strings.Repeat("v", 32), domainUsers), 4},
		"group off column":        {head + fmt.Sprintf("%-34s%-33s%s \n", `example.com\alice`, "vsys1", domainUsers), 4},
		"text in the gap":         {head + fmt.Sprintf("%-34s%-20s%-12s%s \n", `example.com\alice`, "vsys1", "x", domainUsers), 4},
		"group without user":      {head + fmt.Sprintf("%64s%s \n", "", "team-x"), 4},
		"group after a break":     {head + alice + "\n" + fmt.Sprintf("%64s%s \n", "", "team-x"), 6},
		"group off its line":      {head + alice + fmt.Sprintf("%60s%s \n", "", "team-x"), 5},
		"marker only":             {head + alice + fmt.Sprintf("%64s%s \n", "", "*"), 5},
		"total no number":         {head + alice + "\nTotal: many\n", 6},
		"two totals":              {head + alice + "\nTotal: 1\nTotal: 1\n", 7},
		"line after total":        {head + "\nTotal: 1\n" + alice, 6},
	} {
		_, err := identity.ParseUserIDs(cdata(c.body))
		if pe := partError(t, err, identity.PartUserGroups); pe.Line != c.line {
			t.Errorf("%s: line %d (%v), want %d", name, pe.Line, err, c.line)
		}
		if strings.Contains(err.Error(), "alice") || strings.Contains(err.Error(), "domain users") {
			t.Errorf("%s: %q quotes the answer", name, err)
		}
	}
	_, err := identity.ParseUserIDs(cdata(head + alice))
	if pe := partError(t, err, identity.PartUserGroups); pe.Why != "the table has no total" {
		t.Errorf("no total: %v", err)
	}
}

// X1 (P5, P22): match-user answers the U3 table with one user line, and its
// Total counts all users, so the parser does not compare it. A table without
// a user line reads as no user.
func TestParseUserIDsMatch(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseUserIDsMatch(answer(t, "answer-user-ids-match.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{`example.com\carol`: {domainUsers, "engineering", "dug-a", "dug-ab", "custom-a"}}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("match %v\nwant %v", got, want)
	}
	if _, err := identity.ParseUserIDs(answer(t, "answer-user-ids-match.xml")); err == nil {
		t.Error("ParseUserIDs takes a table whose total counts other users")
	}
	none, err := identity.ParseUserIDsMatch(userTable(5))
	if err != nil || len(none) != 0 {
		t.Errorf("no user line: %v, %v", none, err)
	}
	if _, err := identity.ParseUserIDsMatch(cdata("\nUser Name\n")); err == nil {
		t.Error("a header out of its columns reads")
	}
}

// U5, X1: one name per line with one trailing space, then Total and the
// custom-group legend. The full list holds the LDAP and XML API groups, the
// DUGs and the CIE groups; the dynamic list the DUGs only (round 3). The
// marker * goes; it is synthetic, as no captured line carried one.
func TestParseGroupList(t *testing.T) {
	t.Parallel()
	full, err := identity.ParseGroupList(answer(t, "answer-group-list.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		domainUsers, payroll, emptyGroup, workstations, branchStaff, "engineering", "team-x",
		"help desk", "dug-a", "dug-ab", `example-cie\cloud-team`, "custom-a",
	}
	if !slices.Equal(full, want) {
		t.Errorf("full list %q\nwant %q", full, want)
	}
	dynamic, err := identity.ParseGroupList(answer(t, "answer-group-list-dynamic.xml"))
	if err != nil || !slices.Equal(dynamic, []string{"dug-a", "dug-ab"}) {
		t.Errorf("dynamic list %q, %v", dynamic, err)
	}
	// C7: the empty list of a device without User-ID data.
	none, err := identity.ParseGroupList(cdata("\n\nTotal: 0\n* : Custom Group\n\n"))
	if err != nil || len(none) != 0 {
		t.Errorf("the empty list: %q, %v", none, err)
	}
	// The marker goes without a trailing space too.
	marked, err := identity.ParseGroupList(cdata("\ncustom-b *\n\nTotal: 1\n"))
	if err != nil || !slices.Equal(marked, []string{"custom-b"}) {
		t.Errorf("a marker without a trailing space: %q, %v", marked, err)
	}
}

// O3 for U5: both fw01 lists hold exactly Total names (round 3). A list
// that differs from its Total, or has none, is a *PartError of groups.
func TestParseGroupListChecksTheTotal(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		body string
		line int
		why  string
	}{
		"short":            {"\ndug-a \ndug-ab \n\nTotal: 3\n", 5, "the list holds 2 groups and its total is 3"},
		"no total":         {"\ndug-a \n", 0, "the list has no total"},
		"total no number":  {"\ndug-a \n\nTotal: x\n", 4, "the total is no number"},
		"two totals":       {"\ndug-a \n\nTotal: 1\nTotal: 1\n", 5, "the list has two totals"},
		"line after total": {"\n\nTotal: 0\ndug-a \n", 4, "a line follows the total"},
		"marker only":      {"\n* \n\nTotal: 1\n", 2, "a line holds no group name"},
	} {
		_, err := identity.ParseGroupList(cdata(c.body))
		pe := partError(t, err, identity.PartGroups)
		if pe.Line != c.line || pe.Why != c.why {
			t.Errorf("%s: line %d %q, want line %d %q", name, pe.Line, pe.Why, c.line, c.why)
		}
	}
}

// U6: statistics holds one XML entry per group-mapping profile, with its name
// and group count.
func TestParseGroupMappingStatistics(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseGroupMappingStatistics(answer(t, "answer-group-mapping-statistics.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []identity.LDAPSource{{Name: "example.com", Groups: 4}, {Name: "branch", Groups: 1}}
	if !slices.Equal(got, want) {
		t.Errorf("profiles %+v\nwant %+v", got, want)
	}
	// C7: an empty result on a device without a group-mapping profile.
	if none, err := identity.ParseGroupMappingStatistics(plain("")); err != nil || len(none) != 0 {
		t.Errorf("no profile: %+v, %v", none, err)
	}
	for name, c := range map[string]struct{ body, why string }{
		"count": {`<entry><name>example.com</name><groups>4</groups></entry><entry><name>branch</name><groups>many</groups></entry>`, "the group count is no number"},
		"name":  {`<entry><name>example.com</name><groups>4</groups></entry><entry><groups>1</groups></entry>`, "the entry has no name"},
	} {
		_, err := identity.ParseGroupMappingStatistics(plain(c.body))
		if pe := partError(t, err, identity.PartLDAP); pe.Entry != 2 || pe.Why != c.why {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// U6, X1: state all holds per profile a header, tab-indented lines, the
// servers and the group list, and no domain line. The parser gives the base
// of each profile and no domain: the domain comes from the configuration
// (ruling Q1, Task 7).
func TestParseGroupMappingState(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseGroupMappingState(answer(t, "answer-group-mapping-state.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]identity.LDAPState{
		"example.com": {Base: "dc=example,dc=com"},
		"branch":      {Base: "ou=branch,dc=example,dc=com"},
	}
	if !maps.Equal(got, want) {
		t.Errorf("profiles %+v\nwant %+v", got, want)
	}
	// C7: the empty CDATA of a device without a group-mapping profile.
	if none, err := identity.ParseGroupMappingState(cdata("\n\n")); err != nil || len(none) != 0 {
		t.Errorf("no profile: %+v, %v", none, err)
	}
}

// A state answer that does not fit the layout of X1 is a *PartError of
// sources.ldap at its line.
func TestParseGroupMappingStateRefusesABrokenAnswer(t *testing.T) {
	t.Parallel()
	const header = "Group Mapping(vsys1, type: active-directory): example.com \n"
	const base = "\tBase       : dc=example,dc=com\n"
	for name, c := range map[string]struct {
		body string
		line int
		why  string
	}{
		"before a header":    {"\nnot a header\n", 2, "a line comes before the first group mapping"},
		"header":             {"\nGroup Mapping(vsys1)\n", 2, "a group mapping header does not fit"},
		"no base":            {"\n" + header + "\tBind DN    : svc-ldap@example.com\n", 2, "a group mapping has no base"},
		"no base, then next": {"\n" + header + "\n" + header, 2, "a group mapping has no base"},
		"twice":              {"\n" + header + base + header + base, 4, "a group mapping shows twice"},
		"no key":             {"\n" + header + base + "\tconfigured\n", 4, "a line of a group mapping does not fit"},
		"no tab":             {"\n" + header + base + "Base: dc=example,dc=com\n", 4, "a line of a group mapping does not fit"},
		"server in groups":   {"\n" + header + base + "\tNumber of Groups: 1\n\t\t192.0.2.53(389)\n", 5, "a line of a group mapping does not fit"},
	} {
		_, err := identity.ParseGroupMappingState(cdata(c.body))
		pe := partError(t, err, identity.PartLDAP)
		if pe.Line != c.line || pe.Why != c.why {
			t.Errorf("%s: line %d %q, want line %d %q", name, pe.Line, pe.Why, c.line, c.why)
		}
	}
}

const cieHeader = "Name\t\tVsys\tGroups\t\tLast-Action\t\tNext-Action\n"

// U7, X1: plain text with tab-separated columns, 78 dashes and one row per
// CIE profile, without a domain column (SG2). The row of cie-a is synthetic:
// no device showed a profile that synced (U16, ruling D10). cie-b has the
// captured layout of a profile that never synced.
func TestParseCIEStatus(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseCIEStatus(answer(t, "answer-cie-status.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []identity.CIESource{
		{Name: "cie-a", Groups: 1, Last: "120 secs ago"},
		{Name: "cie-b", Groups: 0, Last: "Never"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("profiles %+v\nwant %+v", got, want)
	}
	for name, b := range map[string][]byte{
		"empty":       plain(""),
		"header only": plain(cieHeader + strings.Repeat("-", 78) + "\n"),
	} {
		if none, err := identity.ParseCIEStatus(b); err != nil || len(none) != 0 {
			t.Errorf("%s: %+v, %v", name, none, err)
		}
	}
	for name, c := range map[string]struct {
		body string
		line int
		why  string
	}{
		"no header":   {"cie-a     \tvsys1 \t    1\t\tNever\t\t\tNever\t\n", 1, "the answer holds no CIE table"},
		"short row":   {cieHeader + "cie-a     \tvsys1 \t    1\t\tNever\t\n", 2, "a row does not fit the columns"},
		"group count": {cieHeader + "cie-a     \tvsys1 \t    x\t\tNever\t\t\tNever\t\n", 2, "the group count is no number"},
	} {
		_, err := identity.ParseCIEStatus(plain(c.body))
		pe := partError(t, err, identity.PartCIE)
		if pe.Line != c.line || pe.Why != c.why {
			t.Errorf("%s: line %d %q, want line %d %q", name, pe.Line, pe.Why, c.line, c.why)
		}
	}
}

// U8, X1: plain-text blocks split by an empty line: Primary and a tab, Email
// on the same line when set, then Alt User Names and numbered lines. Every
// name stays as printed. U18: a block that a User-ID groups message rewrote
// holds the primary name only, in the NetBIOS form.
func TestParseUserAttributes(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseUserAttributes(answer(t, "answer-user-attributes.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []identity.Attributes{
		{Primary: `example.com\alice`, Email: "alice@example.com", Alt: []string{"Alice@example.com", `example.com\alice`}},
		{Primary: `example.com\bob`, Email: "robert@example.com", Alt: []string{"bob@example.com"}},
		{Primary: `example\carol`},
		{Primary: `example.com\dave`, Alt: []string{"dave@example.com"}},
		{Primary: `other\ghost`},
		{Primary: `example.com\pc01$`},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("blocks %+v\nwant %+v", got, want)
	}
	// U8 by one user answers one block; C7: an empty result.
	one, err := identity.ParseUserAttributes(plain("\nPrimary: example\\alice\t\n"))
	if err != nil || !reflect.DeepEqual(one, []identity.Attributes{{Primary: `example\alice`}}) {
		t.Errorf("one block: %+v, %v", one, err)
	}
	if none, err := identity.ParseUserAttributes(plain("")); err != nil || len(none) != 0 {
		t.Errorf("no block: %+v, %v", none, err)
	}
	// An email on a line of its own reads too.
	own, err := identity.ParseUserAttributes(plain("\nPrimary: example.com\\bob\t\nEmail: robert@example.com\n"))
	if err != nil || len(own) != 1 || own[0].Email != "robert@example.com" {
		t.Errorf("an email line: %+v, %v", own, err)
	}
}

// A U8 answer that does not fit the layout of X1 is a *PartError of
// users.names at its line.
func TestParseUserAttributesRefusesABrokenBlock(t *testing.T) {
	t.Parallel()
	const alice = "Primary: example.com\\alice\tEmail: alice@example.com\n"
	for name, c := range map[string]struct {
		body string
		line int
		why  string
	}{
		"before a block":  {"\n1) alice@example.com\n", 2, "a line comes before a primary name"},
		"two primaries":   {"\n" + alice + "Primary: example.com\\bob\t\n", 3, "a block holds two primary names"},
		"no name":         {"\nPrimary: \t\n", 2, "a primary line does not fit"},
		"other text":      {"\nPrimary: example.com\\alice\tPhone: 1\n", 2, "a primary line does not fit"},
		"two emails":      {"\n" + alice + "Email: alice@example.com\n", 3, "a block holds two emails"},
		"alt out of list": {"\n" + alice + "1) alice@example.com\n", 3, "a line of a block does not fit"},
		"alt no number":   {"\n" + alice + "Alt User Names: \nx) alice@example.com\n", 4, "an alternate name line does not fit"},
		"alt no name":     {"\n" + alice + "Alt User Names: \n1) \n", 4, "an alternate name line does not fit"},
	} {
		_, err := identity.ParseUserAttributes(plain(c.body))
		pe := partError(t, err, identity.PartUserNames)
		if pe.Line != c.line || pe.Why != c.why {
			t.Errorf("%s: line %d %q, want line %d %q", name, pe.Line, pe.Why, c.line, c.why)
		}
	}
}

// U9, X1: XML entries user= with tag/member, then count.
func TestParseRegisteredUsers(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseRegisteredUsers(answer(t, "answer-registered-user.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []identity.Tags{
		{User: `example.com\carol`, Tags: []string{"tag-a", "tag-b"}},
		{User: `example.com\dave`, Tags: []string{"tag-a"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("tags %+v\nwant %+v", got, want)
	}
	// C7: no registration.
	if none, err := identity.ParseRegisteredUsers(plain("<count>0</count>\n")); err != nil || len(none) != 0 {
		t.Errorf("no registration: %+v, %v", none, err)
	}
	_, err = identity.ParseRegisteredUsers(plain(`<entry user="example.com\carol"><tag><member>tag-a</member></tag></entry>` +
		`<entry><tag><member>tag-a</member></tag></entry>`))
	if pe := partError(t, err, identity.PartTags); pe.Entry != 2 || pe.Why != "the entry has no user" {
		t.Errorf("an entry without a user: %v", err)
	}
}

// U4 (round 3): the short name (LDAP only), the source type, the source and
// the members, flat. A DUG adds Group type: Dynamic. A group without members
// answers a text, which reads as no member.
func TestParseGroupName(t *testing.T) {
	t.Parallel()
	got, err := identity.ParseGroupName(answer(t, "answer-group-name.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := identity.GroupAnswer{
		ShortName: `example.com\domain users`, SourceType: "ldap", Source: "example.com",
		Members: []string{`example.com\alice`, `example.com\bob`, `example.com\carol`},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("group %+v\nwant %+v", got, want)
	}
	for name, c := range map[string]struct {
		body string
		want identity.GroupAnswer
	}{
		"xmlapi": {
			"\n\nsource type: xmlapi\n\n[1     ] example.com\\carol\n[2     ] other\\ghost\n\n",
			identity.GroupAnswer{SourceType: "xmlapi", Members: []string{`example.com\carol`, `other\ghost`}},
		},
		"dug": {
			"\n\nsource type: xmlapi\nGroup type: Dynamic\n\n[1     ] example.com\\carol\n\n",
			identity.GroupAnswer{SourceType: "xmlapi", Type: "Dynamic", Members: []string{`example.com\carol`}},
		},
		"ten members": {
			"\n\nsource type: xmlapi\n\n[10    ] example.com\\carol\n\n",
			identity.GroupAnswer{SourceType: "xmlapi", Members: []string{`example.com\carol`}},
		},
		"no member": {
			"\nUser group 'cn=empty,ou=groups,dc=example,dc=com' does not exist or does not have members\n",
			identity.GroupAnswer{},
		},
	} {
		got, err := identity.ParseGroupName(cdata(c.body))
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %+v, %v\nwant %+v", name, got, err, c.want)
		}
	}
	for name, c := range map[string]struct {
		body string
		line int
	}{
		"no index":   {"\n\nsource type: xmlapi\n\n[x     ] example.com\\carol\n", 5},
		"no member":  {"\n\nsource type: xmlapi\n\n[1     ] \n", 5},
		"no bracket": {"\n\nsource type: xmlapi\n\n[1      example.com\\carol\n", 5},
		"other line": {"\nmembers of example.com\\carol\n", 2},
	} {
		_, err := identity.ParseGroupName(cdata(c.body))
		pe := partError(t, err, identity.PartGroups)
		if pe.Line != c.line || strings.Contains(err.Error(), "carol") {
			t.Errorf("%s: %v, want line %d", name, err, c.line)
		}
	}
}

// Every parser refuses an answer that is no success response, or no XML, as
// a *PartError of its part that quotes nothing of the answer. A text answer
// holds no element.
func TestParsersRefuseOtherAnswers(t *testing.T) {
	t.Parallel()
	parsers := []struct {
		name, part string
		text       bool // the result holds text (X1), else XML
		parse      func([]byte) error
	}{
		{"mappings", identity.PartMappings, false, func(b []byte) error { _, err := identity.ParseMappings(b); return err }},
		{"user-ids", identity.PartUserGroups, true, func(b []byte) error { _, err := identity.ParseUserIDs(b); return err }},
		{"match-user", identity.PartUserGroups, true, func(b []byte) error { _, err := identity.ParseUserIDsMatch(b); return err }},
		{"group list", identity.PartGroups, true, func(b []byte) error { _, err := identity.ParseGroupList(b); return err }},
		{"statistics", identity.PartLDAP, false, func(b []byte) error { _, err := identity.ParseGroupMappingStatistics(b); return err }},
		{"state", identity.PartLDAP, true, func(b []byte) error { _, err := identity.ParseGroupMappingState(b); return err }},
		{"cie", identity.PartCIE, true, func(b []byte) error { _, err := identity.ParseCIEStatus(b); return err }},
		{"attributes", identity.PartUserNames, true, func(b []byte) error { _, err := identity.ParseUserAttributes(b); return err }},
		{"tags", identity.PartTags, false, func(b []byte) error { _, err := identity.ParseRegisteredUsers(b); return err }},
		{"group name", identity.PartGroups, true, func(b []byte) error { _, err := identity.ParseGroupName(b); return err }},
	}
	answers := map[string][]byte{
		"refusal":    []byte(`<response status="error" code="17"><msg><line>refused for example.com\alice</line></msg></response>`),
		"other root": []byte(`<config><alice/></config>`),
		"no xml":     []byte(`example.com\alice`),
		"cut":        []byte(`<response status="success"><result>example.com\alice`),
		"empty":      nil,
	}
	for _, p := range parsers {
		for name, b := range answers {
			err := p.parse(b)
			if pe := partError(t, err, p.part); strings.Contains(pe.Error(), "alice") {
				t.Errorf("%s, %s: %q quotes the answer", p.name, name, pe)
			}
		}
		// A text answer holds no element, and an XML answer no text.
		in, why := plain(`<msg>example.com\alice</msg>`), "the answer holds an element, not text"
		if !p.text {
			in, why = plain(`example.com\alice`), "the answer holds text of no known form"
		}
		if pe := partError(t, p.parse(in), p.part); pe.Why != why {
			t.Errorf("%s: %q, want %q", p.name, pe.Why, why)
		}
	}
}

// §3.3: the text of a *PartError names the part, then the entry or the line,
// then the reason.
func TestPartErrorText(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err  identity.PartError
		want string
	}{
		{identity.PartError{Part: identity.PartMappings, Entry: 3, Why: "the address does not read"}, "mappings: entry 3: the address does not read"},
		{identity.PartError{Part: identity.PartUserGroups, Line: 7, Why: "the table has no total"}, "users.groups: line 7: the table has no total"},
		{identity.PartError{Part: identity.PartTags, Why: "the answer is no XML"}, "tags: the answer is no XML"},
	} {
		if got := c.err.Error(); got != c.want {
			t.Errorf("%q, want %q", got, c.want)
		}
	}
}
