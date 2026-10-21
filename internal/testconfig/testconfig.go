// Package testconfig writes generated firewall configurations for benchmarks.
// R7 wants a benchmark behind every performance figure, and the figures for
// group trees only appear at a size no fixture in this repository has. The
// index and card benchmarks read the same file, so their figures describe one
// configuration. It also writes the App-ID content fixture and the identity
// fixture, so the tests of every package read one file of each, and the
// generated content and identity files of the benchmark of the MCP cache. It
// imports testing; only tests import it. It does not import internal/appid or
// internal/identity, so the tests of those packages can use it.
package testconfig

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The group tree of Groups: 2,000 address groups over six nesting levels. A
// group of the lowest level holds ten addresses, and every 25th of them is
// dynamic; every other group holds three groups of the level below and two
// addresses.
const (
	TreeGroups     = 2000
	groupsPerLevel = 334
	leafAddrs      = 10
	innerGroups    = 3
	innerAddrs     = 2
)

// TopRule names a rule whose source is a group of the top level, g-1999: its
// tree holds 364 groups. It exists when Groups.Rules is above 997.
const TopRule = "r-997"

// Groups is the shape of a generated configuration, all in vsys1.
type Groups struct {
	Addrs int // addresses a-0 …, each tagged t0 to t49
	Rules int // rules r-0 …, each naming a group of the upper three tree levels
	// Ring adds that many static groups c-0 …, each holding the next and the
	// last holding the first, and a rule naming c-0.
	Ring int
	// Dense adds that many static groups d-0 …, each holding three others of
	// them and an address, and a rule naming each.
	Dense int
}

// Write writes the configuration to a file in a temporary directory and returns
// its path.
func Write(tb testing.TB, g Groups) string {
	tb.Helper()
	var b strings.Builder
	b.WriteString(`<config version="11.2.0" urldb="paloaltonetworks"><devices>` +
		`<entry name="localhost.localdomain"><vsys><entry name="vsys1"><address>`)
	for i := range g.Addrs {
		fmt.Fprintf(&b, `<entry name="a-%d"><ip-netmask>10.88.%d.%d</ip-netmask>`+
			`<tag><member>t%d</member></tag></entry>`, i, i/256%256, i%256, i%50)
	}
	b.WriteString(`</address><address-group>`)
	for i := range TreeGroups {
		level := i / groupsPerLevel
		fmt.Fprintf(&b, `<entry name="g-%d">`, i)
		switch {
		case level == 0 && i%25 == 0:
			fmt.Fprintf(&b, `<dynamic><filter>'t%d'</filter></dynamic>`, i%50)
		case level == 0:
			b.WriteString(`<static>`)
			for j := range leafAddrs {
				fmt.Fprintf(&b, `<member>a-%d</member>`, (i*leafAddrs+j)%g.Addrs)
			}
			b.WriteString(`</static>`)
		default:
			b.WriteString(`<static>`)
			for j := range innerGroups {
				fmt.Fprintf(&b, `<member>g-%d</member>`, (level-1)*groupsPerLevel+(i*innerGroups+j)%groupsPerLevel)
			}
			for j := range innerAddrs {
				fmt.Fprintf(&b, `<member>a-%d</member>`, (i*innerAddrs+j)%g.Addrs)
			}
			b.WriteString(`</static>`)
		}
		b.WriteString(`</entry>`)
	}
	for i := range g.Ring {
		fmt.Fprintf(&b, `<entry name="c-%d"><static><member>c-%d</member><member>a-%d</member></static></entry>`,
			i, (i+1)%g.Ring, i%g.Addrs)
	}
	for i := range g.Dense {
		fmt.Fprintf(&b, `<entry name="d-%d"><static><member>d-%d</member><member>d-%d</member>`+
			`<member>d-%d</member><member>a-%d</member></static></entry>`,
			i, (i+1)%g.Dense, (i*7+3)%g.Dense, (i*11+5)%g.Dense, i%g.Addrs)
	}
	b.WriteString(`</address-group><rulebase><security><rules>`)
	upper := 3 * groupsPerLevel
	for i := range g.Rules {
		rule(&b, fmt.Sprintf("r-%d", i), fmt.Sprintf("g-%d", upper+i%(TreeGroups-upper)), fmt.Sprintf("a-%d", (i*7)%g.Addrs))
	}
	if g.Ring > 0 {
		rule(&b, "r-ring", "c-0", "any")
	}
	for i := range g.Dense {
		rule(&b, fmt.Sprintf("r-dense-%d", i), fmt.Sprintf("d-%d", i), "any")
	}
	b.WriteString(`</rules></security></rulebase></entry></vsys></entry></devices></config>`)

	path := filepath.Join(tb.TempDir(), "firewall.xml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// rule writes an allow rule from a source to a destination.
func rule(b *strings.Builder, name, src, dst string) {
	fmt.Fprintf(b, `<entry name="%s"><from><member>any</member></from><to><member>any</member></to>`+
		`<source><member>%s</member></source><destination><member>%s</member></destination>`+
		`<application><member>any</member></application><service><member>any</member></service>`+
		`<action>allow</action></entry>`, name, src, dst)
}

// Content gzips testdata/appid/content.xml, the trimmed App-ID content file of
// version 8000-1000, to dst.
func Content(tb testing.TB, dst string) {
	tb.Helper()
	writeGzipped(tb, dst, "appid", "content.xml")
}

// Identity gzips testdata/identity/identity.json, the identity file of the
// fixture in format 1 (spec 2026-10-17 §4.1), to dst, mode 0600 as a snapshot
// holds it.
func Identity(tb testing.TB, dst string) {
	tb.Helper()
	writeGzipped(tb, dst, "identity", "identity.json")
}

// IdentityFile is a generated identity file in format 1 (spec 2026-10-17
// §4.1), gzipped, with every part complete. Its users example.com\member-00000
// … each have an alternate name and an email, groupsPerUser distinct LDAP
// groups of a list of max(groupsPerUser, users/5), and one registered tag.
// Its mappings map the addresses 2001:db8::1 … to the users in the form
// example\member-00000 …, as a device stores them (M2): the documentation
// prefix holds 100,000 addresses, and a parsed address keeps as many bytes
// for IPv6 as for IPv4. The benchmark of the MCP cache measures what it
// retains (§8).
func IdentityFile(tb testing.TB, users, groupsPerUser, mappings int) []byte {
	tb.Helper()
	groups := max(groupsPerUser, users/5)
	members := make([]int, groups)
	var b strings.Builder
	sep := func(i int) {
		if i > 0 {
			b.WriteByte(',')
		}
	}
	fmt.Fprintf(&b, `{"format":1,"taken_at":"2026-10-17T20:00:00Z","sources":{"ldap":[{"name":"example.com",`+
		`"domain":"example.com","base":"dc=example,dc=com","groups":%d}],"cie":[]},"users":[`, groups)
	for i := range users {
		sep(i)
		fmt.Fprintf(&b, `{"name":"example.com\\member-%05d","alt":["member-%05d@example.com"],`+
			`"email":"member-%05d@example.com","groups":[`, i, i, i)
		for j := range groupsPerUser {
			sep(j)
			g := (i + j) % groups
			members[g]++
			fmt.Fprintf(&b, `"cn=group-%04d,ou=groups,dc=example,dc=com"`, g)
		}
		b.WriteString(`]}`)
	}
	b.WriteString(`],"groups":[`)
	for g, n := range members {
		sep(g)
		fmt.Fprintf(&b, `{"name":"cn=group-%04d,ou=groups,dc=example,dc=com","source":"ldap:example.com","members":%d}`, g, n)
	}
	b.WriteString(`],"dugs":[],"tags":[`)
	for i := range users {
		sep(i)
		fmt.Fprintf(&b, `{"user":"example.com\\member-%05d","tags":["tag-%d"]}`, i, i%10)
	}
	b.WriteString(`],"mappings":[`)
	for i := range mappings {
		sep(i)
		fmt.Fprintf(&b, `{"ip":"2001:db8::%x:%x","user":"example\\member-%05d","type":"XMLAPI","timeout":14400}`,
			(i+1)>>16, (i+1)&0xffff, i%max(users, 1))
	}
	b.WriteString("],\"parts_missing\":[]}\n")
	return gzipped([]byte(b.String()))
}

// writeGzipped gzips a file below testdata to dst, mode 0600.
func writeGzipped(tb testing.TB, dst string, path ...string) {
	tb.Helper()
	_, self, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(append([]string{filepath.Dir(self), "..", "..", "testdata"}, path...)...))
	if err == nil {
		err = os.WriteFile(dst, gzipped(raw), 0o600)
	}
	if err != nil {
		tb.Fatal(err)
	}
}

// gzipped is raw, gzipped. The gzip writer fails only when the writer under
// it fails, and a bytes.Buffer takes every write.
func gzipped(raw []byte) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return b.Bytes()
}

// appCategories are the six category values of the content answer (spec
// 2026-10-16 F5).
var appCategories = []string{"networking", "collaboration", "media", "business-systems", "general-internet", "saas"}

// appFlags are the yes/no filter fields of an application entry (S10).
var appFlags = []string{
	"evasive-behavior", "consume-big-bandwidth", "used-by-malware", "able-to-transfer-file",
	"has-known-vulnerability", "tunnel-other-application", "prone-to-misuse", "pervasive-use",
}

// AppContent is a generated App-ID content file of version 8000-1000 with
// that many applications app-0 …, gzipped, in the trimmed format. Every
// 50th application is a function of a container c-0 …. The entries hold every
// kept field of a real one and about the same bytes: content 9159 has 5552
// applications in a trimmed file of about 6 MB (spec 2026-10-16 F4). The
// benchmark of the MCP cache measures what it retains.
func AppContent(tb testing.TB, apps int) []byte {
	tb.Helper()
	var b strings.Builder
	b.WriteString(`<content version="8000-1000" trim="1"><application>`)
	// The description takes about 300 bytes, as in content 9159 (F4).
	desc := strings.Repeat("Dummy description of a generated application. ", 6)
	for i := range apps {
		fmt.Fprintf(&b, `<entry name="app-%d"><category>%s</category><subcategory>sub-%d</subcategory>`+
			`<technology>tech-%d</technology><description>%s%d.</description>`+
			`<default><port><member>tcp/%d,%d</member><member>udp/%d</member></port>`,
			i, appCategories[i%len(appCategories)], i%40, i%4, desc, i, 1024+i%60000, 2048+i%60000, 1024+i%60000)
		if i%2 == 0 {
			fmt.Fprintf(&b, `<extended-port><member>tcp/%d/secure</member></extended-port>`, 8443+i%1000)
		}
		fmt.Fprintf(&b, `</default><risk>%d</risk>`, 1+i%5)
		for j, f := range appFlags {
			fmt.Fprintf(&b, `<%s>%s</%s>`, f, yesNo((i+j)%3 == 0), f)
		}
		saas := i%6 == 5
		fmt.Fprintf(&b, `<is-saas>%s</is-saas><new-appid>no</new-appid><ident-by-dport>%s</ident-by-dport>`+
			`<tag><member>[Web App]</member><member>[Generated %d]</member></tag>`, yesNo(saas), yesNo(i%2 == 0), i%20)
		if saas {
			fmt.Fprintf(&b, `<saas><is-data-breaches>%s</is-data-breaches><is-poor-terms-of-service>no</is-poor-terms-of-service>`+
				`<certifications><is-soc2>%s</is-soc2></certifications></saas>`, yesNo(i%4 == 0), yesNo(i%3 == 0))
		}
		if i%3 == 0 {
			fmt.Fprintf(&b, `<implicit-use-applications><member>app-%d</member></implicit-use-applications>`+
				`<use-applications><member>app-%d</member></use-applications>`, (i+1)%apps, (i+2)%apps)
		}
		if i%50 == 0 {
			fmt.Fprintf(&b, `<application-container>c-%d</application-container>`, i/50)
		}
		b.WriteString(`</entry>`)
	}
	b.WriteString(`</application><application-container>`)
	for i := 0; i < apps; i += 50 {
		fmt.Fprintf(&b, `<entry name="c-%d"><description>%s</description><functions><member>app-%d</member></functions></entry>`,
			i/50, desc, i)
	}
	b.WriteString("</application-container></content>\n")
	return gzipped([]byte(b.String()))
}

// yesNo is a flag as the content file writes it.
func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
