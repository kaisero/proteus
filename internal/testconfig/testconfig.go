// Package testconfig writes generated firewall configurations for benchmarks.
// R7 wants a benchmark behind every performance figure, and the figures for
// group trees only appear at a size no fixture in this repository has. The
// index and card benchmarks read the same file, so their figures describe one
// configuration. It imports testing; only tests import it.
package testconfig

import (
	"fmt"
	"os"
	"path/filepath"
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
