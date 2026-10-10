package index

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/resolve"
)

// Group tree shape of writeGroups: the groups, the groups per nesting level, and
// the members of each group.
const (
	totalGroups    = 2000
	groupsPerLevel = 334 // six levels
	leafAddrs      = 10  // addresses in a group of the lowest level
	innerGroups    = 3   // groups of the level below in every other group
	innerAddrs     = 2   // addresses in every other group, beside its groups
)

// writeGroups generates a firewall configuration whose rules name nested address
// groups. R7: the figures for the index build come from this file, because no
// fixture holds a group tree of this size.
//
// It holds addrs addresses, 2,000 address groups nested up to six levels deep
// (every 25th group of the lowest level is dynamic) and rules rules, each naming a
// group of the upper three levels as its source. cycle > 0 adds that many static
// groups, each holding the next, the last holding the first, and one rule naming
// the first.
func writeGroups(tb testing.TB, addrs, rules, cycle int) string {
	tb.Helper()
	var b strings.Builder
	b.WriteString(`<config version="11.2.0" urldb="paloaltonetworks"><devices>` +
		`<entry name="localhost.localdomain"><vsys><entry name="vsys1"><address>`)
	for i := range addrs {
		fmt.Fprintf(&b, `<entry name="a-%d"><ip-netmask>10.88.%d.%d</ip-netmask>`+
			`<tag><member>t%d</member></tag></entry>`, i, i/256%256, i%256, i%50)
	}
	b.WriteString(`</address><address-group>`)
	for i := range totalGroups {
		level := i / groupsPerLevel
		fmt.Fprintf(&b, `<entry name="g-%d">`, i)
		switch {
		case level == 0 && i%25 == 0:
			fmt.Fprintf(&b, `<dynamic><filter>'t%d'</filter></dynamic>`, i%50)
		case level == 0:
			b.WriteString(`<static>`)
			for j := range leafAddrs {
				fmt.Fprintf(&b, `<member>a-%d</member>`, (i*leafAddrs+j)%addrs)
			}
			b.WriteString(`</static>`)
		default:
			b.WriteString(`<static>`)
			for j := range innerGroups {
				fmt.Fprintf(&b, `<member>g-%d</member>`, (level-1)*groupsPerLevel+(i*innerGroups+j)%groupsPerLevel)
			}
			for j := range innerAddrs {
				fmt.Fprintf(&b, `<member>a-%d</member>`, (i*innerAddrs+j)%addrs)
			}
			b.WriteString(`</static>`)
		}
		b.WriteString(`</entry>`)
	}
	for i := range cycle {
		fmt.Fprintf(&b, `<entry name="c-%d"><static><member>c-%d</member><member>a-%d</member></static></entry>`,
			i, (i+1)%cycle, i%addrs)
	}
	b.WriteString(`</address-group><rulebase><security><rules>`)
	upper := 3 * groupsPerLevel
	for i := range rules {
		fmt.Fprintf(&b, `<entry name="r-%d"><from><member>any</member></from><to><member>any</member></to>`+
			`<source><member>g-%d</member></source><destination><member>a-%d</member></destination>`+
			`<application><member>any</member></application><service><member>any</member></service>`+
			`<action>allow</action></entry>`, i, upper+i%(totalGroups-upper), (i*7)%addrs)
	}
	if cycle > 0 {
		b.WriteString(`<entry name="r-cycle"><from><member>any</member></from><to><member>any</member></to>` +
			`<source><member>c-0</member></source><destination><member>any</member></destination>` +
			`<application><member>any</member></application><service><member>any</member></service>` +
			`<action>allow</action></entry>`)
	}
	b.WriteString(`</rules></security></rulebase></entry></vsys></entry></devices></config>`)

	path := filepath.Join(tb.TempDir(), "firewall.xml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// benchBuild measures the index build of vsys1 of a generated configuration. The
// edges are read once, outside the loop: the build is what is measured.
func benchBuild(b *testing.B, path string) {
	b.Helper()
	cfg, _, err := config.Load(path)
	if err != nil {
		b.Fatal(err)
	}
	edges, err := ReadEdges(cfg)
	if err != nil {
		b.Fatal(err)
	}
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Build(cfg, edges, sc, resolve.Security); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkIndexBuildNestedGroups builds the index of 20,000 addresses, 2,000
// nested address groups and 5,000 rules naming them.
func BenchmarkIndexBuildNestedGroups(b *testing.B) {
	benchBuild(b, writeGroups(b, 20000, 5000, 0))
}

// BenchmarkIndexBuildGroupCycle builds the same index with one long cycle of
// groups beside the tree.
func BenchmarkIndexBuildGroupCycle(b *testing.B) {
	for _, n := range []int{2000, 5000} {
		b.Run(fmt.Sprintf("groups=%d", n), func(b *testing.B) {
			benchBuild(b, writeGroups(b, 20000, 5000, n))
		})
	}
}
