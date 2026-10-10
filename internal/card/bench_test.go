package card

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/resolve"
)

// writeGroupTree generates a firewall configuration with 20,000 addresses and
// 2,000 address groups nested six levels deep: a group of the lowest level holds
// ten addresses (every 25th is dynamic), every other group three groups of the
// level below and two addresses. Rule r-0 names a group of the top level, so its
// card holds a tree of 364 groups. R7: the lookup figure comes from this file.
func writeGroupTree(tb testing.TB) string {
	tb.Helper()
	const addrs, groups, perLevel = 20000, 2000, 334
	var b strings.Builder
	b.WriteString(`<config version="11.2.0" urldb="paloaltonetworks"><devices>` +
		`<entry name="localhost.localdomain"><vsys><entry name="vsys1"><address>`)
	for i := range addrs {
		fmt.Fprintf(&b, `<entry name="a-%d"><ip-netmask>10.88.%d.%d</ip-netmask>`+
			`<tag><member>t%d</member></tag></entry>`, i, i/256%256, i%256, i%50)
	}
	b.WriteString(`</address><address-group>`)
	for i := range groups {
		level := i / perLevel
		fmt.Fprintf(&b, `<entry name="g-%d">`, i)
		switch {
		case level == 0 && i%25 == 0:
			fmt.Fprintf(&b, `<dynamic><filter>'t%d'</filter></dynamic>`, i%50)
		case level == 0:
			b.WriteString(`<static>`)
			for j := range 10 {
				fmt.Fprintf(&b, `<member>a-%d</member>`, (i*10+j)%addrs)
			}
			b.WriteString(`</static>`)
		default:
			b.WriteString(`<static>`)
			for j := range 3 {
				fmt.Fprintf(&b, `<member>g-%d</member>`, (level-1)*perLevel+(i*3+j)%perLevel)
			}
			fmt.Fprintf(&b, `<member>a-%d</member><member>a-%d</member></static>`, (i*2)%addrs, (i*2+1)%addrs)
		}
		b.WriteString(`</entry>`)
	}
	fmt.Fprintf(&b, `</address-group><rulebase><security><rules>`+
		`<entry name="r-0"><from><member>any</member></from><to><member>any</member></to>`+
		`<source><member>g-%d</member></source><destination><member>any</member></destination>`+
		`<application><member>any</member></application><service><member>any</member></service>`+
		`<action>allow</action></entry>`+
		`</rules></security></rulebase></entry></vsys></entry></devices></config>`, groups-1)

	path := filepath.Join(tb.TempDir(), "firewall.xml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// BenchmarkRuleCardNestedGroups builds the lookup card of a rule whose source is
// a group tree of 364 groups, out of 2,000.
func BenchmarkRuleCardNestedGroups(b *testing.B) {
	cfg, _, err := config.Load(writeGroupTree(b))
	if err != nil {
		b.Fatal(err)
	}
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		cs, err := Find(cfg, idx, "r-0", KindRule)
		if err != nil || len(cs) != 1 {
			b.Fatalf("Find: %d cards, %v", len(cs), err)
		}
	}
}
