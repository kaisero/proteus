package index

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/config"
)

// writeFirewall generates a multi-vsys firewall configuration of a given size.
//
// R7 wants a benchmark behind a performance figure, and the figures that matter
// here only appear at a size no fixture in this repository has: the cost being
// measured is per scope, and a small file has two or three. This writes one with
// as many vsys and rules as a large multi-vsys firewall.
func writeFirewall(tb testing.TB, vsyses, rulesPerVsys, addrsPerVsys int) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "firewall.xml")
	f, err := os.Create(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	var b strings.Builder

	b.WriteString(`<config version="11.2.0" urldb="paloaltonetworks"><shared><address>`)
	for i := range 2000 {
		fmt.Fprintf(&b, `<entry name="sh-%d"><ip-netmask>10.%d.%d.0/24</ip-netmask>`+
			`<tag><member>t%d</member></tag></entry>`, i, i/256%256, i%256, i%50)
	}
	b.WriteString(`</address><profile-group><entry name="pg"><virus><member>av</member></virus>` +
		`<url-filtering><member>urlf</member></url-filtering></entry></profile-group></shared>`)

	b.WriteString(`<devices><entry name="localhost.localdomain"><vsys>`)
	for v := range vsyses {
		fmt.Fprintf(&b, `<entry name="vsys%d"><address>`, v+1)
		for i := range addrsPerVsys {
			fmt.Fprintf(&b, `<entry name="a-%d-%d"><ip-netmask>172.%d.%d.0/24</ip-netmask>`+
				`<tag><member>tag-%d</member></tag></entry>`, v, i, v%256, i%256, i%40)
		}
		b.WriteString(`</address><rulebase><security><rules>`)
		for i := range rulesPerVsys {
			prof := `<profile-setting><group><member>pg</member></group></profile-setting>`
			if i%2 == 0 {
				prof = `<profile-setting><profiles>` +
					`<url-filtering><member>urlf</member></url-filtering>` +
					`<virus><member>av</member></virus></profiles></profile-setting>`
			}
			fmt.Fprintf(&b, `<entry name="r-%d-%d">`+
				`<from><member>z%d</member></from><to><member>z%d</member></to>`+
				`<source><member>a-%d-%d</member></source>`+
				`<destination><member>any</member></destination>`+
				`<application><member>web-browsing</member></application>`+
				`<service><member>application-default</member></service>`+
				`<tag><member>tag-%d</member></tag>`+
				`<log-setting>lfp-%d</log-setting>%s<action>allow</action></entry>`,
				v, i, i%8, (i+1)%8, v, i%addrsPerVsys, i%40, i%6, prof)
		}
		b.WriteString(`</rules></security></rulebase></entry>`)
	}
	b.WriteString(`</vsys></entry></devices></config>`)

	if _, err := f.WriteString(b.String()); err != nil {
		tb.Fatal(err)
	}
	return path
}

func loadedFirewall(tb testing.TB) (*config.Config, []config.Scope) {
	tb.Helper()
	cfg, _, err := config.Load(writeFirewall(tb, 12, 1200, 1500))
	if err != nil {
		tb.Fatal(err)
	}
	seen := map[string]bool{}
	var scopes []config.Scope
	_ = cfg.WalkPaths(func(e config.Event) bool {
		if !seen[e.Scope.String()] {
			seen[e.Scope.String()] = true
			scopes = append(scopes, e.Scope)
		}
		return true
	})
	return cfg, scopes
}

// Building one reference index per scope. Before the edge list was shared this
// read the whole configuration once per scope and discarded what it could not see.
func BenchmarkRefsIndexEveryScope(b *testing.B) {
	cfg, scopes := loadedFirewall(b)
	for b.Loop() {
		edges, err := ReadEdges(cfg)
		if err != nil {
			b.Fatal(err)
		}
		for _, sc := range scopes {
			newRefsIndex(NewInterner(), edges.list, sc)
		}
	}
	b.ReportMetric(float64(len(scopes)), "scopes")
}

// The read itself, which is now done once however many scopes ask for it.
func BenchmarkReadEdges(b *testing.B) {
	cfg, _ := loadedFirewall(b)
	var n int
	for b.Loop() {
		e, err := readEdges(cfg)
		if err != nil {
			b.Fatal(err)
		}
		n = len(e)
	}
	b.ReportMetric(float64(n), "edges")
}
