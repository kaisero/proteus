package index

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/config"
)

// writePanorama generates a Panorama configuration of a given size.
//
// R7 wants a benchmark behind a performance figure, and the figures that matter
// here only appear at a size no fixture in this repository has: the cost being
// measured is per scope, and a small file has two or three. This writes one with
// as many scopes and rules as a mid-sized deployment.
func writePanorama(tb testing.TB, dgs, rulesPerDG, addrsPerDG, templates int) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "panorama.xml")
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

	b.WriteString(`<devices><entry name="localhost.localdomain"><template>`)
	for t := range templates {
		fmt.Fprintf(&b, `<entry name="tpl-%d"><config><devices><entry name="localhost.localdomain">`+
			`<network><interface><ethernet>`, t)
		for i := range 40 {
			fmt.Fprintf(&b, `<entry name="ethernet1/%d"><layer3>`+
				`<interface-management-profile>mgmt-%d</interface-management-profile>`+
				`</layer3></entry>`, i, i%4)
		}
		b.WriteString(`</ethernet></interface></network></entry></devices></config></entry>`)
	}
	b.WriteString(`</template><device-group>`)

	for d := range dgs {
		fmt.Fprintf(&b, `<entry name="dg-%d"><address>`, d)
		for i := range addrsPerDG {
			fmt.Fprintf(&b, `<entry name="a-%d-%d"><ip-netmask>172.%d.%d.0/24</ip-netmask>`+
				`<tag><member>tag-%d</member></tag></entry>`, d, i, d%256, i%256, i%40)
		}
		b.WriteString(`</address>`)
		for _, rb := range []string{"pre-rulebase", "post-rulebase"} {
			fmt.Fprintf(&b, `<%s><security><rules>`, rb)
			for i := range rulesPerDG / 2 {
				prof := `<profile-setting><group><member>pg</member></group></profile-setting>`
				if i%2 == 0 {
					prof = `<profile-setting><profiles>` +
						`<url-filtering><member>urlf</member></url-filtering>` +
						`<virus><member>av</member></virus></profiles></profile-setting>`
				}
				fmt.Fprintf(&b, `<entry name="r-%d-%s-%d">`+
					`<from><member>z%d</member></from><to><member>z%d</member></to>`+
					`<source><member>a-%d-%d</member></source>`+
					`<destination><member>any</member></destination>`+
					`<application><member>web-browsing</member></application>`+
					`<service><member>application-default</member></service>`+
					`<tag><member>tag-%d</member></tag>`+
					`<log-setting>lfp-%d</log-setting>%s<action>allow</action></entry>`,
					d, rb, i, i%8, (i+1)%8, d, i%addrsPerDG, i%40, i%6, prof)
			}
			fmt.Fprintf(&b, `</rules></security></%s>`, rb)
		}
		b.WriteString(`</entry>`)
	}
	b.WriteString(`</device-group></entry></devices></config>`)

	if _, err := f.WriteString(b.String()); err != nil {
		tb.Fatal(err)
	}
	return path
}

func loadedPanorama(tb testing.TB) (*config.Config, []config.Scope) {
	tb.Helper()
	cfg, _, err := config.Load(writePanorama(tb, 12, 1200, 1500, 5))
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
	cfg, scopes := loadedPanorama(b)
	b.ReportMetric(float64(len(scopes)), "scopes")
	for b.Loop() {
		resetEdgeCache()
		for _, sc := range scopes {
			if _, err := newRefsIndex(NewInterner(), cfg, sc); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// The read itself, which is now done once however many scopes ask for it.
func BenchmarkReadEdges(b *testing.B) {
	cfg, _ := loadedPanorama(b)
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

func resetEdgeCache() {
	edgeCacheMu.Lock()
	edgeCache = map[string]*edgeCacheEntry{}
	edgeCacheMu.Unlock()
}
