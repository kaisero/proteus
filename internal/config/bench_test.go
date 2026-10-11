package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Load parses the file and takes the schema from a process-wide cache. The first
// Load in a process also decodes the digest and builds the reference table, which
// together cost about 55 ms; every Load after that does not.
func BenchmarkLoad(b *testing.B) {
	for b.Loop() {
		if _, _, err := Load("../../testdata/config/firewall-multivsys.xml"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBuildRefTable(b *testing.B) {
	cfg, _, err := Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		_ = buildRefTable(cfg.schema.root)
	}
}

// WalkPaths builds an entry's instance path once per entry, not once per value
// it emits.
func BenchmarkWalkPaths(b *testing.B) {
	cfg, _, err := Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		_ = cfg.WalkPaths(func(Event) bool { return true })
	}
}

func BenchmarkBuildPathTable(b *testing.B) {
	cfg, _, err := Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		_ = buildPathTable(cfg.schema.root)
	}
}

// writeLarge generates a firewall configuration of about 9 MB: 20,000
// addresses, 2,000 static groups of ten members and 10,000 security rules, each
// rule with a profile group and a log setting.
func writeLarge(tb testing.TB) string {
	tb.Helper()
	var b strings.Builder
	b.WriteString(`<config version="11.2.0" urldb="paloaltonetworks"><devices>` +
		`<entry name="localhost.localdomain"><vsys><entry name="vsys1"><address>`)
	for i := range 20000 {
		fmt.Fprintf(&b, `<entry name="a-%d"><ip-netmask>10.88.%d.%d</ip-netmask>`+
			`<tag><member>t%d</member></tag><description>host %d</description></entry>`, i, i/256%256, i%256, i%50, i)
	}
	b.WriteString(`</address><address-group>`)
	for i := range 2000 {
		fmt.Fprintf(&b, `<entry name="g-%d"><static>`, i)
		for j := range 10 {
			fmt.Fprintf(&b, `<member>a-%d</member>`, (i*10+j)%20000)
		}
		b.WriteString(`</static></entry>`)
	}
	b.WriteString(`</address-group><rulebase><security><rules>`)
	for i := range 10000 {
		fmt.Fprintf(&b, `<entry name="r-%d"><from><member>inside</member></from><to><member>outside</member></to>`+
			`<source><member>g-%d</member></source><destination><member>a-%d</member></destination>`+
			`<application><member>any</member></application><service><member>application-default</member></service>`+
			`<profile-setting><group><member>pg</member></group></profile-setting><log-setting>ls</log-setting>`+
			`<action>allow</action></entry>`, i, i%2000, i%20000)
	}
	b.WriteString(`</rules></security></rulebase></entry></vsys></entry></devices></config>`)
	path := filepath.Join(tb.TempDir(), "large.xml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// R3's count walks the whole tree against the digest. On the large file it adds
// about 3% to Load: 4.4 ms of 158 ms on an Apple M3 Pro (BenchmarkLoadLarge,
// BenchmarkUndescribedLarge).
func BenchmarkLoadLarge(b *testing.B) {
	path := writeLarge(b)
	for b.Loop() {
		if _, _, err := Load(path); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUndescribedLarge(b *testing.B) {
	cfg, _, err := Load(writeLarge(b))
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if u := cfg.undescribed(); len(u) != 0 {
			b.Fatalf("untyped %v", u)
		}
	}
}
