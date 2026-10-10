package nat

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/simulate"
)

// writeBidirectional generates a firewall configuration with addrs address
// objects and rules bi-directional static NAT rules from trust to untrust. Rule i
// translates host h-i to the object nat-i, so each implicit rule asks which
// address nat-i holds. R7: the NAT match figure comes from this file.
func writeBidirectional(tb testing.TB, addrs, rules int) string {
	tb.Helper()
	var b strings.Builder
	b.WriteString(`<config version="11.2.0" urldb="paloaltonetworks"><devices>` +
		`<entry name="localhost.localdomain"><vsys><entry name="vsys1"><address>`)
	for i := range addrs - rules {
		fmt.Fprintf(&b, `<entry name="h-%d"><ip-netmask>10.88.%d.%d</ip-netmask></entry>`, i, i/256%256, i%256)
	}
	for i := range rules {
		fmt.Fprintf(&b, `<entry name="nat-%d"><ip-netmask>198.18.%d.%d</ip-netmask></entry>`, i, i/256, i%256)
	}
	b.WriteString(`</address><rulebase><nat><rules>`)
	for i := range rules {
		fmt.Fprintf(&b, `<entry name="bidir-%d"><from><member>trust</member></from><to><member>untrust</member></to>`+
			`<source><member>h-%d</member></source><destination><member>any</member></destination>`+
			`<service>any</service><source-translation><static-ip>`+
			`<translated-address>nat-%d</translated-address><bi-directional>yes</bi-directional>`+
			`</static-ip></source-translation></entry>`, i, i, i)
	}
	b.WriteString(`</rules></nat></rulebase></entry></vsys></entry></devices></config>`)

	path := filepath.Join(tb.TempDir(), "firewall.xml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// BenchmarkMatchBidirectional matches one outbound flow, which no rule
// translates, against 300 bi-directional rules and their 300 implicit rules,
// among 20,000 address objects.
func BenchmarkMatchBidirectional(b *testing.B) {
	cfg, _, err := config.Load(writeBidirectional(b, 20000, 300))
	if err != nil {
		b.Fatal(err)
	}
	in := Input{
		Target: withIndexes(cfg, "vsys1"), Vsys: "vsys1",
		Flow: simulate.Flow{
			Source:      simulate.Addr(netip.MustParseAddr("10.88.250.1")),
			Destination: simulate.Addr(netip.MustParseAddr("198.19.0.1")),
			Protocol:    "tcp", DestPort: 443,
		},
		In:     simulate.Port{Device: "fw", Router: "default", Zone: "trust"},
		PreNAT: &simulate.Forward{Out: simulate.Port{Zone: "untrust", Interface: "ethernet1/1"}},
	}
	if m := Match(in); m.Rule != nil || len(m.Excluded) != 600 {
		b.Fatalf("rule %v, %d excluded: want no rule and 600 excluded", m.Rule, len(m.Excluded))
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = Match(in)
	}
}
