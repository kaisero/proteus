package nat

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/simulate"
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

// writePoolGroup generates a firewall configuration with addrs address objects,
// members of which, pool-0 to pool-<members-1>, form the static group pool-grp.
// One rule translates every source from trust to untrust to that group, so a
// translation looks up each member by name. R7: the NAT translation figure comes
// from this file.
func writePoolGroup(tb testing.TB, addrs, members int) string {
	tb.Helper()
	var b strings.Builder
	b.WriteString(`<config version="11.2.0" urldb="paloaltonetworks"><devices>` +
		`<entry name="localhost.localdomain"><vsys><entry name="vsys1"><address>`)
	for i := range addrs - members {
		fmt.Fprintf(&b, `<entry name="h-%d"><ip-netmask>10.88.%d.%d</ip-netmask></entry>`, i, i/256%256, i%256)
	}
	for i := range members {
		fmt.Fprintf(&b, `<entry name="pool-%d"><ip-netmask>198.18.%d.%d</ip-netmask></entry>`, i, i/256, i%256)
	}
	b.WriteString(`</address><address-group><entry name="pool-grp"><static>`)
	for i := range members {
		fmt.Fprintf(&b, `<member>pool-%d</member>`, i)
	}
	b.WriteString(`</static></entry></address-group><rulebase><nat><rules>` +
		`<entry name="snat-pool"><from><member>trust</member></from><to><member>untrust</member></to>` +
		`<source><member>any</member></source><destination><member>any</member></destination>` +
		`<service>any</service><source-translation><dynamic-ip-and-port>` +
		`<translated-address><member>pool-grp</member></translated-address>` +
		`</dynamic-ip-and-port></source-translation></entry>` +
		`</rules></nat></rulebase></entry></vsys></entry></devices></config>`)

	path := filepath.Join(tb.TempDir(), "firewall.xml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// BenchmarkTranslatePoolGroup translates one outbound flow by a rule whose
// source pool is a static group of 200 address objects, among 20,000.
func BenchmarkTranslatePoolGroup(b *testing.B) {
	cfg, _, err := config.Load(writePoolGroup(b, 20000, 200))
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
	m := Match(in)
	if r := Translate(in, m); r.Source == nil || len(r.Source.Candidates) != 200 || r.Flow.Source.String() != "198.18.0.0" {
		b.Fatalf("source %+v, flow %s: want 200 candidates and 198.18.0.0", r.Source, r.Flow.Source)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = Translate(in, m)
	}
}
