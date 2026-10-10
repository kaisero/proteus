package simulate

import (
	"net/netip"
	"testing"

	"github.com/okaiser/proteus/internal/reason"
)

func TestDNSNotes(t *testing.T) {
	t.Parallel()
	a := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, x := range s {
			out = append(out, netip.MustParseAddr(x))
		}
		return out
	}
	f := Flow{
		Source:      Endpoint{Name: "src.example", Addrs: a("198.18.0.1", "2001:db8::1"), Canonical: "edge.example"},
		Destination: Endpoint{Name: "dst.example", Addrs: a("198.18.0.2", "198.18.0.3", "198.18.0.4")},
	}
	want := Reasons{
		reason.New("dns.canonical-name", "src.example has the canonical name edge.example, as this machine's resolver reports it"),
		reason.New("dns.other-addresses", "src.example resolved to 2 addresses; traced 198.18.0.1, not 2001:db8::1"),
		reason.New("dns.other-addresses", "dst.example resolved to 3 addresses; traced 198.18.0.2, not 198.18.0.3, 198.18.0.4"),
	}
	if got := DNSNotes(f, true); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("traced: %v", got)
	}
	if got := DNSNotes(f, false); len(got) != 1 || got[0] != want[0] {
		t.Errorf("not traced, only the alias: %v", got)
	}
	if got := DNSNotes(Flow{Source: Addr(netip.MustParseAddr("198.18.0.1"))}, true); got != nil {
		t.Errorf("an address has no DNS note: %v", got)
	}
}
