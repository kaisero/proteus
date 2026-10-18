package simulate

import (
	"net/netip"
	"testing"

	"github.com/kaisero/proteus/internal/reason"
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
	if got := DNSNotes(f, "traced"); len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("traced: %v", got)
	}
	if got := DNSNotes(f, "checked"); len(got) != 3 || got[2].Text != "dst.example resolved to 3 addresses; checked 198.18.0.2, not 198.18.0.3, 198.18.0.4" {
		t.Errorf("checked: %v", got)
	}
	if got := DNSNotes(Flow{Source: Addr(netip.MustParseAddr("198.18.0.1"))}, "traced"); got != nil {
		t.Errorf("an address has no DNS note: %v", got)
	}
}

// Each endpoint keeps its first address and its name; the flow given is not
// changed.
func TestFirstAddresses(t *testing.T) {
	t.Parallel()
	a, b := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("198.18.0.3")
	f := Flow{
		Source:      Addr(netip.MustParseAddr("198.18.0.1")),
		Destination: Endpoint{Name: "dst.example", Addrs: []netip.Addr{a, b}, Resolved: true},
	}
	got := f.FirstAddresses()
	if d := got.Destination; d.Name != "dst.example" || len(d.Addrs) != 1 || d.Addrs[0] != a || !d.Resolved {
		t.Errorf("destination %+v", d)
	}
	if len(got.Source.Addrs) != 1 || len(f.Destination.Addrs) != 2 {
		t.Errorf("source %+v, the flow given %+v", got.Source, f.Destination)
	}
	// Appending to the cut endpoint does not write into the flow given.
	_ = append(got.Destination.Addrs, netip.MustParseAddr("198.18.0.9"))
	if f.Destination.Addrs[1] != b {
		t.Errorf("the flow given changed: %v", f.Destination.Addrs)
	}
}
