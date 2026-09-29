package index

import (
	"net/netip"
	"testing"
)

// IPv6 goes through the same containment as IPv4, and a range still has to be broken
// into prefixes. The arithmetic uses big.Int precisely because a v6 address does not fit
// in a uint64, so this is the case that exercises it.
func TestIPv6Containment(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-ipv6.xml", "vsys1")

	rules, rep := idx.Candidates(Source, "2001:db8:1::5")
	names := map[string]bool{}
	for _, h := range rep.Hits {
		names[h.Name] = true
	}
	for _, want := range []string{"v6-net", "v6-host"} {
		if !names[want] {
			t.Errorf("%s did not match 2001:db8:1::5, got %v", want, names)
		}
	}
	if !ruleNames(idx, rules)["v6-rule"] {
		t.Error("the rule naming the v6 network was not reached")
	}
}

// An IPv6 range decomposes into prefixes that cover it exactly, and nothing outside it.
func TestIPv6RangeDecomposition(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-ipv6.xml", "vsys1")

	for _, in := range []string{"2001:db8:2::1", "2001:db8:2::8", "2001:db8:2::10"} {
		if got := idx.Containing(netip.MustParseAddr(in)); len(got) == 0 {
			t.Errorf("%s is inside the range and was not matched", in)
		}
	}
	for _, out := range []string{"2001:db8:2::", "2001:db8:2::11", "2001:db8:3::1"} {
		if got := idx.Containing(netip.MustParseAddr(out)); len(got) != 0 {
			t.Errorf("%s is outside the range but matched %+v", out, got)
		}
	}
}

// A v6 prefix overlaps the objects inside it.
func TestIPv6Overlapping(t *testing.T) {
	idx := indexOf(t, "../../testdata/config/firewall-ipv6.xml", "vsys1")

	got := idx.Overlapping(netip.MustParsePrefix("2001:db8:1::/64"))
	if len(got) == 0 {
		t.Error("a v6 prefix overlapped nothing")
	}
}
