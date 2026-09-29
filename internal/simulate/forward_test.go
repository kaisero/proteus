package simulate

import (
	"net/netip"
	"testing"

	"github.com/okaiser/proteus/internal/resolve"
)

func TestPortMatchAndChoice(t *testing.T) {
	t.Parallel()
	p := Port{Addr: netip.MustParsePrefix("10.0.0.1/24")}
	if p.Link().String() != "10.0.0.0/24" {
		t.Errorf("link = %s", p.Link())
	}
	m := Match{NextHops: []resolve.FIBRoute{{NextHop: "10.0.0.2"}, {NextHop: "10.0.0.3"}}}
	if m.First().NextHop != "10.0.0.2" {
		t.Error("first")
	}
	if (&ChoiceError{Question: "q"}).Error() != "q" || (&ChoiceError{Question: "q", Options: []string{"a", "b"}}).Error() != "q: a, b" {
		t.Error("choice")
	}
}
