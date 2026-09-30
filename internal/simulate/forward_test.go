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

func TestUnavailableErrorReadsAsItsReason(t *testing.T) {
	t.Parallel()
	one := &UnavailableError{Missing: []Missing{{Device: "fw1", Reason: "no snapshot"}}}
	if one.Error() != "no snapshot" {
		t.Errorf("one: %q", one.Error())
	}
	two := &UnavailableError{Missing: []Missing{{"fw1", "a"}, {"fw2", "b"}}}
	if two.Error() != "fw1: a; fw2: b" {
		t.Errorf("two: %q", two.Error())
	}
}
