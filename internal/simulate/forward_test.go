package simulate

import (
	"net/netip"
	"testing"

	"github.com/okaiser/proteus/internal/index"
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
	two := &UnavailableError{Missing: []Missing{{Device: "fw1", Reason: "a"}, {Device: "fw2", Reason: "b"}}}
	if two.Error() != "fw1: a; fw2: b" {
		t.Errorf("two: %q", two.Error())
	}
}

// A target's index comes from its provider; without one it is an error, never
// an index built here.
func TestTargetIndexComesFromItsProvider(t *testing.T) {
	t.Parallel()
	if _, err := (Target{}).Index(resolve.Security); err == nil || err.Error() != "no index provider" {
		t.Errorf("no provider: %v", err)
	}
	var asked resolve.Rulebase
	tg := Target{Indexes: func(rb resolve.Rulebase) (*index.Index, error) { asked = rb; return nil, nil }}
	if _, err := tg.Index(resolve.NAT); err != nil || asked != resolve.NAT {
		t.Errorf("provider asked for %v: %v", asked, err)
	}
}
