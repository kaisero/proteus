package simulate

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/okaiser/proteus/internal/config"
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
	if _, err := (Target{}).Index(resolve.Security, "vsys1"); err == nil || err.Error() != "no index provider" {
		t.Errorf("no provider: %v", err)
	}
	failing := Target{Indexes: func(resolve.Rulebase) (*index.Index, error) { return nil, errors.New("broken") }}
	if _, err := failing.Index(resolve.NAT, "vsys1"); err == nil || err.Error() != "broken" {
		t.Errorf("a failed provider: %v", err)
	}
	empty := Target{Indexes: func(resolve.Rulebase) (*index.Index, error) { return nil, nil }}
	if _, err := empty.Index(resolve.Security, "vsys1"); err == nil || err.Error() != "the index provider gives no index" {
		t.Errorf("no index: %v", err)
	}
	cfg, _, err := config.Load("../../testdata/config/firewall-simulate.xml")
	if err != nil {
		t.Fatal(err)
	}
	var asked resolve.Rulebase
	tg := Target{Indexes: func(rb resolve.Rulebase) (*index.Index, error) {
		asked = rb
		return index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, rb)
	}}
	if idx, err := tg.Index(resolve.NAT, "vsys1"); err != nil || idx == nil || asked != resolve.NAT {
		t.Errorf("provider asked for %v: %v", asked, err)
	}
	// A provider of another vsys would answer with that vsys's rules.
	if _, err := tg.Index(resolve.Security, "vsys2"); err == nil || err.Error() != "the index provider gives vsys:vsys1, not vsys vsys2" {
		t.Errorf("another vsys: %v", err)
	}
}
