package resolve

import (
	"testing"

	"github.com/okaiser/proteus/internal/config"
)

// One shared dynamic group resolves to different members in each vsys, because
// only shared and the vsys itself contribute. Resolving it globally makes every
// result for a rule that uses it wrong rather than incomplete. First observed on
// Panorama 11.2.7-h1 across sibling device groups; sibling vsys on one firewall
// stand in the same relation.
func TestDynamicGroupResolvesPerScope(t *testing.T) {
	t.Parallel()
	tg, err := TargetFor(vsysLab(t), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	got, err := tg.ResolveGroup("corp-location")
	if err != nil {
		t.Fatalf("ResolveGroup: %v", err)
	}
	if len(got.ByTag) != 1 || got.ByTag[0] != "corp-location-vienna" {
		t.Errorf("resolved to %v, want [corp-location-vienna]", got.ByTag)
	}
	if got.Filter == "" {
		t.Error("a dynamic group must report its filter")
	}
	if got.Note == "" {
		t.Error("the result must say that runtime-registered members are not included")
	}
}

// The sibling vsys holds the Graz objects, so the same group resolves differently
// there. This is the case a global index would get wrong.
func TestDynamicGroupDiffersInASibling(t *testing.T) {
	t.Parallel()
	got, err := GroupInScope(vsysLab(t), config.Scope{Sort: config.ScopeVsys, Name: "vsys2"}, "corp-location")
	if err != nil {
		t.Fatalf("GroupInScope: %v", err)
	}
	if len(got.ByTag) != 1 || got.ByTag[0] != "corp-location-graz" {
		t.Errorf("vsys2 resolved to %v, want [corp-location-graz]", got.ByTag)
	}
}

// A vsys with no tagged objects of its own resolves the same group to nothing,
// which is the honest answer rather than the sibling's members.
func TestDynamicGroupIsEmptyWhereNothingIsTagged(t *testing.T) {
	t.Parallel()
	got, err := GroupInScope(vsysLab(t), config.Scope{Sort: config.ScopeVsys, Name: "vsys3"}, "corp-location")
	if err != nil {
		t.Fatalf("GroupInScope: %v", err)
	}
	if len(got.ByTag) != 0 {
		t.Errorf("vsys3 resolved to %v, want nothing", got.ByTag)
	}
}

func TestResolveGroupRejectsAnUnknownName(t *testing.T) {
	t.Parallel()
	tg, _ := TargetFor(vsysLab(t), "localhost.localdomain", "vsys1")
	if _, err := tg.ResolveGroup("no-such-group"); err == nil {
		t.Error("an unknown group must be an error")
	}
}

// A filter PAN-OS accepts but this parser does not must yield nothing and say so,
// rather than guess a membership.
func TestUnparseableFilterIsReported(t *testing.T) {
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-badfilter.xml")
	got, err := GroupInScope(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, "g-bad")
	if err != nil {
		t.Fatalf("GroupInScope: %v", err)
	}
	if len(got.ByTag) != 0 {
		t.Errorf("an unparseable filter must yield no members, got %v", got.ByTag)
	}
	if got.FilterError == "" {
		t.Error("it must say why")
	}
}

// A boolean filter resolves, not just a single tag.
func TestBooleanFilterResolves(t *testing.T) {
	t.Parallel()
	cfg := loadT(t, "../../testdata/config/firewall-badfilter.xml")
	sc := config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}
	and, err := GroupInScope(cfg, sc, "g-and")
	if err != nil {
		t.Fatalf("GroupInScope: %v", err)
	}
	if len(and.ByTag) != 1 || and.ByTag[0] != "h-both" {
		t.Errorf("'a' and 'b' resolved to %v, want [h-both]", and.ByTag)
	}
	notf, err := GroupInScope(cfg, sc, "g-not")
	if err != nil {
		t.Fatalf("GroupInScope: %v", err)
	}
	if len(notf.ByTag) != 1 || notf.ByTag[0] != "h-a" {
		t.Errorf("'a' and not 'b' resolved to %v, want [h-a]", notf.ByTag)
	}
}

// A static group reports its member list, not a filter.
func TestStaticGroupResolvesToItsMembers(t *testing.T) {
	t.Parallel()
	tg, err := TargetFor(fwLab(t), "localhost.localdomain", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := tg.ResolveGroup("g-servers")
	if err != nil {
		t.Fatalf("ResolveGroup: %v", err)
	}
	if len(got.Static) != 1 || got.Static[0] != "dc01" {
		t.Errorf("Static = %v, want [dc01]", got.Static)
	}
	if got.Filter != "" {
		t.Errorf("a static group has no filter, got %q", got.Filter)
	}
}
