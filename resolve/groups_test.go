package resolve

import (
	"testing"

	"github.com/okaiser/go-panos-schema/config"
)

// One shared dynamic group resolves to different members in each device group,
// because only the visible scope contributes. Resolving it globally makes every
// result for a rule that uses it wrong rather than incomplete.
// Observed on Panorama 11.2.7-h1.
func TestDynamicGroupResolvesPerScope(t *testing.T) {
	tg, err := TargetFor(lab(t), "007900000000003", "vsys1")
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

// The sibling device group holds the Graz objects, so the same group resolves
// differently there. This is the case a global index would get wrong.
func TestDynamicGroupDiffersInASibling(t *testing.T) {
	got, err := GroupInScope(lab(t), config.Scope{
		Sort: config.ScopeDeviceGroup, Name: "corp-graz",
	}, "corp-location")
	if err != nil {
		t.Fatalf("GroupInScope: %v", err)
	}
	if len(got.ByTag) != 1 || got.ByTag[0] != "corp-location-graz" {
		t.Errorf("corp-graz resolved to %v, want [corp-location-graz]", got.ByTag)
	}
}

// A device group with no tagged objects of its own resolves the same group to
// nothing, which is the honest answer rather than the sibling's members.
func TestDynamicGroupIsEmptyWhereNothingIsTagged(t *testing.T) {
	got, err := GroupInScope(lab(t), config.Scope{
		Sort: config.ScopeDeviceGroup, Name: "at-ktn",
	}, "corp-location")
	if err != nil {
		t.Fatalf("GroupInScope: %v", err)
	}
	if len(got.ByTag) != 0 {
		t.Errorf("at-ktn resolved to %v, want nothing", got.ByTag)
	}
}

func TestResolveGroupRejectsAnUnknownName(t *testing.T) {
	tg, _ := TargetFor(lab(t), "007900000000003", "vsys1")
	if _, err := tg.ResolveGroup("no-such-group"); err == nil {
		t.Error("an unknown group must be an error")
	}
}
