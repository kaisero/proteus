package resolve

import (
	"testing"

	"github.com/okaiser/go-panos-schema/config"
)

func shadowLab(t *testing.T) *config.Config {
	t.Helper()
	cfg, _, err := config.Load("../testdata/config/panorama-shadow.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func TestScopedObjectsExcludeSiblings(t *testing.T) {
	tg, err := TargetFor(lab(t), "007900000000003", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	objs, err := tg.Objects("address")
	if err != nil {
		t.Fatalf("Objects: %v", err)
	}
	names := map[string]bool{}
	for _, o := range objs {
		names[o.Name] = true
	}
	if !names["corp-dc-vienna"] || !names["corp-location-vienna"] {
		t.Errorf("the target's own objects are missing: %v", names)
	}
	// corp-graz is a sibling device group, so its objects are invisible here.
	if names["corp-dc-graz"] || names["corp-location-graz"] {
		t.Errorf("sibling device-group objects leaked in: %v", names)
	}
}

func TestScopedObjectsCarryValueAndTags(t *testing.T) {
	tg, _ := TargetFor(lab(t), "007900000000003", "vsys1")
	objs, _ := tg.Objects("address")
	for _, o := range objs {
		if o.Name != "corp-location-vienna" {
			continue
		}
		if o.Value != "10.124.0.0/16" {
			t.Errorf("value = %q, want 10.124.0.0/16", o.Value)
		}
		if len(o.Tags) != 1 || o.Tags[0] != "corp-location" {
			t.Errorf("tags = %v, want [corp-location]", o.Tags)
		}
		if o.Scope.String() != "dg:host_1_directory" {
			t.Errorf("scope = %q, want dg:host_1_directory", o.Scope.String())
		}
		return
	}
	t.Error("corp-location-vienna not found")
}

func TestShadowingIsReported(t *testing.T) {
	tg, err := TargetFor(shadowLab(t), "001122334455", "vsys1")
	if err != nil {
		t.Fatalf("TargetFor: %v", err)
	}
	objs, err := tg.Objects("address")
	if err != nil {
		t.Fatalf("Objects: %v", err)
	}
	var shadowed *Object
	for i := range objs {
		if objs[i].Name == "web-server" {
			shadowed = &objs[i]
		}
	}
	if shadowed == nil {
		t.Fatal("web-server not found")
	}
	if shadowed.Scope.String() != "dg:leaf" {
		t.Errorf("the descendant definition must win, got scope %q", shadowed.Scope.String())
	}
	if shadowed.Value != "10.9.9.1" {
		t.Errorf("value = %q, want the leaf's 10.9.9.1", shadowed.Value)
	}
	if shadowed.ShadowedFrom == nil || shadowed.ShadowedFrom.String() != "dg:top" {
		t.Errorf("shadowing must name what it replaced, got %v", shadowed.ShadowedFrom)
	}
	// An ancestor-only object is still visible.
	var found bool
	for _, o := range objs {
		if o.Name == "only-in-top" {
			found = true
			if o.ShadowedFrom != nil {
				t.Error("only-in-top shadows nothing")
			}
		}
	}
	if !found {
		t.Error("only-in-top must be inherited from the ancestor")
	}
}
