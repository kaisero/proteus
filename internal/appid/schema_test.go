package appid_test

import (
	"slices"
	"testing"

	"github.com/okaiser/proteus/internal/appid"
	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/schema"
)

// filterPath is the hand-modelled node of the S10 map (AGENTS.md R8).
const filterPath = "/config/devices/entry/vsys/entry/application-filter/entry"

// Spec 2026-10-16 §3.2: every field of an application filter selects on a kept
// field of the content file. A new filter field in a new schema fails here
// until FilterField maps it and the trim keeps its application field.
func TestEveryFilterFieldHasAKeptField(t *testing.T) {
	t.Parallel()
	cfg, _, err := config.Load("../../testdata/config/firewall-apps.xml")
	if err != nil {
		t.Fatal(err)
	}
	for _, segs := range [][]string{
		{"devices", "entry", "vsys", "entry", "application-filter", "entry"},
		{"shared", "application-filter", "entry"},
	} {
		n := cfg.Digest()
		for _, s := range segs {
			n = n.Step(s)
		}
		if n == nil {
			t.Fatalf("the digest has no %v", segs)
		}
		fields := 0
		for _, f := range n.Fields() {
			if f.Kind == schema.KindAttrReq || f.Name == "exclude" {
				continue
			}
			fields++
			app, ok := appid.FilterField(f.Name)
			if !ok {
				t.Errorf("%s/%s maps to no application field", n.Path(), f.Name)
				continue
			}
			if !appid.Kept(app) {
				t.Errorf("%s/%s maps to %s, which the trim drops", n.Path(), f.Name, app)
			}
		}
		if fields == 0 {
			t.Fatalf("%s has no field, so the check would pass vacuously", n.Path())
		}
	}
	// S10 names the tag field tagging.
	if app, ok := appid.FilterField("tagging"); !ok || app != "tag" {
		t.Errorf("FilterField(tagging) = %q, %v", app, ok)
	}
	for _, f := range []string{"name", "exclude", "no-such-field"} {
		if _, ok := appid.FilterField(f); ok {
			t.Errorf("FilterField(%s) maps a field that selects nothing", f)
		}
	}
	// Spec 2026-10-16 §5.1: Via lists the fields in schema field order.
	for _, segs := range [][]string{
		{"devices", "entry", "vsys", "entry", "application-filter", "entry"},
		{"shared", "application-filter", "entry"},
	} {
		n := cfg.Digest()
		for _, s := range segs {
			n = n.Step(s)
		}
		var order []string
		for _, f := range n.Fields() {
			if f.Kind != schema.KindAttrReq && f.Name != "exclude" {
				order = append(order, f.Name)
			}
		}
		got := slices.DeleteFunc(appid.FilterOrder(), func(f string) bool { return !slices.Contains(order, f) })
		if !slices.Equal(got, order) {
			t.Errorf("%s: the filter order is %v, the schema order %v", n.Path(), got, order)
		}
	}
	declared := false
	for _, h := range schema.HandModelled() {
		declared = declared || h.Path == filterPath && h.Owner == "internal/appid"
	}
	if !declared {
		t.Error("the filter-field map is not registered in schema.HandModelled")
	}
}
