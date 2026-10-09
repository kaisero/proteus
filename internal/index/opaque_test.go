package index

import (
	"maps"
	"strings"
	"testing"
)

// A rule naming an external list, a region or a dynamic group, directly or
// through a static group, is recorded per field with a reason; a cycle of static
// groups ends the walk.
func TestOpaque(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-opaque.xml", "vsys1")
	rules := idx.Rules()
	v := idx.With(Providers{})
	// Each rule's reasons as "code: text", joined.
	named := func(f Field) map[string]string {
		b, why := v.Opaque(f)
		out := map[string]string{}
		for it := b.Iterator(); it.HasNext(); {
			bit := it.Next()
			var parts []string
			for _, r := range why[bit] {
				parts = append(parts, string(r.Code)+": "+r.Text)
			}
			out[rules[bit].Name] = strings.Join(parts, "; ")
		}
		return out
	}
	want := map[string]string{
		"from-edl":     "doubt.edl: external list (edl-bad)",
		"from-country": "doubt.region: region (AT)",
		"from-dag":     "doubt.dynamic-group: members registered at runtime are not known (dag-web)",
		"from-group":   "doubt.edl: external list (edl-bad, in group g-mixed)",
		"not-from-edl": "doubt.edl: external list (edl-bad)",
		"from-region":  "doubt.region: region (my-region)",
	}
	if got := named(Source); !maps.Equal(got, want) {
		t.Errorf("source: got %v, want %v", got, want)
	}
	if got := named(Destination); !maps.Equal(got, map[string]string{"to-builtin": "doubt.edl: external list (panw-highrisk-ip-list)"}) {
		t.Errorf("destination: got %v", got)
	}
	if b, why := v.Opaque(Service); !b.IsEmpty() || why != nil {
		t.Errorf("service has no opaque rules: %v %v", b, why)
	}
	// The caller's copy is its own.
	b, why := v.Opaque(Source)
	b.Clear()
	clear(why)
	if again, _ := v.Opaque(Source); again.GetCardinality() != uint64(len(want)) {
		t.Error("Opaque returned the index's own bitmap")
	}
}
