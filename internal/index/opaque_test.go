package index

import (
	"maps"
	"net/netip"
	"strings"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"
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

// A dynamic group whose filter starts with a parenthesis is a dynamic group like
// any other (L1): its tagged addresses reach its rule, and the rule carries the
// dynamic-group doubt. Read as a static group, it reached no address.
func TestDynamicGroupWithAParenthesisedFilter(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-dynamic-filter.xml", "vsys1")
	rules := idx.Rules()
	names := func(b *roaring.Bitmap) map[string]bool {
		out := map[string]bool{}
		for it := b.Iterator(); it.HasNext(); {
			out[rules[it.Next()].Name] = true
		}
		return out
	}
	// As observed on fw02, PAN-OS 12.2.3 (L1): 10.88.1.1 and 10.88.1.2 hit the
	// rule, 10.88.1.3 does not.
	for _, tc := range []struct {
		addr string
		hit  bool
	}{{"10.88.1.1", true}, {"10.88.1.2", true}, {"10.88.1.3", false}} {
		if got := names(idx.CandidatesFor(Source, netip.MustParseAddr(tc.addr))); got["from-dag"] != tc.hit {
			t.Errorf("%s: from-dag in %v, want %v", tc.addr, keys(got), tc.hit)
		}
	}
	v := idx.With(Providers{})
	for _, member := range []string{"h-a", "h-b"} {
		b, _ := v.Candidates(Source, member)
		if !names(b)["from-dag"] {
			t.Errorf("Candidates(Source, %s) = %v, want from-dag", member, keys(names(b)))
		}
	}
	b, why := v.Opaque(Source)
	got := names(b)
	if len(got) != 1 || !got["from-dag"] {
		t.Fatalf("opaque rules = %v, want [from-dag]", keys(got))
	}
	for _, rs := range why {
		if len(rs) != 1 || rs[0].Code != "doubt.dynamic-group" || !strings.Contains(rs[0].Text, "(dag-paren)") {
			t.Errorf("reasons = %v", rs)
		}
	}
	if len(idx.UnparsedFilters()) != 0 {
		t.Errorf("unparsed filters: %v", idx.UnparsedFilters())
	}
}
