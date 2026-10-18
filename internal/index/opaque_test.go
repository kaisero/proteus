package index

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/kaisero/proteus/internal/resolve"
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
		if got := names(candidates(idx, Source, tc.addr)); got["from-dag"] != tc.hit {
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

// classifierOf builds a classifier over static groups written as name -> members,
// the address h and the dynamic group dag.
func classifierOf(groups map[string]string) *classifier {
	objs := opaqueObjects{
		addrs:  []resolve.Object{{Name: "h", Kind: "address", Value: "10.88.0.1"}},
		groups: []resolve.Object{{Name: "dag", Kind: "address-group", Value: "'t'", Dynamic: true}},
	}
	for name, members := range groups {
		objs.groups = append(objs.groups, resolve.Object{Name: name, Kind: "address-group", Value: members})
	}
	return newClassifier(objs)
}

// Every group gets one answer, whatever group a rule names first: a cycle of
// static groups that holds a dynamic group is opaque in every group of it, and a
// cycle that holds none is opaque in none.
func TestClassifyAnswersEachGroupOnce(t *testing.T) {
	t.Parallel()
	groups := map[string]string{
		"a": "b", "b": "c, h", "c": "a, dag", // a cycle reaching dag
		"x": "y, h", "y": "z", "z": "x, h", // a cycle reaching nothing opaque
		"top": "x, a",
		"s":   "s, h", // a group holding itself
	}
	want := map[string]string{
		"a":   "dag, in group c, in group b, in group a",
		"b":   "dag, in group c, in group b",
		"c":   "dag, in group c",
		"top": "dag, in group c, in group b, in group a, in group top",
		"x":   "", "y": "", "z": "", "s": "", "h": "",
		"dag": "dag",
	}
	for _, order := range [][]string{
		{"a", "b", "c", "x", "y", "z", "top", "s", "h", "dag"},
		{"top", "c", "b", "a", "z", "y", "x", "s", "dag", "h"},
		{"y", "b", "x", "s", "top", "z", "a", "h", "c", "dag"},
	} {
		c := classifierOf(groups)
		for _, v := range order {
			got := c.classify(v)
			text := strings.TrimSuffix(strings.TrimPrefix(got.Text, opaqueRuntime+" ("), ")")
			if text != want[v] {
				t.Errorf("order %v: classify(%s) = %q, want %q", order, v, got.Text, want[v])
			}
		}
		for _, g := range []string{"a", "b", "c", "x", "y", "z", "top", "s"} {
			if _, done := c.via[g]; !done {
				t.Errorf("order %v: %s has no stored answer", order, g)
			}
		}
	}
}

// denseGroups is n static groups d-0 … that each hold three others of them and
// the address h, the shape of BenchmarkIndexBuildDenseGroups. With dag set, d-0
// also holds the dynamic group dag.
func denseGroups(n int, dag bool) map[string]string {
	out := map[string]string{}
	for i := range n {
		out[fmt.Sprintf("d-%d", i)] = fmt.Sprintf("d-%d, d-%d, d-%d, h", (i+1)%n, (i*7+3)%n, (i*11+5)%n)
	}
	if dag {
		out["d-0"] += ", dag"
	}
	return out
}

// Groups that hold each other densely are decided in work linear in their
// members, not by walking every way through them: 40 such groups took more
// than ten minutes to index before. The answers follow reachability, and the
// reason text is the same on every build.
func TestClassifyDecidesADenseCycleOnce(t *testing.T) {
	t.Parallel()
	const n = 400
	for _, dag := range []bool{false, true} {
		groups := denseGroups(n, dag)
		c := classifierOf(groups)
		members := 0
		for _, v := range groups {
			members += len(strings.Split(v, ", "))
		}
		if c.reads > 3*members {
			t.Errorf("dag %v: %d member reads for %d members, want at most three each", dag, c.reads, members)
		}
		texts := map[string]string{}
		for g := range groups {
			r := c.classify(g)
			if (r.Text != "") != dag {
				t.Errorf("dag %v: classify(%s) = %q", dag, g, r.Text)
			}
			texts[g] = r.Text
		}
		if !dag {
			continue
		}
		if got := c.classify("d-0").Text; got != opaqueRuntime+" (dag, in group d-0)" {
			t.Errorf("classify(d-0) = %q", got)
		}
		for range 3 {
			again := classifierOf(groups)
			for g, want := range texts {
				if got := again.classify(g).Text; got != want {
					t.Fatalf("classify(%s) = %q on one build and %q on another", g, want, got)
				}
			}
		}
	}
}

// On random graphs of static groups, a group is opaque exactly when it reaches
// dag, and every via is a member of its group.
func TestClassifyFollowsReachability(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // a fixed test graph, not a secret
	for range 500 {
		n := 1 + rng.IntN(12)
		groups := map[string][]string{}
		for i := range n {
			g := fmt.Sprintf("g-%d", i)
			for range rng.IntN(4) {
				groups[g] = append(groups[g], fmt.Sprintf("g-%d", rng.IntN(n)))
			}
			if rng.IntN(6) == 0 {
				groups[g] = append(groups[g], "dag")
			}
			groups[g] = append(groups[g], "h")
		}
		written := map[string]string{}
		for g, ms := range groups {
			written[g] = strings.Join(ms, ", ")
		}
		c := classifierOf(written)
		for g := range groups {
			seen := map[string]bool{}
			var reaches func(v string) bool
			reaches = func(v string) bool {
				if v == "dag" {
					return true
				}
				if seen[v] {
					return false
				}
				seen[v] = true
				return slices.ContainsFunc(groups[v], reaches)
			}
			if got := c.classify(g).Text != ""; got != reaches(g) {
				t.Fatalf("%v: classify(%s) opaque %v, want %v", written, g, got, !got)
			}
			if v := c.via[g]; v != "" && !slices.Contains(groups[g], v) {
				t.Fatalf("%v: via[%s] = %s, not a member", written, g, v)
			}
		}
	}
}
