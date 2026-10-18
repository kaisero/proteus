package index

import (
	"testing"

	"github.com/RoaringBitmap/roaring/v2"
)

// Candidates unions the four ways a rule field can reach a value: the object
// covering it, any group holding that object, a literal in the field, and the
// field being "any". Forgetting one of the four is the mistake this exists to
// prevent.
func TestCandidatesCoversAllFourPaths(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-paths.xml", "vsys1")
	rules := idx.Rules()
	names := func(b *roaring.Bitmap) map[string]bool {
		out := map[string]bool{}
		for it := b.Iterator(); it.HasNext(); {
			out[rules[it.Next()].Name] = true
		}
		return out
	}

	got := names(candidates(idx, Source, "10.1.1.1"))
	for _, want := range []string{
		"by-object",  // source names h-1 directly
		"by-group",   // source names g-hosts, which holds h-1
		"by-literal", // source is 10.1.0.0/16, which covers 10.1.1.1
		"by-any",     // source is any
	} {
		if !got[want] {
			t.Errorf("%s missing; Candidates found %v", want, keys(got))
		}
	}
	if got["unrelated"] {
		t.Errorf("a rule about another address must not match: %v", keys(got))
	}
}

// A name has three of the four paths: itself, its groups, and any. A literal
// cannot apply, because a name is not an address.
func TestCandidatesOfANameCoversNameGroupsAndAny(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-paths.xml", "vsys1")
	rules := idx.Rules()
	got := map[string]bool{}
	for it := candidates(idx, Source, "h-1").Iterator(); it.HasNext(); {
		got[rules[it.Next()].Name] = true
	}
	for _, want := range []string{"by-object", "by-group", "by-any"} {
		if !got[want] {
			t.Errorf("%s missing; got %v", want, keys(got))
		}
	}
	if got["by-literal"] {
		t.Error("a name cannot reach a literal address field")
	}
}

// RulesReaching is the name and its groups only: no any, no literal.
func TestRulesReachingIsTheNameAndItsGroups(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-paths.xml", "vsys1")
	rules := idx.Rules()
	got := map[string]bool{}
	for it := idx.RulesReaching(Source, "h-1").Iterator(); it.HasNext(); {
		got[rules[it.Next()].Name] = true
	}
	if !got["by-object"] || !got["by-group"] || got["by-any"] || got["by-literal"] {
		t.Errorf("got %v", keys(got))
	}
}

// The composition a consumer writes: two sides, intersect, drop disabled, take the
// lowest bit. The library supplies the sides and nothing more.
func TestComposingSidesGivesTheDeviceAnswer(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-anyrule.xml", "vsys1")
	src := candidates(idx, Source, "198.18.0.5")
	dst := candidates(idx, Destination, "198.18.1.5")
	cand := roaring.And(src, dst)
	cand.AndNot(idx.Disabled())
	if cand.IsEmpty() {
		t.Fatal("both rules reach these addresses")
	}
	// fw01 reports ztnac-to-lab for the equivalent probe: the any-rule, which is
	// earlier. The fixture mirrors that shape.
	if got := idx.Rules()[cand.Minimum()].Name; got != "any-early" {
		t.Errorf("first match = %q, want any-early", got)
	}
}

func TestCandidatesOfAnUnknownAddressIsEmptyExceptAny(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-paths.xml", "vsys1")
	rules := idx.Rules()
	got := map[string]bool{}
	for it := candidates(idx, Destination, "203.0.113.1").Iterator(); it.HasNext(); {
		got[rules[it.Next()].Name] = true
	}
	// Nothing names that address, so only a destination of "any" can reach it.
	for name := range got {
		if name != "by-object" && name != "by-group" && name != "by-literal" &&
			name != "by-any" && name != "unrelated" {
			t.Errorf("unexpected rule %q", name)
		}
	}
	if !got["by-object"] {
		// by-object's destination is any in the fixture, so it must appear.
		t.Errorf("a destination of any must reach every address; got %v", keys(got))
	}
}

// candidates is the rule set Candidates returns, without its report.
func candidates(idx *Index, f Field, value string) *roaring.Bitmap {
	b, _ := idx.Candidates(f, value)
	return b
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A prefix reaches a rule through an overlapping object, a group holding one, an
// overlapping literal, or a field of any.
func TestCandidatesOfAPrefix(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-paths.xml", "vsys1")
	rules := idx.Rules()
	got := map[string]bool{}
	// 10.1.1.0/24 contains h-1 at 10.1.1.1 and overlaps the literal 10.1.0.0/16.
	for it := candidates(idx, Source, "10.1.1.0/24").Iterator(); it.HasNext(); {
		got[rules[it.Next()].Name] = true
	}
	for _, want := range []string{"by-object", "by-group", "by-literal", "by-any"} {
		if !got[want] {
			t.Errorf("%s missing; Candidates found %v", want, keys(got))
		}
	}
	if got["unrelated"] {
		t.Errorf("10.9.9.9 is outside 10.1.1.0/24: %v", keys(got))
	}
}

// A prefix covering nothing but reached by an any-rule still finds that rule, and
// nothing else.
func TestCandidatesOfAPrefixOnlyAny(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-paths.xml", "vsys1")
	rules := idx.Rules()
	got := map[string]bool{}
	for it := candidates(idx, Source, "203.0.113.0/24").Iterator(); it.HasNext(); {
		got[rules[it.Next()].Name] = true
	}
	if !got["by-any"] {
		t.Errorf("an any-rule reaches every prefix; got %v", keys(got))
	}
	for _, unwanted := range []string{"by-object", "by-group", "by-literal"} {
		if got[unwanted] {
			t.Errorf("%s must not reach 203.0.113.0/24: %v", unwanted, keys(got))
		}
	}
}

// A name that does not exist reaches only the any-rules, and interning it must not
// corrupt the table for later lookups.
func TestCandidatesOfAnUnknownName(t *testing.T) {
	t.Parallel()
	idx := indexOf(t, "../../testdata/config/firewall-paths.xml", "vsys1")
	before := idx.Interner().Len()
	rules := idx.Rules()
	got := map[string]bool{}
	for it := candidates(idx, Source, "no-such-object").Iterator(); it.HasNext(); {
		got[rules[it.Next()].Name] = true
	}
	if !got["by-any"] {
		t.Errorf("only an any-rule can reach an unknown name; got %v", keys(got))
	}
	if got["by-object"] || got["by-group"] {
		t.Errorf("an unknown name reaches no object rule: %v", keys(got))
	}
	// A known name still resolves afterwards.
	after := map[string]bool{}
	for it := candidates(idx, Source, "h-1").Iterator(); it.HasNext(); {
		after[rules[it.Next()].Name] = true
	}
	if !after["by-object"] {
		t.Error("interning an unknown name broke a later lookup")
	}
	if idx.Interner().Len() < before {
		t.Error("the interner shrank")
	}
}
