package index

import (
	"net/netip"
	"testing"

	"github.com/RoaringBitmap/roaring/v2"

	"github.com/okaiser/go-panos-schema/config"
)

func liveLikeIndex(t *testing.T, dg string) *Index {
	t.Helper()
	return indexOf(t, "../testdata/config/panorama-literals.xml", dg)
}

// A rule can name an address directly instead of naming an object. An address
// lookup has to reach those rules too, or a configuration written that way looks
// empty.
func TestRulesWithAddrFindsALiteralField(t *testing.T) {
	idx := liveLikeIndex(t, "dg1")

	// The rule's source is exactly this address.
	exact := idx.RulesWithAddr(Source, netip.MustParseAddr("198.18.1.1"))
	if exact.IsEmpty() {
		t.Fatal("no rule found for the exact literal 198.18.1.1/32")
	}
	if got := idx.Rules()[exact.Minimum()].Name; got != "literal-host" {
		t.Errorf("first match = %q, want literal-host", got)
	}
}

// The point of a trie: an address inside a literal prefix matches it.
func TestRulesWithAddrMatchesInsideAPrefix(t *testing.T) {
	idx := liveLikeIndex(t, "dg1")
	b := idx.RulesWithAddr(Source, netip.MustParseAddr("198.18.9.42"))
	if b.IsEmpty() {
		t.Fatal("198.18.9.42 is inside the rule's 198.18.0.0/16 source")
	}
	names := map[string]bool{}
	for it := b.Iterator(); it.HasNext(); {
		names[idx.Rules()[it.Next()].Name] = true
	}
	if !names["literal-net"] {
		t.Errorf("got %v, want literal-net", names)
	}
	if names["literal-host"] {
		t.Error("198.18.9.42 is not inside 198.18.1.1/32")
	}
}

// A literal on the destination side is indexed separately from the source side.
//
// 198.18.2.1 is not a useful probe for that: it is the destination of one rule but
// also sits inside another rule's 198.18.0.0/16 source. 203.0.113.9 is the
// destination of exactly one rule and a source of none.
func TestRulesWithAddrIsPerField(t *testing.T) {
	idx := liveLikeIndex(t, "dg1")
	dst := idx.RulesWithAddr(Destination, netip.MustParseAddr("203.0.113.9"))
	if dst.IsEmpty() {
		t.Fatal("203.0.113.9 is the destination of the out-of-range rule")
	}
	if got := idx.Rules()[dst.Minimum()].Name; got != "literal-far-dest" {
		t.Errorf("first match = %q, want literal-far-dest", got)
	}
	if src := idx.RulesWithAddr(Source, netip.MustParseAddr("203.0.113.9")); !src.IsEmpty() {
		t.Error("203.0.113.9 is not a source in this fixture")
	}
}

// A named object and a literal both reach the rule, and the two paths combine.
func TestLiteralAndNamedCombine(t *testing.T) {
	idx := liveLikeIndex(t, "dg1")
	in := idx.Interner()

	src := idx.RulesWith(Source, in.ID("named-host"))
	src.Or(idx.RulesWithAddr(Source, netip.MustParseAddr("198.18.1.1")))
	dst := idx.RulesWith(Destination, in.ID("named-dest"))
	dst.Or(idx.RulesWithAddr(Destination, netip.MustParseAddr("198.18.2.1")))

	cand := roaring.And(src, dst)
	if cand.IsEmpty() {
		t.Fatal("the literal rule and the named rule both exist, so something must match")
	}
	found := map[string]bool{}
	for it := cand.Iterator(); it.HasNext(); {
		found[idx.Rules()[it.Next()].Name] = true
	}
	if !found["literal-host"] || !found["named-rule"] {
		t.Errorf("got %v, want both literal-host and named-rule", found)
	}
}

// A keyword such as any is not an address and must not enter the trie. If it did,
// every address would match every rule.
//
// 192.0.2.7 is outside every literal in the fixture, so the only way it could match
// is through a keyword having been indexed as a prefix.
func TestKeywordsAreNotLiterals(t *testing.T) {
	idx := liveLikeIndex(t, "dg1")
	for _, f := range []Field{Source, Destination, Application, Service} {
		if b := idx.RulesWithAddr(f, netip.MustParseAddr("192.0.2.7")); !b.IsEmpty() {
			t.Errorf("%s matched an address outside every literal, so a keyword was indexed", f)
		}
	}
}

func TestRulesWithPrefixOverlaps(t *testing.T) {
	idx := liveLikeIndex(t, "dg1")
	b := idx.RulesWithPrefix(Source, netip.MustParsePrefix("198.18.0.0/8"))
	if b.GetCardinality() < 2 {
		t.Errorf("a /8 overlaps both the /32 and the /16 source, got %d rules",
			b.GetCardinality())
	}
}

var _ = config.ScopeShared
