package schema

import "testing"

func TestInlineSequencesFound(t *testing.T) {
	root := load(t)
	got := InlineSequences(root)
	if len(got) == 0 {
		t.Fatal("no inline sequences found")
	}
	paths := map[string]bool{}
	for _, n := range got {
		paths[n.Path()] = true
	}
	// address-group/entry/dynamic is a named sequence that is not an entry.
	if !paths["/config/shared/address-group/entry/dynamic"] {
		t.Error("address-group/entry/dynamic must be an inline sequence")
	}
	// An entry sequence is not inline.
	if paths["/config/shared/address/entry"] {
		t.Error("an entry sequence must not be reported as inline")
	}
	// The root is not inline either.
	if paths["/config"] {
		t.Error("the root must not be reported as inline")
	}
}

func TestInlineSequencesDeduplicate(t *testing.T) {
	root := load(t)
	inline := InlineSequences(root)
	shapes := map[string]int{}
	for _, n := range inline {
		shapes[Fingerprint(n)]++
	}
	// The fixture has two security rulebases under shared and two under a device
	// group, so the security and rulebase wrappers repeat.
	if len(shapes) >= len(inline) {
		t.Fatalf("%d shapes from %d inline sequences; some must be shared",
			len(shapes), len(inline))
	}
}
