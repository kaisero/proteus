package schema

import (
	"os"
	"testing"
)

func load(t *testing.T) *Node {
	t.Helper()
	f, err := os.Open("../../testdata/schema/cms-schema-trimmed.xml")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	root, err := Parse(f)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return root
}

func TestParseRoot(t *testing.T) {
	root := load(t)
	if root.Kind != KindSequence || root.Name != "config" {
		t.Fatalf("got kind=%v name=%q, want sequence/config", root.Kind, root.Name)
	}
}

func TestParseLeafAttributes(t *testing.T) {
	root := load(t)
	addr := root.Child("shared").Child("address").EntrySequence()
	fqdn := addr.Child("fqdn")
	if fqdn == nil {
		t.Fatal("fqdn not found; choice children must be flattened into the entry sequence")
	}
	if fqdn.Type != "string" || fqdn.MaxLen != 255 {
		t.Errorf("got type=%q maxlen=%d, want string/255", fqdn.Type, fqdn.MaxLen)
	}
	desc := addr.Child("description")
	if desc.Help != "Description" {
		t.Errorf("got help=%q, want Description", desc.Help)
	}
}

func TestParseEnumValues(t *testing.T) {
	root := load(t)
	rules := root.Child("shared").Child("pre-rulebase").Child("security").
		Child("rules").EntrySequence()
	action := rules.Child("action")
	if action.Default != "allow" {
		t.Errorf("got default=%q, want allow", action.Default)
	}
	want := []string{"allow", "deny", "drop"}
	if len(action.EnumValues) != len(want) {
		t.Fatalf("got %v, want %v", action.EnumValues, want)
	}
	for i, v := range want {
		if action.EnumValues[i] != v {
			t.Errorf("enum[%d] = %q, want %q", i, action.EnumValues[i], v)
		}
	}
}

// The distinction pango gets wrong. See AGENTS.md R4.
func TestParseListShape(t *testing.T) {
	root := load(t)
	dg := root.Child("devices").Child("entry").Child("device-group").EntrySequence()

	refTpl := dg.Child("reference-templates")
	if !refTpl.IsMemberList() || refTpl.IsEntryList() {
		t.Error("reference-templates must be a member list")
	}

	devices := dg.Child("devices")
	if !devices.IsEntryList() || devices.IsMemberList() {
		t.Error("devices must be an entry list")
	}

	vsys := devices.EntrySequence().Child("vsys")
	if !vsys.IsEntryList() {
		t.Error("devices/entry/vsys must be an entry list, not a member list")
	}
}

func TestParsePath(t *testing.T) {
	root := load(t)
	vsys := root.Child("devices").Child("entry").Child("device-group").
		EntrySequence().Child("devices").EntrySequence().Child("vsys")
	want := "/config/devices/entry/device-group/entry/devices/entry/vsys"
	if got := vsys.Path(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseMemberOf(t *testing.T) {
	root := load(t)
	src := root.Child("shared").Child("pre-rulebase").Child("security").
		Child("rules").EntrySequence().Child("source")
	member := src.Child("member")
	want := []string{
		"#config/shared/address/entry/@name",
		"#config/shared/address-group/entry/@name",
	}
	if len(member.MemberOf) != len(want) {
		t.Fatalf("got %v, want %v", member.MemberOf, want)
	}
	for i, w := range want {
		if member.MemberOf[i] != w {
			t.Errorf("memberof[%d] = %q, want %q", i, member.MemberOf[i], w)
		}
	}
}

func TestReadonlyIsEmpty(t *testing.T) {
	// The schema declares readonly but describes nothing inside it. parent-dg
	// lives there, so it must be hand-modelled. See AGENTS.md R8.
	root := load(t)
	ro := root.Child("readonly")
	if ro == nil {
		t.Fatal("readonly node missing")
	}
	if len(ro.Children) != 0 {
		t.Errorf("readonly has %d children; the schema describes none", len(ro.Children))
	}
}
