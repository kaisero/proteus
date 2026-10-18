package schema

import (
	"os"
	"testing"
)

func load(t *testing.T) *Node {
	t.Helper()
	f, err := os.Open("../../testdata/schema/schema-trimmed.xml")
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

// securityRule is the entry sequence of a vsys security rule.
func securityRule(root *Node) *Node {
	return root.Child("devices").EntrySequence().Child("vsys").EntrySequence().
		Child("rulebase").Child("security").Child("rules").EntrySequence()
}

func TestParseRoot(t *testing.T) {
	t.Parallel()
	root := load(t)
	if root.Kind != KindSequence || root.Name != "config" {
		t.Fatalf("got kind=%v name=%q, want sequence/config", root.Kind, root.Name)
	}
}

func TestParseLeafAttributes(t *testing.T) {
	t.Parallel()
	root := load(t)
	addr := root.Child("shared").Child("address").EntrySequence()
	fqdn := addr.Child("fqdn")
	if fqdn == nil {
		t.Fatal("fqdn not found; choice children must be flattened into the entry sequence")
	}
	if fqdn.Type != "string" || fqdn.MaxLen != 255 {
		t.Errorf("got type=%q maxlen=%d, want string/255", fqdn.Type, fqdn.MaxLen)
	}
	disabled := securityRule(root).Child("disabled")
	if disabled.Help != "Disable the rule" {
		t.Errorf("got help=%q, want Disable the rule", disabled.Help)
	}
}

// The schema marks a secret encrypt="yes"; phash it does not, and it is a
// hand-modelled secret (AGENTS.md R8).
func TestParseEncrypted(t *testing.T) {
	t.Parallel()
	root := load(t)
	cert := root.Child("shared").Child("certificate").EntrySequence()
	if !cert.Child("private-key").Encrypted || !IsSecret(cert.Child("private-key")) {
		t.Error("private-key must be encrypted and secret")
	}
	if cert.Child("common-name").Encrypted || IsSecret(cert.Child("common-name")) {
		t.Error("common-name is not a secret")
	}
	user := root.Child("shared").Child("local-user-database").Child("user").EntrySequence()
	if phash := user.Child("phash"); phash.Encrypted || !IsSecret(phash) {
		t.Errorf("phash: encrypted %v, secret %v; want false, true", phash.Encrypted, IsSecret(phash))
	}
	if IsSecret(nil) {
		t.Error("nil is not a secret")
	}
}

func TestParseEnumValues(t *testing.T) {
	t.Parallel()
	root := load(t)
	rules := securityRule(root)
	action := rules.Child("action")
	if action.Default != "allow" {
		t.Errorf("got default=%q, want allow", action.Default)
	}
	want := []string{"deny", "allow", "drop", "reset-client", "reset-server", "reset-both"}
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
	t.Parallel()
	root := load(t)
	source := securityRule(root).Child("source")
	if !source.IsMemberList() || source.IsEntryList() {
		t.Error("a security rule's source must be a member list")
	}

	devices := root.Child("devices")
	if !devices.IsEntryList() || devices.IsMemberList() {
		t.Error("devices must be an entry list")
	}

	vsys := devices.EntrySequence().Child("vsys")
	if !vsys.IsEntryList() {
		t.Error("devices/entry/vsys must be an entry list, not a member list")
	}
}

func TestParsePath(t *testing.T) {
	t.Parallel()
	root := load(t)
	vsys := root.Child("devices").EntrySequence().Child("vsys")
	want := "/config/devices/entry/vsys"
	if got := vsys.Path(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseMemberOf(t *testing.T) {
	t.Parallel()
	root := load(t)
	member := securityRule(root).Child("source").Child("member")
	got := map[string]bool{}
	for _, m := range member.MemberOf {
		got[m] = true
	}
	for _, w := range []string{
		"#config/shared/address/entry/@name",
		"#config/shared/address-group/entry/@name",
	} {
		if !got[w] {
			t.Errorf("memberof misses %q; got %v", w, member.MemberOf)
		}
	}
}

func TestReadonlyIsEmpty(t *testing.T) {
	t.Parallel()
	// The schema declares readonly but describes nothing inside it, so a node
	// that lives there must be hand-modelled. See AGENTS.md R8.
	root := load(t)
	ro := root.Child("readonly")
	if ro == nil {
		t.Fatal("readonly node missing")
	}
	if len(ro.Children) != 0 {
		t.Errorf("readonly has %d children; the schema describes none", len(ro.Children))
	}
}
