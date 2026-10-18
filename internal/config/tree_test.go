package config

import (
	"strings"
	"testing"
)

const treeDoc = `<response><result>
<config version="11.2.0" detail-version="11.2.7">
  <shared>
    <address>
      <entry name="a"><ip-netmask>10.0.0.1</ip-netmask><tag><member>t1</member></tag></entry>
      <entry name="b"><fqdn>x.example</fqdn></entry>
    </address>
  </shared>
  <devices>
    <entry name="localhost.localdomain">
      <device-group>
        <entry name="dg1"><description>first</description></entry>
      </device-group>
    </entry>
  </devices>
</config>
</result></response>`

func tree(t *testing.T) *Element {
	t.Helper()
	root, err := parseTree(strings.NewReader(treeDoc))
	if err != nil {
		t.Fatalf("parseTree: %v", err)
	}
	return root
}

// The root is the config element, whether or not the file wraps it.
func TestParseTreeAnchorsAtConfig(t *testing.T) {
	t.Parallel()
	root := tree(t)
	if root.Name != "config" {
		t.Fatalf("root = %q, want config", root.Name)
	}
	if got := root.Attr("version"); got != "11.2.0" {
		t.Errorf("version = %q, want 11.2.0", got)
	}
}

func TestElementChildAndChildren(t *testing.T) {
	t.Parallel()
	root := tree(t)
	addr := root.Child("shared").Child("address")
	if addr == nil {
		t.Fatal("shared/address not found")
	}
	entries := addr.ChildrenNamed("entry")
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Attr("name") != "a" {
		t.Errorf("first entry = %q, want a", entries[0].Attr("name"))
	}
	if root.Child("nope") != nil {
		t.Error("an absent child must be nil")
	}
	if root.Child("nope").Child("deeper") != nil {
		t.Error("chaining off a nil element must stay nil")
	}
}

func TestElementText(t *testing.T) {
	t.Parallel()
	root := tree(t)
	e := root.Child("shared").Child("address").ChildrenNamed("entry")[0]
	if got := e.Child("ip-netmask").Text; got != "10.0.0.1" {
		t.Errorf("text = %q, want 10.0.0.1", got)
	}
	if got := e.Child("tag").Child("member").Text; got != "t1" {
		t.Errorf("member = %q, want t1", got)
	}
}

func TestElementMembers(t *testing.T) {
	t.Parallel()
	root := tree(t)
	e := root.Child("shared").Child("address").ChildrenNamed("entry")[0]
	got := e.Child("tag").Members()
	if len(got) != 1 || got[0] != "t1" {
		t.Errorf("members = %v, want [t1]", got)
	}
	if e.Child("nope").Members() != nil {
		t.Error("members of a nil element must be nil")
	}
}

// A schema path names arrays and sequences, not instances, so entry stays entry.
func TestElementSchemaPath(t *testing.T) {
	t.Parallel()
	root := tree(t)
	e := root.Child("devices").Child("entry").Child("device-group").ChildrenNamed("entry")[0]
	if got, want := e.SchemaPath(), "/config/devices/entry/device-group/entry"; got != want {
		t.Errorf("schema path = %q, want %q", got, want)
	}
}

// An instance path names the entries, so two device groups are distinguishable.
func TestElementInstancePath(t *testing.T) {
	t.Parallel()
	root := tree(t)
	e := root.Child("devices").Child("entry").Child("device-group").ChildrenNamed("entry")[0]
	want := "/config/devices/localhost.localdomain/device-group/dg1"
	if got := e.InstancePath(); got != want {
		t.Errorf("instance path = %q, want %q", got, want)
	}
}

// Find follows a fixed element-name path, which is how the readers match exactly.
func TestElementFind(t *testing.T) {
	t.Parallel()
	root := tree(t)
	got := root.Find("devices", "entry", "device-group", "entry")
	if len(got) != 1 || got[0].Attr("name") != "dg1" {
		t.Errorf("Find returned %d elements, want the one device group", len(got))
	}
	if len(root.Find("shared", "nope")) != 0 {
		t.Error("an unmatched path must return nothing")
	}
}

func TestParseTreeRejectsAFileWithNoConfig(t *testing.T) {
	t.Parallel()
	if _, err := parseTree(strings.NewReader("<response><result/></response>")); err == nil {
		t.Error("want an error when there is no config element")
	}
}

func TestTextOr(t *testing.T) {
	t.Parallel()
	root := tree(t)
	e := root.Child("devices").Child("entry").Child("device-group").ChildrenNamed("entry")[0]
	if got := e.Child("description").TextOr("fallback"); got != "first" {
		t.Errorf("TextOr = %q, want first", got)
	}
	if got := e.Child("absent").TextOr("fallback"); got != "fallback" {
		t.Errorf("TextOr on a nil element = %q, want fallback", got)
	}
}

// Every accessor tolerates a nil receiver, so a lookup chain needs no checks.
func TestNilElementAccessors(t *testing.T) {
	t.Parallel()
	var e *Element
	if e.Attr("x") != "" {
		t.Error("Attr on nil must be empty")
	}
	if e.Child("x") != nil {
		t.Error("Child on nil must be nil")
	}
	if e.ChildrenNamed("x") != nil {
		t.Error("ChildrenNamed on nil must be nil")
	}
	if e.Members() != nil {
		t.Error("Members on nil must be nil")
	}
	if e.Find("x") != nil {
		t.Error("Find on nil must be nil")
	}
	if e.TextOr("f") != "f" {
		t.Error("TextOr on nil must return the fallback")
	}
	if got := e.SchemaPath(); got != "/" {
		t.Errorf("SchemaPath on nil = %q, want /", got)
	}
}

func TestAttrAbsent(t *testing.T) {
	t.Parallel()
	root := tree(t)
	if got := root.Attr("no-such-attr"); got != "" {
		t.Errorf("absent attribute = %q, want empty", got)
	}
}

func TestParseTreeRejectsMalformedXML(t *testing.T) {
	t.Parallel()
	if _, err := parseTree(strings.NewReader("<config><unclosed>")); err == nil {
		t.Error("want an error for malformed XML")
	}
}
