package digest

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/schema"
)

func fixture(t *testing.T) *schema.Node {
	t.Helper()
	f, err := os.Open("../../testdata/schema/schema-trimmed.xml")
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	root, err := schema.Parse(f)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return root
}

func encoded(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, &Digest{
		Platform: PlatformFirewall, Version: "11.2.0", Root: fixture(t),
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return buf.Bytes()
}

func TestRoundTripPreservesStructure(t *testing.T) {
	t.Parallel()
	root := fixture(t)
	var buf bytes.Buffer
	if err := Write(&buf, &Digest{
		Platform: PlatformFirewall, Version: "11.2.0", Root: root,
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Platform != PlatformFirewall || got.Version != "11.2.0" {
		t.Errorf("got %s/%s, want firewall/11.2.0", got.Platform, got.Version)
	}
	before := schema.EntryTypes(root)
	after := schema.EntryTypes(got.Root)
	if len(before) != len(after) {
		t.Fatalf("entry types: got %d, want %d", len(after), len(before))
	}
	for i := range before {
		if before[i].Path() != after[i].Path() {
			t.Errorf("path %d: got %q, want %q", i, after[i].Path(), before[i].Path())
		}
	}
}

// Parent pointers are not serialised. Read must rebuild them, or Path breaks.
func TestReadRebuildsParents(t *testing.T) {
	t.Parallel()
	got, err := Read(bytes.NewReader(encoded(t)))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	vsys := got.Root.Child("devices").EntrySequence().Child("vsys")
	if vsys == nil {
		t.Fatal("vsys not found after round trip")
	}
	want := "/config/devices/entry/vsys"
	if vsys.Path() != want {
		t.Errorf("got %q, want %q", vsys.Path(), want)
	}
	if !vsys.IsEntryList() {
		t.Error("vsys must survive the round trip as an entry list")
	}
}

func TestRoundTripPreservesAnnotations(t *testing.T) {
	t.Parallel()
	got, err := Read(bytes.NewReader(encoded(t)))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	rules := got.Root.Child("devices").EntrySequence().Child("vsys").EntrySequence().
		Child("rulebase").Child("security").Child("rules").EntrySequence()
	action := rules.Child("action")
	if action.Default != "allow" {
		t.Errorf("default: got %q, want allow", action.Default)
	}
	if len(action.EnumValues) != 6 {
		t.Errorf("enum values: got %v, want 6", action.EnumValues)
	}
	src := rules.Child("source").Child("member")
	if len(src.MemberOf) != 12 {
		t.Errorf("memberof: got %v, want 12", src.MemberOf)
	}
	addr := got.Root.Child("shared").Child("address").EntrySequence()
	if addr.Child("fqdn").MaxLen != 255 {
		t.Errorf("maxlen: got %d, want 255", addr.Child("fqdn").MaxLen)
	}
	if h := rules.Child("disabled").Help; h != "Disable the rule" {
		t.Errorf("help: got %q, want Disable the rule", h)
	}
	cert := got.Root.Child("shared").Child("certificate").EntrySequence()
	if !cert.Child("private-key").Encrypted || cert.Child("common-name").Encrypted {
		t.Error("encrypted: the mark must survive on private-key only")
	}
}

// A digest written before the encrypted mark existed is refused, not read as
// one without secrets.
func TestReadRefusesAnOlderFormat(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"format":1,"platform":"firewall","version":"11.2.0","root":{"k":0,"n":"config"}}`))
	_ = zw.Close()
	if _, err := Read(&buf); err == nil || !strings.Contains(err.Error(), "format version 1") {
		t.Errorf("want a format error, got %v", err)
	}
}

func TestWriteIsGzipped(t *testing.T) {
	t.Parallel()
	b := encoded(t)
	if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Error("digest must be gzipped; magic bytes missing")
	}
}

func TestFilename(t *testing.T) {
	t.Parallel()
	if got, want := Filename(PlatformFirewall, "11.2.0"), "panos-11.2.0-firewall.json.gz"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReadRejectsGarbage(t *testing.T) {
	t.Parallel()
	if _, err := Read(bytes.NewReader([]byte("not gzip"))); err == nil {
		t.Error("want an error for non-gzip input")
	}
}

func TestWriteRejectsAnUnknownPlatform(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := Write(&buf, &Digest{Platform: "router", Version: "11.2.0", Root: fixture(t)}); err == nil {
		t.Error("want an error for an unknown platform")
	}
}
