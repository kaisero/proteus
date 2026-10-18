package identity_test

import (
	"bytes"
	"compress/gzip"
	"encoding"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/testconfig"
)

const fixtures = "../../testdata/identity/"

// fixtureFile reads testdata/identity/identity.json, the file of format 1 as
// plain JSON (spec 2026-10-17 §4.1, §7).
func fixtureFile(t *testing.T) identity.File {
	t.Helper()
	raw, err := os.ReadFile(fixtures + "identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var f identity.File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// loadFixture gzips identity.json, as a snapshot holds it, and loads it.
func loadFixture(t *testing.T) *identity.Data {
	t.Helper()
	path := filepath.Join(t.TempDir(), identity.FileName)
	testconfig.Identity(t, path)
	d, err := identity.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// equalFiles compares two files field by field, so a failure names the field.
func equalFiles(t *testing.T, got, want identity.File) {
	t.Helper()
	if got.Format != want.Format {
		t.Errorf("format %d, want %d", got.Format, want.Format)
	}
	if !got.TakenAt.Equal(want.TakenAt) {
		t.Errorf("taken_at %v, want %v", got.TakenAt, want.TakenAt)
	}
	if got.MappingsPartial != want.MappingsPartial {
		t.Errorf("mappings_partial %v, want %v", got.MappingsPartial, want.MappingsPartial)
	}
	for _, field := range []struct {
		name      string
		got, want any
	}{
		{"sources.ldap", got.Sources.LDAP, want.Sources.LDAP},
		{"sources.cie", got.Sources.CIE, want.Sources.CIE},
		{"users", got.Users, want.Users},
		{"groups", got.Groups, want.Groups},
		{"dugs", got.DUGs, want.DUGs},
		{"tags", got.Tags, want.Tags},
		{"mappings", got.Mappings, want.Mappings},
		{"parts_missing", got.PartsMissing, want.PartsMissing},
	} {
		if !reflect.DeepEqual(field.got, field.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", field.name, field.got, field.want)
		}
	}
}

// gz gzips a document.
func gz(t *testing.T, doc string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write([]byte(doc)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// gunzip unzips a document.
func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// §4.1: Read reads what Encode writes, field by field. The fixture misses no
// part and leaves mappings_partial out.
func TestEncodeReadRoundTrip(t *testing.T) {
	t.Parallel()
	want := fixtureFile(t)
	if len(want.PartsMissing) != 0 || want.MappingsPartial {
		t.Fatalf("the fixture misses %v, partial %v; want a whole file", want.PartsMissing, want.MappingsPartial)
	}
	var b bytes.Buffer
	if err := identity.Encode(&b, want); err != nil {
		t.Fatal(err)
	}
	if doc := gunzip(t, b.Bytes()); strings.Contains(doc, "mappings_partial") {
		t.Errorf("a whole table writes mappings_partial: %s", doc)
	}
	d, err := identity.Read(&b)
	if err != nil {
		t.Fatal(err)
	}
	equalFiles(t, d.File(), want)
	if !d.TakenAt().Equal(time.Date(2026, 10, 17, 20, 0, 0, 0, time.UTC)) {
		t.Errorf("TakenAt %v", d.TakenAt())
	}
}

// pinnedKeys holds the JSON keys of each format (spec 2026-10-17 §4.1). The
// format changes when a key changes its meaning or goes: Format then rises,
// and the keys of the new format are pinned here. An added key keeps the
// format and needs only an entry in its list (ruling T4).
var pinnedKeys = map[int][]string{
	1: {
		"format", "taken_at",
		"sources", "sources.ldap", "sources.ldap.name", "sources.ldap.domain", "sources.ldap.base", "sources.ldap.groups",
		"sources.cie", "sources.cie.name", "sources.cie.domain", "sources.cie.groups", "sources.cie.last",
		"users", "users.name", "users.alt", "users.email", "users.groups",
		"groups", "groups.name", "groups.source", "groups.members",
		"dugs",
		"tags", "tags.user", "tags.tags",
		"mappings", "mappings.ip", "mappings.user", "mappings.type", "mappings.timeout",
		"mappings_partial", // SG13
		"parts_missing",
	},
}

var (
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
)

// jsonKeys lists the JSON keys of a struct type and of the structs below it,
// as encoding/json names them. A type that marshals itself, such as time.Time
// or netip.Addr, is one value.
func jsonKeys(t reflect.Type, prefix string) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = f.Name
		}
		key := prefix + name
		out = append(out, key)
		ft := f.Type
		for ft.Kind() == reflect.Slice || ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && !ft.Implements(textMarshaler) && !ft.Implements(jsonMarshaler) {
			out = append(out, jsonKeys(ft, key+".")...)
		}
	}
	return out
}

// §4.1, SG13: the keys of File and its parts equal the pinned keys of Format.
// A removed or renamed key fails until Format rises and the new keys are
// pinned; an added key fails until it joins the pinned list.
func TestFormatGuardsTheFields(t *testing.T) {
	t.Parallel()
	pinned, ok := pinnedKeys[identity.Format]
	if !ok {
		t.Fatalf("Format %d: pin the keys of the new format here", identity.Format)
	}
	got := jsonKeys(reflect.TypeFor[identity.File](), "")
	for _, k := range pinned {
		if !slices.Contains(got, k) {
			t.Errorf("the key %s of format %d is gone or renamed: raise Format and pin the keys of the new format", k, identity.Format)
		}
	}
	for _, k := range got {
		if !slices.Contains(pinned, k) {
			t.Errorf("the key %s is new: add it to the pinned keys of format %d", k, identity.Format)
		}
	}
	if identity.FileName != "identity.json.gz" {
		t.Errorf("FileName %q", identity.FileName)
	}
}

// The checker of the pinned keys must be able to fail: it names a new key and
// a key that goes.
func TestJSONKeysSeeEveryField(t *testing.T) {
	t.Parallel()
	type inner struct {
		Kept string `json:"kept"`
	}
	type file struct {
		Name    string      `json:"name"`
		Untyped int         // encoding/json names it Untyped
		Skipped bool        `json:"-"`
		When    time.Time   `json:"when"`
		Addr    netip.Addr  `json:"addr"`
		List    []inner     `json:"list,omitempty"`
		Ptr     *inner      `json:"ptr"`
		Addrs   []*struct{} `json:"addrs"`
	}
	got := jsonKeys(reflect.TypeFor[file](), "")
	want := []string{"name", "Untyped", "when", "addr", "list", "list.kept", "ptr", "ptr.kept", "addrs"}
	if !slices.Equal(got, want) {
		t.Errorf("keys %v\nwant %v", got, want)
	}
}

// §8: the fixture holds 4 users, 8 groups, 8 user-group pairs (DUGs among
// them, D13), 6 mappings and 2 tag entries.
func TestCountsHoldTheMemberships(t *testing.T) {
	t.Parallel()
	got := loadFixture(t).Counts()
	want := identity.Counts{Users: 4, Groups: 8, Memberships: 8, Mappings: 6, Tags: 2}
	if got != want {
		t.Errorf("counts %+v, want %+v", got, want)
	}
}

// §4.1: a file of another format is refused, and the error names its format.
func TestReadRefusesAnotherFormat(t *testing.T) {
	t.Parallel()
	for doc, format := range map[string]string{
		`{"format": 2, "users": []}`: "format 2",
		`{"users": []}`:              "format 0",
	} {
		_, err := identity.Read(bytes.NewReader(gz(t, doc)))
		if err == nil || !strings.Contains(err.Error(), format) {
			t.Errorf("%s: err %v, want one that names %s", doc, err, format)
		}
	}
}

// Review focus 1: a damaged file is an error, never a partial answer. The
// error quotes no value of the file (§3.5).
func TestReadRefusesADamagedFile(t *testing.T) {
	t.Parallel()
	var whole bytes.Buffer
	if err := identity.Encode(&whole, fixtureFile(t)); err != nil {
		t.Fatal(err)
	}
	b := whole.Bytes()
	for name, in := range map[string][]byte{
		"no gzip":         []byte("not gzip"),
		"cut trailer":     b[:len(b)-4],
		"cut in the data": b[:len(b)/2],
		"bad json":        gz(t, `{"format": 1, "users": [`),
		"no json":         gz(t, `example.com\alice`),
		"wrong type":      gz(t, `{"format": 1, "users": 3}`),
		"two values":      gz(t, `{"format": 1} {"format": 1}`),
		"bad address":     gz(t, `{"format": 1, "mappings": [{"ip": "x-198.51.100.10", "user": "example.com\\alice"}]}`),
		"no address":      gz(t, `{"format": 1, "mappings": [{"ip": "", "user": "example.com\\alice"}]}`),
	} {
		_, err := identity.Read(bytes.NewReader(in))
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		for _, v := range []string{"198.51.100", "alice", "example"} {
			if strings.Contains(err.Error(), v) {
				t.Errorf("%s: the error %q quotes a value of the file", name, err)
			}
		}
	}
	if _, err := identity.Load(filepath.Join(t.TempDir(), "missing.json.gz")); err == nil {
		t.Error("a missing file: no error")
	}
	damaged := filepath.Join(t.TempDir(), identity.FileName)
	if err := os.WriteFile(damaged, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Load(damaged); err == nil || !strings.Contains(err.Error(), damaged) {
		t.Errorf("a damaged file: %v, want an error that names it", err)
	}
}

// Encode writes only a file that Read reads: the format of this build, and a
// valid address in each mapping. A write error reaches the caller.
func TestEncodeRefusesAFileReadCannotRead(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	if err := identity.Encode(&b, identity.File{Format: 2}); err == nil || b.Len() != 0 {
		t.Errorf("format 2: err %v, wrote %d bytes", err, b.Len())
	}
	noAddr := identity.File{Format: identity.Format, Mappings: []identity.Mapping{{User: `example.com\alice`}}}
	if err := identity.Encode(&b, noAddr); err == nil || b.Len() != 0 || strings.Contains(err.Error(), "alice") {
		t.Errorf("a mapping without an address: err %v, wrote %d bytes", err, b.Len())
	}
	if err := identity.Encode(failWriter{}, fixtureFile(t)); !errors.Is(err, errWrite) {
		t.Errorf("err %v, want the write error", err)
	}
	// gzip writes its header first and the data at Close.
	if err := identity.Encode(&failLater{}, fixtureFile(t)); !errors.Is(err, errWrite) {
		t.Errorf("err %v, want the write error of Close", err)
	}
}

var errWrite = errors.New("dummy write error")

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errWrite }

// failLater takes the first write and fails each later one.
type failLater struct{ writes int }

func (f *failLater) Write(p []byte) (int, error) {
	if f.writes++; f.writes > 1 {
		return 0, errWrite
	}
	return len(p), nil
}

// §4.1: every list key is present, as [] when empty; mappings_partial is left
// out when false. A file with null lists reads as empty lists.
func TestEncodeWritesEmptyLists(t *testing.T) {
	t.Parallel()
	var b bytes.Buffer
	if err := identity.Encode(&b, identity.File{Format: identity.Format}); err != nil {
		t.Fatal(err)
	}
	doc := gunzip(t, b.Bytes())
	for _, key := range []string{`"ldap":[]`, `"cie":[]`, `"users":[]`, `"groups":[]`, `"dugs":[]`, `"tags":[]`, `"mappings":[]`, `"parts_missing":[]`} {
		if !strings.Contains(doc, key) {
			t.Errorf("the empty file lacks %s: %s", key, doc)
		}
	}
	if strings.Contains(doc, "null") || strings.Contains(doc, "mappings_partial") {
		t.Errorf("the empty file: %s", doc)
	}
	d, err := identity.Read(bytes.NewReader(gz(t, `{"format": 1, "users": null, "parts_missing": null}`)))
	if err != nil {
		t.Fatal(err)
	}
	if f := d.File(); f.Users == nil || f.PartsMissing == nil || f.Sources.LDAP == nil {
		t.Errorf("null lists read as %+v", f)
	}
}

// §8: New stores each group name once, so a membership holds no copy of it;
// tag names too. The data holds its own copy of the caller's file.
func TestNewInternsTheGroupNames(t *testing.T) {
	t.Parallel()
	f := unshared(fixtureFile(t))
	if unsafe.StringData(f.Users[0].Groups[0]) == unsafe.StringData(f.Groups[0].Name) {
		t.Fatal("the input shares a name, so the test proves nothing")
	}
	f.PartsMissing = []string{identity.PartTags}
	d := identity.New(f)
	got := d.File()
	domainUsers := got.Groups[0].Name
	for _, u := range got.Users {
		if len(u.Groups) == 0 {
			continue // dave is in no group (D13)
		}
		if u.Groups[0] != domainUsers || unsafe.StringData(u.Groups[0]) != unsafe.StringData(domainUsers) {
			t.Errorf("%s holds a copy of %s", u.Name, domainUsers)
		}
	}
	if unsafe.StringData(got.Tags[0].Tags[0]) != unsafe.StringData(got.Tags[1].Tags[0]) {
		t.Error("the tag tag-a is held twice")
	}
	if got.DUGs[0] != got.Groups[3].Name || unsafe.StringData(got.DUGs[0]) != unsafe.StringData(got.Groups[3].Name) {
		t.Error("the DUG dug-a is held twice")
	}
	f.Users[0].Groups[0] = "changed"
	f.Users[0].Alt[0] = "changed"
	f.Groups[0].Name = "changed"
	f.Tags[0].Tags[0] = "changed"
	f.Mappings[0].User = "changed"
	f.PartsMissing[0] = "changed"
	again := d.File()
	if again.Users[0].Groups[0] != domainUsers || again.Users[0].Alt[0] != "alice@example.com" ||
		again.Groups[0].Name != domainUsers || again.Tags[0].Tags[0] != "tag-a" ||
		again.Mappings[0].User != `example\alice` || again.PartsMissing[0] != identity.PartTags {
		t.Errorf("a change of the caller's file reached the data: %+v", again)
	}
}

// unshared gives each group, DUG and tag name of f a copy of its own. A JSON
// decoder can share equal strings, and then a test of New sees no difference.
func unshared(f identity.File) identity.File {
	for i := range f.Groups {
		f.Groups[i].Name = strings.Clone(f.Groups[i].Name)
	}
	for i := range f.DUGs {
		f.DUGs[i] = strings.Clone(f.DUGs[i])
	}
	for _, u := range f.Users {
		for j := range u.Groups {
			u.Groups[j] = strings.Clone(u.Groups[j])
		}
	}
	for _, tg := range f.Tags {
		for j := range tg.Tags {
			tg.Tags[j] = strings.Clone(tg.Tags[j])
		}
	}
	return f
}

// §3.4: PartsMissing is sorted, and the caller gets a copy.
func TestPartsMissingIsACopy(t *testing.T) {
	t.Parallel()
	f := fixtureFile(t)
	f.PartsMissing = []string{identity.PartMappings, identity.PartTags}
	d := identity.New(f)
	got := d.PartsMissing()
	if !slices.Equal(got, []string{"mappings", "tags"}) {
		t.Fatalf("PartsMissing %v", got)
	}
	got[0] = "changed"
	if d.PartsMissing()[0] != "mappings" {
		t.Error("a change of the answer reached the data")
	}
	if loadFixture(t).PartsMissing() == nil {
		t.Error("a whole file gives nil, want an empty list")
	}
}
