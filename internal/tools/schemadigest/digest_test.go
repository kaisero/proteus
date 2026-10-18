package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/digest"
)

// seedSchema copies the trimmed fixture in as schema.xml.
func seedSchema(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("../../../testdata/schema/schema-trimmed.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "schema.xml"), src, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDigestWritesAReadableDigest(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	schemaDir := filepath.Join(tmp, "schemas")
	digestDir := filepath.Join(tmp, "digest")
	seedSchema(t, schemaDir)

	if err := runDigest(schemaDir, digestDir, "11.2.0"); err != nil {
		t.Fatalf("runDigest: %v", err)
	}
	f, err := os.Open(filepath.Join(digestDir, digest.Filename))
	if err != nil {
		t.Fatalf("digest not written: %v", err)
	}
	defer f.Close()
	d, err := digest.Read(f)
	if err != nil {
		t.Fatalf("the written digest does not read back: %v", err)
	}
	if d.Version != "11.2.0" || d.Platform != digest.PlatformFirewall {
		t.Errorf("digest says %s %s, want 11.2.0 %s", d.Platform, d.Version, digest.PlatformFirewall)
	}
}

func TestDigestRejectsAnEmptyDirectory(t *testing.T) {
	t.Parallel()
	err := runDigest(t.TempDir(), t.TempDir(), "11.2.0")
	if err == nil {
		t.Fatal("want an error when no schema file is present")
	}
	if !strings.Contains(err.Error(), "schema-pull") {
		t.Errorf("the error should say how to fix it, got: %v", err)
	}
}

// A schema whose parse finds no memberof target means the parser is dropping
// <validate>. The tool must refuse to write that digest.
func TestDigestRefusesASchemaWithNoReferences(t *testing.T) {
	t.Parallel()
	dir, out := t.TempDir(), t.TempDir()
	doc := `<sequence name="config"><array name="thing"><sequence name="entry">` +
		`<attr-req name="name" type="string"/></sequence></array></sequence>`
	if err := os.WriteFile(filepath.Join(dir, "schema.xml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runDigest(dir, out, "11.2.0")
	if err == nil || !strings.Contains(err.Error(), "no references") {
		t.Fatalf("want a no-references error, got %v", err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("a refused digest must not be written, found %d files", len(entries))
	}
}

// A schema with references but no encrypted element means the parser is
// dropping encrypt="yes". The tool must refuse to write that digest.
func TestDigestRefusesASchemaWithNoSecrets(t *testing.T) {
	t.Parallel()
	dir, out := t.TempDir(), t.TempDir()
	doc := `<sequence name="config"><array name="thing"><sequence name="entry">` +
		`<attr-req name="name" type="string"/><array name="tag"><element name="member" type="string">` +
		`<validate><memberof type="tag" memberof="#config/shared/tag/entry/@name"/></validate>` +
		`</element></array></sequence></array></sequence>`
	if err := os.WriteFile(filepath.Join(dir, "schema.xml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runDigest(dir, out, "11.2.0")
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("want a no-secrets error, got %v", err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("a refused digest must not be written, found %d files", len(entries))
	}
}

// A schema with references and secrets but no tlo="yes" element means the
// parser is dropping the template-object mark, and the merge of a pushed
// template would take each template object by its children (spec 2026-10-17
// C11). The tool must refuse to write that digest.
func TestAssertTemplateObjectsFound(t *testing.T) {
	t.Parallel()
	dir, out := t.TempDir(), t.TempDir()
	doc := `<sequence name="config"><array name="thing"><sequence name="entry">` +
		`<attr-req name="name" type="string"/><element name="key" type="string" encrypt="yes"/>` +
		`<array name="tag"><element name="member" type="string">` +
		`<validate><memberof type="tag" memberof="#config/shared/tag/entry/@name"/></validate>` +
		`</element></array></sequence></array></sequence>`
	if err := os.WriteFile(filepath.Join(dir, "schema.xml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	err := runDigest(dir, out, "11.2.0")
	if err == nil || !strings.Contains(err.Error(), `tlo="yes"`) {
		t.Fatalf("want a no-template-objects error, got %v", err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 0 {
		t.Errorf("a refused digest must not be written, found %d files", len(entries))
	}
}

func TestDigestReportsAParseError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "schema.xml"), []byte("<sequence"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := runDigest(dir, t.TempDir(), "11.2.0"); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("want a parse error, got %v", err)
	}
}
