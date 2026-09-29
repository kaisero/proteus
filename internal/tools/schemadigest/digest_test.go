package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/digest"
)

// seedSchema copies the trimmed fixture in as cms-schema.xml.
func seedSchema(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("../../../testdata/schema/cms-schema-trimmed.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cms-schema.xml"), src, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDigestWritesAReadableDigest(t *testing.T) {
	tmp := t.TempDir()
	schemaDir := filepath.Join(tmp, "schemas")
	digestDir := filepath.Join(tmp, "digest")
	seedSchema(t, schemaDir)

	if err := runDigest(schemaDir, digestDir, "11.2.0"); err != nil {
		t.Fatalf("runDigest: %v", err)
	}
	f, err := os.Open(filepath.Join(digestDir, "panos-11.2.0-panorama.json.gz"))
	if err != nil {
		t.Fatalf("digest not written: %v", err)
	}
	defer f.Close()
	d, err := digest.Read(f)
	if err != nil {
		t.Fatalf("the written digest does not read back: %v", err)
	}
	if d.Version != "11.2.0" || d.Platform != digest.PlatformPanorama {
		t.Errorf("digest says %s %s, want 11.2.0 %s", d.Platform, d.Version, digest.PlatformPanorama)
	}
}

func TestDigestRejectsAnEmptyDirectory(t *testing.T) {
	err := runDigest(t.TempDir(), t.TempDir(), "11.2.0")
	if err == nil {
		t.Fatal("want an error when no schema file is present")
	}
	if !strings.Contains(err.Error(), "schema-pull") {
		t.Errorf("the error should say how to fix it, got: %v", err)
	}
}
