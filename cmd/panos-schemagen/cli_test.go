package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seedSchema copies the trimmed fixture in as cms-schema.xml.
func seedSchema(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("../../testdata/schema/cms-schema-trimmed.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cms-schema.xml"), src, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDigestThenGenerate(t *testing.T) {
	tmp := t.TempDir()
	schemaDir := filepath.Join(tmp, "schemas")
	digestDir := filepath.Join(tmp, "digest")
	outDir := filepath.Join(tmp, "model")
	seedSchema(t, schemaDir)

	if err := runDigest(schemaDir, digestDir, "11.2.0"); err != nil {
		t.Fatalf("runDigest: %v", err)
	}
	if _, err := os.Stat(filepath.Join(digestDir, "panos-11.2.0-panorama.json.gz")); err != nil {
		t.Fatalf("digest not written: %v", err)
	}

	if err := runGenerate(digestDir, outDir); err != nil {
		t.Fatalf("runGenerate: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "v11_2", "panorama", "model.go"))
	if err != nil {
		t.Fatalf("model not written: %v", err)
	}
	if !strings.Contains(string(got), "type AddressEntry struct") {
		t.Error("generated model has no AddressEntry")
	}
	if !strings.Contains(string(got), "package model") {
		t.Error("generated model has no package clause")
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	tmp := t.TempDir()
	schemaDir := filepath.Join(tmp, "schemas")
	digestDir := filepath.Join(tmp, "digest")
	seedSchema(t, schemaDir)
	if err := runDigest(schemaDir, digestDir, "11.2.0"); err != nil {
		t.Fatal(err)
	}

	first, second := filepath.Join(tmp, "a"), filepath.Join(tmp, "b")
	if err := runGenerate(digestDir, first); err != nil {
		t.Fatal(err)
	}
	if err := runGenerate(digestDir, second); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(filepath.Join(first, "v11_2", "panorama", "model.go"))
	b, _ := os.ReadFile(filepath.Join(second, "v11_2", "panorama", "model.go"))
	if string(a) != string(b) {
		t.Error("two runs produced different output; the drift gate needs determinism")
	}
}

func TestVersionPackageName(t *testing.T) {
	for in, want := range map[string]string{
		"11.2.0": "v11_2", "11.1.0": "v11_1", "10.2.0": "v10_2",
	} {
		if got := versionPackage(in); got != want {
			t.Errorf("versionPackage(%q) = %q, want %q", in, got, want)
		}
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

func TestGenerateRejectsAnEmptyDigestDirectory(t *testing.T) {
	err := runGenerate(t.TempDir(), t.TempDir())
	if err == nil {
		t.Fatal("want an error when no digest is present")
	}
	if !strings.Contains(err.Error(), "schema-digest") {
		t.Errorf("the error should say how to fix it, got: %v", err)
	}
}
