package config

import (
	"strings"
	"testing"
)

func TestLoadBareConfig(t *testing.T) {
	cfg, rep, err := Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version() != "11.2.0" {
		t.Errorf("version = %q, want 11.2.0", cfg.Version())
	}
	if cfg.DetailVersion() != "11.2.7" {
		t.Errorf("detail version = %q, want 11.2.7", cfg.DetailVersion())
	}
	if cfg.Platform() != Panorama {
		t.Errorf("platform = %v, want Panorama", cfg.Platform())
	}
	t.Logf("untyped elements: %d", len(rep.Untyped))
}

// The same configuration arrives wrapped when it comes from the XML API.
func TestLoadWrappedConfig(t *testing.T) {
	cfg, _, err := Load("../testdata/config/panorama-lab-wrapped.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version() != "11.2.0" || cfg.Platform() != Panorama {
		t.Errorf("wrapped load gave %q/%v, want 11.2.0/Panorama", cfg.Version(), cfg.Platform())
	}
}

func TestLoadDetectsFirewall(t *testing.T) {
	cfg, _, err := Load("../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Platform() != Firewall {
		t.Errorf("platform = %v, want Firewall", cfg.Platform())
	}
	if cfg.DetailVersion() != "11.2.5" {
		t.Errorf("detail version = %q, want 11.2.5", cfg.DetailVersion())
	}
}

func TestLoadRejectsAnUnsupportedVersion(t *testing.T) {
	_, _, err := Load("../testdata/config/unsupported-version.xml")
	if err == nil {
		t.Fatal("want an error for an unsupported version")
	}
	if !strings.Contains(err.Error(), "11.2") {
		t.Errorf("the error should name the nearest supported version, got: %v", err)
	}
	if !strings.Contains(err.Error(), "9.1.0") {
		t.Errorf("the error should name the version it was given, got: %v", err)
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, _, err := Load("../testdata/config/does-not-exist.xml"); err == nil {
		t.Fatal("want an error for a missing file")
	}
}

func TestLoadRejectsAFileWithNoConfigElement(t *testing.T) {
	if _, _, err := Load("../testdata/schema/cms-schema-trimmed.xml"); err == nil {
		t.Fatal("want an error for a file with no <config> element")
	}
}

func TestConfigAccessors(t *testing.T) {
	cfg, _, err := Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Path() != "../testdata/config/panorama-lab.xml" {
		t.Errorf("Path = %q", cfg.Path())
	}
	if cfg.Digest() == nil {
		t.Error("Digest must return the schema root")
	}
	root := cfg.Root()
	if root == nil || root.Name != "config" {
		t.Fatalf("Root = %v, want the config element", root)
	}
	if root.Child("devices") == nil {
		t.Error("the root must carry the parsed tree")
	}
}

// The schema is decoded once per process and shared, so two loads of the same
// version get the same schema.
func TestSchemaIsSharedBetweenLoads(t *testing.T) {
	a, _, err := Load("../testdata/config/panorama-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Load("../testdata/config/panorama-lab-wrapped.xml")
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Error("two configurations of the same version must share one decoded schema")
	}
	if a.Root() == b.Root() {
		t.Error("but each keeps its own parsed tree")
	}
}
