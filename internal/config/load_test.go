package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/okaiser/proteus/internal/digest"
)

func TestLoadBareConfig(t *testing.T) {
	t.Parallel()
	cfg, rep, err := Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version() != "11.2.0" {
		t.Errorf("version = %q, want 11.2.0", cfg.Version())
	}
	if cfg.DetailVersion() != "11.2.5" {
		t.Errorf("detail version = %q, want 11.2.5", cfg.DetailVersion())
	}
	t.Logf("untyped elements: %d", len(rep.Untyped))
}

// The same configuration arrives wrapped when it comes from the XML API.
func TestLoadWrappedConfig(t *testing.T) {
	t.Parallel()
	cfg, _, err := Load("../../testdata/config/firewall-multivsys-wrapped.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version() != "11.2.0" {
		t.Errorf("wrapped load gave version %q, want 11.2.0", cfg.Version())
	}
	if cfg.Root().Child("devices") == nil {
		t.Error("the wrapped load must reach the config element's children")
	}
}

// A Panorama configuration is refused by name, not loaded against the wrong
// schema. proteus reads each firewall's own configuration.
func TestLoadRejectsPanorama(t *testing.T) {
	t.Parallel()
	_, _, err := Load("../../testdata/config/panorama-rejected.xml")
	if err == nil {
		t.Fatal("a Panorama configuration must be an error")
	}
	if !strings.Contains(err.Error(), "Panorama") {
		t.Errorf("the error must say it is a Panorama configuration, got: %v", err)
	}
}

func TestLoadReadsAFirewall(t *testing.T) {
	t.Parallel()
	cfg, _, err := Load("../../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DetailVersion() != "11.2.5" {
		t.Errorf("detail version = %q, want 11.2.5", cfg.DetailVersion())
	}
}

// One schema reads every PAN-OS version: older, newer, malformed or none. No
// version is checked, and the report says nothing about a version.
func TestLoadReadsAnyVersionWithTheOneSchema(t *testing.T) {
	t.Parallel()
	lab, _, err := Load("../../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name, doc string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for path, version := range map[string]string{
		"../../testdata/config/firewall-version-12.2.xml":                   "12.2.0",
		"../../testdata/config/unsupported-version.xml":                     "9.1.0",
		write("eleven.xml", `<config version="eleven"><devices/></config>`): "eleven",
		write("none.xml", `<config><devices/></config>`):                    "",
	} {
		cfg, rep, err := Load(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if cfg.Version() != version || cfg.Digest() != lab.Digest() {
			t.Errorf("%s: version %q, shared schema %v", path, cfg.Version(), cfg.Digest() == lab.Digest())
		}
		if rep.String() != "no untyped elements" {
			t.Errorf("%s: report %q", path, rep.String())
		}
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	t.Parallel()
	if _, _, err := Load("../../testdata/config/does-not-exist.xml"); err == nil {
		t.Fatal("want an error for a missing file")
	}
}

func TestLoadRejectsAFileWithNoConfigElement(t *testing.T) {
	t.Parallel()
	if _, _, err := Load("../../testdata/schema/schema-trimmed.xml"); err == nil {
		t.Fatal("want an error for a file with no <config> element")
	}
}

func TestConfigAccessors(t *testing.T) {
	t.Parallel()
	const path = "../../testdata/config/firewall-multivsys.xml"
	cfg, _, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Path() != path {
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

// The schema is decoded once per process and shared, so two loads get the same
// schema.
func TestSchemaIsSharedBetweenLoads(t *testing.T) {
	t.Parallel()
	a, _, err := Load("../../testdata/config/firewall-multivsys.xml")
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Load("../../testdata/config/firewall-multivsys-wrapped.xml")
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Error("two configurations must share one decoded schema")
	}
	if a.Root() == b.Root() {
		t.Error("but each keeps its own parsed tree")
	}
}

// predefinedDir writes a configuration with a predefined.xml next to it and
// returns the configuration's path.
func predefinedDir(t *testing.T, predefined string) string {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile("../../testdata/predefined/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.xml"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PredefinedFile), []byte(predefined), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "config.xml")
}

// The device's predefined services load from the file next to the configuration,
// as the device answers them (L4), wrapped or bare. Without the file the
// configuration loads as before.
func TestLoadReadsThePredefinedServices(t *testing.T) {
	t.Parallel()
	entries := func(cfg *Config) string {
		var out []string
		for _, e := range cfg.Predefined().Find("service", "entry") {
			out = append(out, e.Attr("name")+" "+e.Child("protocol").Child("tcp").Child("port").Text+" "+e.SchemaPath())
		}
		return strings.Join(out, "; ")
	}
	const want = "service-http 80,8080 /predefined/service/entry; service-https 443 /predefined/service/entry"
	wrapped, _, err := Load("../../testdata/predefined/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	if got := entries(wrapped); got != want {
		t.Errorf("wrapped: %s", got)
	}
	bare, _, err := Load(predefinedDir(t, `<service><entry name="service-http"><protocol><tcp><port>80,8080</port></tcp></protocol></entry>`+
		`<entry name="service-https"><protocol><tcp><port>443</port></tcp></protocol></entry></service>`))
	if err != nil {
		t.Fatal(err)
	}
	if got := entries(bare); got != want {
		t.Errorf("bare: %s", got)
	}
	// The predefined services are not part of the configuration's own tree.
	if wrapped.Root().Child("predefined") != nil || wrapped.Root().Find("service", "entry") != nil {
		t.Error("the predefined services reached the configuration tree")
	}
	without, _, err := Load("../../testdata/config/firewall-nat-cases.xml")
	if err != nil {
		t.Fatal(err)
	}
	if without.Predefined() != nil {
		t.Error("a configuration without predefined.xml has no predefined services")
	}
}

// A well-formed predefined.xml without a <service> element holds no predefined
// services: the configuration loads, and rules that name them stay in doubt.
func TestLoadReadsAPredefinedFileWithoutServicesAsNone(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"empty result": `<response status="success"><result/></response>`,
		"html page":    `<html><body><p>Sign in first</p></body></html>`,
	} {
		cfg, _, err := Load(predefinedDir(t, body))
		if err != nil || cfg.Predefined() != nil {
			t.Errorf("%s: want no predefined services and no error, got %v", name, err)
		}
	}
}

// A predefined.xml that cannot be read or parsed fails the load and names the
// file: skipping it would hide data.
func TestLoadRejectsABadPredefinedFile(t *testing.T) {
	t.Parallel()
	for name, body := range map[string]string{
		"malformed":      `<response status="success"><result><service><entry name="service-http">`,
		"malformed html": `<html><body><p>Sign in<br></body></html>`,
	} {
		_, _, err := Load(predefinedDir(t, body))
		if err == nil || !strings.Contains(err.Error(), PredefinedFile) {
			t.Errorf("%s: want an error naming %s, got %v", name, PredefinedFile, err)
		}
	}
	path := predefinedDir(t, "")
	if err := os.Chmod(filepath.Join(filepath.Dir(path), PredefinedFile), 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil || !strings.Contains(err.Error(), "open") || !strings.Contains(err.Error(), PredefinedFile) {
		t.Errorf("unreadable: want an open error naming the file, got %v", err)
	}
}

// A build without its digest, or with a damaged one, says which.
func TestReadDigestReportsAMissingOrBadFile(t *testing.T) {
	t.Parallel()
	if _, err := readDigest(fstest.MapFS{}); err == nil || !strings.Contains(err.Error(), "no schema digest") {
		t.Errorf("missing: %v", err)
	}
	bad := fstest.MapFS{"schemadigest/" + digest.Filename: {Data: []byte("not gzip")}}
	if _, err := readDigest(bad); err == nil || !strings.Contains(err.Error(), digest.Filename) {
		t.Errorf("damaged: %v", err)
	}
}
