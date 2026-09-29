package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
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

// A configuration newer than every digest is read with the highest one below it,
// and the load says so. Spec §9: refusing blocks an estate on one upgrade.
func TestLoadUsesTheNearestLowerDigest(t *testing.T) {
	t.Parallel()
	cfg, rep, err := Load("../../testdata/config/firewall-version-12.2.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Version() != "12.2.0" || cfg.DigestVersion() != "11.2.0" {
		t.Errorf("version %s read with %s, want 12.2.0 read with 11.2.0", cfg.Version(), cfg.DigestVersion())
	}
	for _, want := range []string{"12.2.0", "11.2.0"} {
		if !strings.Contains(rep.VersionGap, want) {
			t.Errorf("the report's gap must name %s, got %q", want, rep.VersionGap)
		}
	}
	if cfg.VersionGap() != rep.VersionGap {
		t.Error("the config and the report must describe the same gap")
	}
	if !strings.Contains(rep.String(), "12.2.0") {
		t.Errorf("the report's String must carry the gap, got %q", rep.String())
	}
}

// A configuration older than every digest is read with the lowest one.
func TestLoadUsesTheLowestDigestWhenNoneIsLower(t *testing.T) {
	t.Parallel()
	cfg, rep, err := Load("../../testdata/config/unsupported-version.xml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DigestVersion() != "11.2.0" {
		t.Errorf("9.1.0 read with %s, want 11.2.0", cfg.DigestVersion())
	}
	if !strings.Contains(rep.VersionGap, "9.1.0") {
		t.Errorf("the gap must name 9.1.0, got %q", rep.VersionGap)
	}
}

// An exact match has no gap.
func TestLoadWithAnExactDigestHasNoGap(t *testing.T) {
	t.Parallel()
	cfg, rep, err := Load("../../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VersionGap() != "" || rep.VersionGap != "" {
		t.Errorf("gap = %q / %q, want none", cfg.VersionGap(), rep.VersionGap)
	}
	if cfg.DigestVersion() != cfg.Version() {
		t.Errorf("digest %s, version %s", cfg.DigestVersion(), cfg.Version())
	}
}

// A version that is not a PAN-OS version cannot be matched to anything.
func TestLoadRejectsAMalformedVersion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bad.xml")
	if err := os.WriteFile(path, []byte(`<config version="eleven"><devices/></config>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(path); err == nil || !strings.Contains(err.Error(), "eleven") {
		t.Errorf("want an error naming the bad version, got %v", err)
	}
}

func TestNearestDigest(t *testing.T) {
	t.Parallel()
	have := []string{"10.1.0", "11.2.0"}
	for in, want := range map[string]string{
		"11.2.0": "11.2.0",
		"12.2.0": "11.2.0",
		"11.0.0": "10.1.0",
		"10.1.0": "10.1.0",
		"9.1.0":  "10.1.0",
	} {
		got, err := nearestDigest(in, have)
		if err != nil || got != want {
			t.Errorf("nearestDigest(%s) = %q, %v; want %s", in, got, err, want)
		}
	}
	if _, err := nearestDigest("11.2", have); err == nil {
		t.Error("a two-part version must be rejected")
	}
	if _, err := nearestDigest("11.x.0", have); err == nil {
		t.Error("a non-numeric version must be rejected")
	}
	if _, err := nearestDigest("11.2.0", nil); err == nil {
		t.Error("a build with no digest must say so")
	}
}

func TestDigestVersionsComeFromTheEmbeddedFiles(t *testing.T) {
	t.Parallel()
	if got := digestVersions(digestFS); len(got) != 1 || got[0] != "11.2.0" {
		t.Errorf("digestVersions = %v, want [11.2.0]", got)
	}
}

// Only firewall digests with a well-formed version count, sorted by version rather
// than by name: 9.1.0 sorts after 11.2.0 as a string.
func TestDigestVersionsFilterAndSort(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"schemadigest/panos-11.2.0-firewall.json.gz": {},
		"schemadigest/panos-9.1.0-firewall.json.gz":  {},
		"schemadigest/panos-10.1.0-router.json.gz":   {},
		"schemadigest/panos-x.y.z-firewall.json.gz":  {},
		"schemadigest/README":                        {},
	}
	if got := strings.Join(digestVersions(fsys), ","); got != "9.1.0,11.2.0" {
		t.Errorf("digestVersions = %s, want 9.1.0,11.2.0", got)
	}
	if got := digestVersions(fstest.MapFS{}); got != nil {
		t.Errorf("no directory must yield nothing, got %v", got)
	}
}

func TestNearestDigestSkipsAMalformedEntry(t *testing.T) {
	t.Parallel()
	if got, err := nearestDigest("11.2.0", []string{"bad", "11.2.0"}); err != nil || got != "11.2.0" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestLoadDigestReportsAMissingFile(t *testing.T) {
	t.Parallel()
	if _, err := loadDigest("0.0.1"); err == nil || !strings.Contains(err.Error(), "0.0.1") {
		t.Errorf("want an error naming the version, got %v", err)
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

// The schema is decoded once per process and shared, so two loads of the same
// version get the same schema.
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
		t.Error("two configurations of the same version must share one decoded schema")
	}
	if a.Root() == b.Root() {
		t.Error("but each keeps its own parsed tree")
	}
}

// A <config> element without a version cannot be matched to a schema.
func TestLoadRejectsAConfigWithNoVersion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "noversion.xml")
	if err := os.WriteFile(path, []byte("<config><devices/></config>"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("want an error naming the missing version, got %v", err)
	}
}
