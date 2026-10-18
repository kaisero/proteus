package config

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/okaiser/proteus/internal/digest"
	"github.com/okaiser/proteus/internal/schema"
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
	// SchemaRoot passes the error on, and gives no root.
	if root, err := rootOf(readDigest(fstest.MapFS{})); root != nil || err == nil {
		t.Errorf("SchemaRoot of a missing digest: %v, %v", root, err)
	}
}

// The embedded digest carries the template-object mark (spec 2026-10-17 C11).
// Object entries such as a zone or a CIE profile, and nodes such as the threats
// update schedule, have it. The device entry and the vsys entry do not, so the
// merge of a pushed template goes on below them.
func TestTheEmbeddedDigestMarksTemplateObjects(t *testing.T) {
	t.Parallel()
	root, err := SchemaRoot()
	if err != nil {
		t.Fatal(err)
	}
	step := func(path string) *schema.Node {
		n := root
		for seg := range strings.SplitSeq(path, "/") {
			n = n.Step(seg)
		}
		return n
	}
	for _, p := range []string{
		"devices/entry/vsys/entry/zone/entry",
		"devices/entry/vsys/entry/cloud-identity-engine/entry",
		"devices/entry/deviceconfig/system/update-schedule/threats",
	} {
		if n := step(p); n == nil || !n.TemplateObject {
			t.Errorf("%s: no template-object mark", p)
		}
	}
	for _, p := range []string{"devices/entry", "devices/entry/vsys/entry"} {
		if n := step(p); n == nil || n.TemplateObject {
			t.Errorf("%s: want a described node without the mark", p)
		}
	}
	cfg, _, err := Load("../../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Digest() != root {
		t.Error("SchemaRoot and a load share one decoded digest")
	}
}

// show config running answers indented, two spaces a level (spec 2026-10-17
// C12). The indent is whitespace only: the indented copy of a fixture loads to
// the tree of the fixture and of its compact form, and the round trip of R3
// holds for it.
func TestAnIndentedConfigLoadsAsTheCompact(t *testing.T) {
	t.Parallel()
	lab, _, err := Load("../../testdata/config/firewall-lab.xml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../testdata/config/firewall-lab-indented.xml")
	if err != nil {
		t.Fatal(err)
	}
	indented, rep, err := Load("../../testdata/config/firewall-lab-indented.xml")
	if err != nil {
		t.Fatal(err)
	}
	if p := treeDiff(lab.Root(), indented.Root()); p != "" {
		t.Errorf("the indented tree differs at %s", p)
	}
	compact, err := parseTree(bytes.NewReader(regexp.MustCompile(`>\s+<`).ReplaceAll(raw, []byte("><"))))
	if err != nil {
		t.Fatal(err)
	}
	if p := treeDiff(compact, indented.Root()); p != "" {
		t.Errorf("the compact tree differs at %s", p)
	}
	if rep.HasUnknown() || indented.Version() != lab.Version() || indented.DetailVersion() != lab.DetailVersion() {
		t.Errorf("report %s, version %s %s", rep, indented.Version(), indented.DetailVersion())
	}
	if !slices.Equal(xmlEvents(t, raw), xmlEvents(t, writeTree(indented.Root()))) {
		t.Error("the indented tree does not write back as its file (R3)")
	}
}

// The merge of firewall-lab.xml and its pushed template loads: a firewall
// configuration with template values is a firewall configuration, so no
// Panorama refusal (spec 2026-10-17 §2.3). The plugin that the digest does not
// describe counts once, at its top (R3, C3). The root keeps the base's
// attributes, so the version reads as before (§2.1).
func TestMergedFixtureLoads(t *testing.T) {
	t.Parallel()
	cfg, rep, err := Load("../../testdata/config/firewall-lab-merged.xml")
	if err != nil {
		t.Fatal(err)
	}
	const plugin = "/config/devices/localhost.localdomain/deviceconfig/plugins/example_plugin"
	if len(rep.Untyped) != 1 || rep.Untyped[0].XPath != plugin {
		t.Errorf("untyped = %+v, want %s once", rep.Untyped, plugin)
	}
	if cfg.Version() != "11.2.0" || cfg.DetailVersion() != "11.2.5" || cfg.Root().Attr("ptpl") != "" {
		t.Errorf("root: version %q, detail %q, ptpl %q", cfg.Version(), cfg.DetailVersion(), cfg.Root().Attr("ptpl"))
	}
	if zones := cfg.Root().Find("devices", "entry", "vsys", "entry", "zone", "entry"); len(zones) != 1 || zones[0].Attr("name") != "tpl-zone" {
		t.Errorf("zones = %d", len(zones))
	}
}

// Parse reads a configuration from bytes as Load reads its file: the same
// tree, version and report. It reads no file beside it, so a predefined.xml
// next to the file does not reach it. The fetch reads the domains of the
// identity sources from the configuration it holds (spec 2026-10-17 §3.2).
func TestParseReadsBytes(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../testdata/config/firewall-lab-merged.xml")
	if err != nil {
		t.Fatal(err)
	}
	pre, err := os.ReadFile("../../testdata/predefined/predefined.xml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, PredefinedFile), pre, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, loadRep, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed, parseRep, err := Parse(bytes.NewReader(raw), "config")
	if err != nil {
		t.Fatal(err)
	}
	if p := treeDiff(loaded.Root(), parsed.Root()); p != "" {
		t.Errorf("the parsed tree differs at %s", p)
	}
	if loaded.Predefined() == nil || parsed.Predefined() != nil {
		t.Errorf("predefined: loaded %v, parsed %v; want only the load to read the file beside", loaded.Predefined() != nil, parsed.Predefined() != nil)
	}
	if parsed.Path() != "config" || parsed.Version() != loaded.Version() || parsed.DetailVersion() != loaded.DetailVersion() ||
		parsed.Digest() != loaded.Digest() || !slices.Equal(parseRep.Untyped, loadRep.Untyped) {
		t.Errorf("parsed %q %q %q, report %s; loaded report %s", parsed.Path(), parsed.Version(), parsed.DetailVersion(), parseRep, loadRep)
	}
	// It refuses what Load refuses, and names the configuration.
	if _, _, err := Parse(strings.NewReader("<response/>"), "the-name"); err == nil || !strings.Contains(err.Error(), "the-name") {
		t.Errorf("no config element: %v", err)
	}
	panorama, err := os.ReadFile("../../testdata/config/panorama-rejected.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Parse(bytes.NewReader(panorama), "the-name"); err == nil || !strings.Contains(err.Error(), "Panorama") {
		t.Errorf("a Panorama configuration: %v", err)
	}
}
