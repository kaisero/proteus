package config

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/okaiser/go-panos-schema/internal/digest"
	"github.com/okaiser/go-panos-schema/internal/schema"
)

// Platform is the kind of device a configuration came from.
type Platform int

// The platforms a configuration can describe.
const (
	Firewall Platform = iota
	Panorama
)

func (p Platform) String() string {
	if p == Panorama {
		return "panorama"
	}
	return "firewall"
}

// supported lists the PAN-OS versions this build carries a digest for.
var supported = []string{"11.2.0"}

// Config is a loaded configuration: the parsed file, the schema that describes it,
// and the facts read from the root element. It is immutable once loaded.
//
// The file is parsed once, here. Every reader in resolve and index works on the
// element tree rather than reopening the path, because reading per query cost 17
// parses for a single index build.
type Config struct {
	path          string
	version       string
	detailVersion string
	platform      Platform
	schema        *loadedSchema
	root          *Element
}

// Version returns the schema version from the config root, e.g. 11.2.0.
func (c *Config) Version() string { return c.version }

// DetailVersion returns the patch level from the config root, e.g. 11.2.7.
func (c *Config) DetailVersion() string { return c.detailVersion }

// Platform reports whether the configuration came from a firewall or Panorama.
func (c *Config) Platform() Platform { return c.platform }

// Path returns the file the configuration was loaded from.
func (c *Config) Path() string { return c.path }

// Digest returns the schema root that describes this configuration.
func (c *Config) Digest() *schema.Node { return c.schema.root }

// Root returns the parsed config element. It is read-only.
func (c *Config) Root() *Element { return c.root }

// Load reads a configuration file and the schema digest that describes it.
//
// A configuration arrives in two shapes. type=export&category=configuration
// yields a bare <config>; type=config&action=show wraps it in
// <response><result>. Both load.
func Load(path string) (*Config, Report, error) {
	var rep Report
	f, err := os.Open(path)
	if err != nil {
		return nil, rep, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	root, err := parseTree(f)
	if err != nil {
		return nil, rep, fmt.Errorf("config: %s: %w", path, err)
	}
	version := root.Attr("version")
	if version == "" {
		return nil, rep, fmt.Errorf("config: %s: the <config> element has no version attribute", path)
	}
	platform := platformOf(root)

	sch, err := loadDigest(version, platform)
	if err != nil {
		return nil, rep, err
	}
	return &Config{
		path: path, version: version, detailVersion: root.Attr("detail-version"),
		platform: platform, schema: sch, root: root,
	}, rep, nil
}

// platformOf reports whether a configuration came from a firewall or Panorama.
//
// Panorama writes device-group, template and template-stack under devices/entry;
// a firewall writes vsys. A configuration with neither is a firewall with nothing
// configured.
func platformOf(root *Element) Platform {
	for _, d := range root.Find("devices", "entry") {
		for _, marker := range []string{"device-group", "template", "template-stack"} {
			if d.Child(marker) != nil {
				return Panorama
			}
		}
	}
	return Firewall
}

// loadedSchema is a decoded digest and the reference table derived from it.
//
// Both are immutable and both are expensive: decoding a digest costs about 40 ms,
// and building the reference table walks all 2,291 entry arrays for about 15 ms.
// Neither depends on a configuration file, so both are computed once per process
// and shared by every Config that uses that schema.
type loadedSchema struct {
	root *schema.Node
	refs refTable
}

var (
	schemaMu    sync.Mutex
	schemaCache = map[string]*loadedSchema{}
)

func loadDigest(version string, platform Platform) (*loadedSchema, error) {
	name := digest.Filename(platform.String(), version)

	schemaMu.Lock()
	defer schemaMu.Unlock()
	if ls, ok := schemaCache[name]; ok {
		return ls, nil
	}

	f, err := digestFS.Open("schemadigest/" + name)
	if err != nil {
		return nil, fmt.Errorf("config: no schema for PAN-OS %s %s; this build supports %s",
			version, platform, strings.Join(supported, ", "))
	}
	defer func() { _ = f.Close() }()
	d, err := digest.Read(f)
	if err != nil {
		return nil, fmt.Errorf("config: read digest %s: %w", name, err)
	}
	ls := &loadedSchema{root: d.Root, refs: buildRefTable(d.Root)}
	schemaCache[name] = ls
	return ls, nil
}
