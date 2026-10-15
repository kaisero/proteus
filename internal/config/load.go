package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/okaiser/proteus/internal/digest"
	"github.com/okaiser/proteus/internal/schema"
)

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
	schema        *loadedSchema
	root          *Element
	predefined    *Element
}

// PredefinedFile is the file next to a configuration that holds the device's
// predefined services. fetch stores it as the document "predefined".
const PredefinedFile = "predefined.xml"

// Version returns the version attribute of the config root, e.g. 11.2.0, or
// empty when it has none. Nothing checks it: one schema reads every version.
func (c *Config) Version() string { return c.version }

// DetailVersion returns the patch level from the config root, e.g. 11.2.7.
func (c *Config) DetailVersion() string { return c.detailVersion }

// Path returns the file the configuration was loaded from.
func (c *Config) Path() string { return c.path }

// Digest returns the schema root that describes this configuration.
func (c *Config) Digest() *schema.Node { return c.schema.root }

// Root returns the parsed config element. It is read-only.
func (c *Config) Root() *Element { return c.root }

// Predefined returns the device's predefined objects as a <predefined> element
// holding a <service> element, or nil when the configuration came without them.
// It is read-only, and it is not part of Root: a walk of the configuration never
// sees it.
func (c *Config) Predefined() *Element { return c.predefined }

// Load reads a configuration file and the schema digest that describes it. One
// digest reads every PAN-OS version.
//
// A configuration arrives in two shapes. type=export&category=configuration
// yields a bare <config>; type=config&action=show wraps it in
// <response><result>. Both load.
//
// When PredefinedFile sits next to the configuration, Load reads it too, so a
// stored snapshot and --file on its config.xml see the same predefined services.
// No file, or a well-formed file without a <service> element: the configuration
// loads without them, and rules that name them stay in doubt. A file that cannot
// be read or parsed fails the load, because skipping it would hide data.
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
	if isPanorama(root) {
		return nil, rep, fmt.Errorf("config: %s is a Panorama configuration; "+
			"proteus reads each firewall's own configuration", path)
	}

	sch, err := loadDigest()
	if err != nil {
		return nil, rep, err
	}
	pre, err := loadPredefined(filepath.Join(filepath.Dir(path), PredefinedFile))
	if err != nil {
		return nil, rep, err
	}
	cfg := &Config{
		path: path, version: root.Attr("version"), detailVersion: root.Attr("detail-version"),
		schema: sch, root: root, predefined: pre,
	}
	rep.Untyped = cfg.undescribed()
	return cfg, rep, nil
}

// loadPredefined reads the device's predefined services, or returns nil when the
// file is absent or holds no <service> element.
//
// The device answers <show><predefined><xpath>/predefined/service</xpath></predefined></show>
// with <response status="success"><result><service> and one entry per service, in
// the shape of a configured service (as observed on fw02, PAN-OS 12.2.3, L4). The
// file is read bare or wrapped, as a configuration is. The <service> element is
// kept under a <predefined> element, so its path is /predefined/service, as on the
// device.
func loadPredefined(path string) (*Element, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	svc, err := parseTreeAt(f, "service")
	if errors.Is(err, errNoElement) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	pre := &Element{Name: "predefined", Children: []*Element{svc}}
	svc.Parent = pre
	return pre, nil
}

// isPanorama reports whether a configuration came from Panorama.
//
// Panorama writes device-group, template and template-stack under devices/entry;
// a firewall writes vsys. Observed on Panorama 11.2.7-h1.
func isPanorama(root *Element) bool {
	for _, d := range root.Find("devices", "entry") {
		for _, marker := range []string{"device-group", "template", "template-stack"} {
			if d.Child(marker) != nil {
				return true
			}
		}
	}
	return false
}

// loadedSchema is a decoded digest and the reference table derived from it.
//
// Both are immutable and both are expensive: decoding a digest costs about 40 ms,
// and building the reference table walks all 2,291 entry arrays for about 15 ms.
// Neither depends on a configuration file, so both are computed once per process
// and shared by every Config that uses that schema.
type loadedSchema struct {
	root  *schema.Node
	refs  refTable
	paths pathTable
	kinds kindTable
	// shared and rulebase are the nodes of /config/shared and of a vsys
	// rulebase, which also describes the shared pushed rulebases (ChildNode).
	shared, rulebase *schema.Node
}

var (
	schemaOnce   sync.Once
	schemaLoaded *loadedSchema
	schemaErr    error
)

func loadDigest() (*loadedSchema, error) {
	schemaOnce.Do(func() { schemaLoaded, schemaErr = readDigest(digestFS) })
	return schemaLoaded, schemaErr
}

// readDigest decodes the digest in fsys and builds its tables.
func readDigest(fsys fs.FS) (*loadedSchema, error) {
	f, err := fsys.Open("schemadigest/" + digest.Filename)
	if err != nil {
		return nil, fmt.Errorf("config: no schema digest: %w", err)
	}
	defer func() { _ = f.Close() }()
	d, err := digest.Read(f)
	if err != nil {
		return nil, fmt.Errorf("config: read digest %s: %w", digest.Filename, err)
	}
	return &loadedSchema{
		root: d.Root, refs: buildRefTable(d.Root), paths: buildPathTable(d.Root), kinds: buildKindTable(d.Root),
		shared:   d.Root.Step("shared"),
		rulebase: d.Root.Step("devices").Step("entry").Step("vsys").Step("entry").Step("rulebase"),
	}, nil
}
