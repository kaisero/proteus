package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
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
	digestVersion string
	schema        *loadedSchema
	root          *Element
}

// Version returns the schema version from the config root, e.g. 11.2.0.
func (c *Config) Version() string { return c.version }

// DetailVersion returns the patch level from the config root, e.g. 11.2.7.
func (c *Config) DetailVersion() string { return c.detailVersion }

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
	if isPanorama(root) {
		return nil, rep, fmt.Errorf("config: %s is a Panorama configuration; "+
			"proteus reads each firewall's own configuration", path)
	}

	dv, err := nearestDigest(version, digestVersions(digestFS))
	if err != nil {
		return nil, rep, fmt.Errorf("config: %s: %w", path, err)
	}
	sch, err := loadDigest(dv)
	if err != nil {
		return nil, rep, err
	}
	cfg := &Config{
		path: path, version: version, detailVersion: root.Attr("detail-version"),
		digestVersion: dv, schema: sch, root: root,
	}
	rep.VersionGap = cfg.VersionGap()
	return cfg, rep, nil
}

// DigestVersion returns the PAN-OS version of the schema the configuration was read
// with. It differs from Version when this build carries no digest for that version.
func (c *Config) DigestVersion() string { return c.digestVersion }

// VersionGap describes the difference between Version and DigestVersion, or is
// empty when they agree.
//
// A configuration read with another release's schema can be under-read silently: a
// field that was added or moved yields no reference, so a lookup misses rules and
// looks complete. Spec §9 requires the gap to travel with every answer.
func (c *Config) VersionGap() string {
	if c.version == c.digestVersion {
		return ""
	}
	return fmt.Sprintf("the configuration is PAN-OS %s but was read with the %s schema, "+
		"the nearest this build carries; a field added or moved between them yields no "+
		"reference, so this answer can miss rules", c.version, c.digestVersion)
}

// digestVersions lists the PAN-OS versions a file system carries a firewall digest
// for, oldest first. Load passes the embedded files, so adding a digest needs no
// edit here.
func digestVersions(fsys fs.FS) []string {
	entries, err := fs.ReadDir(fsys, "schemadigest")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		v, ok := strings.CutPrefix(e.Name(), "panos-")
		if !ok {
			continue
		}
		if v, ok = strings.CutSuffix(v, "-"+digest.PlatformFirewall+".json.gz"); !ok {
			continue
		}
		if _, err := parseVersion(v); err == nil {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(x, y string) int {
		a, _ := parseVersion(x)
		b, _ := parseVersion(y)
		return slices.Compare(a[:], b[:])
	})
	return out
}

// nearestDigest picks the digest a configuration is read with: its own version when
// the build has it, else the highest below it, else the lowest there is. have must
// be sorted oldest first. Source: docs/specs/2026-09-27-panos-analyst-scope.md §9.
func nearestDigest(version string, have []string) (string, error) {
	want, err := parseVersion(version)
	if err != nil {
		return "", err
	}
	if len(have) == 0 {
		return "", errors.New("this build carries no schema digest")
	}
	best := ""
	for _, h := range have {
		hv, err := parseVersion(h)
		if err != nil {
			continue
		}
		if lessVersion(want, hv) {
			break
		}
		best = h
	}
	if best == "" {
		best = have[0]
	}
	return best, nil
}

// parseVersion reads a PAN-OS schema version such as 11.2.0.
func parseVersion(s string) ([3]int, error) {
	var v [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("version %q is not a PAN-OS version like 11.2.0", s)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, fmt.Errorf("version %q is not a PAN-OS version like 11.2.0", s)
		}
		v[i] = n
	}
	return v, nil
}

func lessVersion(a, b [3]int) bool { return slices.Compare(a[:], b[:]) < 0 }

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
}

var (
	schemaMu    sync.Mutex
	schemaCache = map[string]*loadedSchema{}
)

func loadDigest(version string) (*loadedSchema, error) {
	name := digest.Filename(digest.PlatformFirewall, version)

	schemaMu.Lock()
	defer schemaMu.Unlock()
	if ls, ok := schemaCache[name]; ok {
		return ls, nil
	}

	f, err := digestFS.Open("schemadigest/" + name)
	if err != nil {
		return nil, fmt.Errorf("config: no schema digest for PAN-OS %s", version)
	}
	defer func() { _ = f.Close() }()
	d, err := digest.Read(f)
	if err != nil {
		return nil, fmt.Errorf("config: read digest %s: %w", name, err)
	}
	ls := &loadedSchema{root: d.Root, refs: buildRefTable(d.Root), paths: buildPathTable(d.Root)}
	schemaCache[name] = ls
	return ls, nil
}
