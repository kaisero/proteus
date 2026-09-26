package config

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"

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

// Config is a loaded configuration: the file, the schema that describes it, and
// the facts read from the root element. It is immutable once loaded.
type Config struct {
	path          string
	version       string
	detailVersion string
	platform      Platform
	root          *schema.Node
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
func (c *Config) Digest() *schema.Node { return c.root }

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

	version, detail, platform, err := sniff(f)
	if err != nil {
		return nil, rep, fmt.Errorf("config: %s: %w", path, err)
	}

	root, err := loadDigest(version, platform)
	if err != nil {
		return nil, rep, err
	}
	return &Config{
		path: path, version: version, detailVersion: detail,
		platform: platform, root: root,
	}, rep, nil
}

// sniff reads the root element and the first marker that names the platform.
//
// Panorama writes device-group, template and template-stack under devices/entry;
// a firewall writes vsys. The first of those to appear decides.
func sniff(r io.Reader) (version, detail string, platform Platform, err error) {
	dec := xml.NewDecoder(r)
	inConfig := false
	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return "", "", 0, fmt.Errorf("read: %w", terr)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !inConfig {
			if se.Name.Local != "config" {
				continue
			}
			inConfig = true
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "version":
					version = a.Value
				case "detail-version":
					detail = a.Value
				}
			}
			if version == "" {
				return "", "", 0, fmt.Errorf("the <config> element has no version attribute")
			}
			continue
		}
		switch se.Name.Local {
		case "device-group", "template", "template-stack":
			return version, detail, Panorama, nil
		case "vsys":
			return version, detail, Firewall, nil
		}
	}
	if !inConfig {
		return "", "", 0, fmt.Errorf("no <config> element found")
	}
	// A configuration with neither marker is a firewall with nothing configured.
	return version, detail, Firewall, nil
}

func loadDigest(version string, platform Platform) (*schema.Node, error) {
	name := digest.Filename(platform.String(), version)
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
	return d.Root, nil
}
