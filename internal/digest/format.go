// Package digest reads and writes the committed schema digest.
//
// The digest is this project's own artifact, derived from the vendor schema. It
// keeps what code generation and the schema package need and drops the rest, so
// it can be committed and gated in CI without redistributing vendor files.
package digest

import (
	"fmt"

	"github.com/okaiser/panos-analyst/internal/schema"
)

// The platform a digest was built from.
const (
	PlatformFirewall = "firewall" // schema.xml
	PlatformPanorama = "panorama" // cms-schema.xml
)

// formatVersion changes when the on-disk shape changes. Read refuses a digest it
// does not understand rather than decoding it wrongly.
const formatVersion = 1

// Digest is one platform's schema at one PAN-OS version.
type Digest struct {
	FormatVersion int          `json:"format"`
	Platform      string       `json:"platform"`
	Version       string       `json:"version"` // the config root version, e.g. 11.2.0
	Root          *schema.Node `json:"root"`
}

// Filename returns the committed name for a digest.
func Filename(platform, version string) string {
	return fmt.Sprintf("panos-%s-%s.json.gz", version, platform)
}

func (d *Digest) validate() error {
	switch {
	case d == nil:
		return fmt.Errorf("digest: nil")
	case d.Platform != PlatformFirewall && d.Platform != PlatformPanorama:
		return fmt.Errorf("digest: unknown platform %q, want %s or %s",
			d.Platform, PlatformFirewall, PlatformPanorama)
	case d.Version == "":
		return fmt.Errorf("digest: empty version")
	case d.Root == nil:
		return fmt.Errorf("digest: no root node")
	}
	return nil
}
