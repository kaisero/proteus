package digest

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"

	"github.com/okaiser/panos-analyst/internal/schema"
)

// Read decodes a gzipped JSON digest and rebuilds parent pointers, which are not
// serialised.
func Read(r io.Reader) (*Digest, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("digest: gzip: %w", err)
	}
	// Closing a gzip reader only reports a trailing-checksum problem, which
	// the decode below would already have surfaced.
	defer func() { _ = zr.Close() }()

	var d Digest
	if err := json.NewDecoder(zr).Decode(&d); err != nil {
		return nil, fmt.Errorf("digest: decode: %w", err)
	}
	if d.FormatVersion != formatVersion {
		return nil, fmt.Errorf("digest: format version %d, this build reads %d",
			d.FormatVersion, formatVersion)
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	relink(d.Root, nil)
	return &d, nil
}

func relink(n, parent *schema.Node) {
	if n == nil {
		return
	}
	n.Parent = parent
	for _, c := range n.Children {
		relink(c, n)
	}
}
