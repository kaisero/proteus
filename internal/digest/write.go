package digest

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
)

// Write encodes a digest as gzipped JSON.
func Write(w io.Writer, d *Digest) error {
	if err := d.validate(); err != nil {
		return err
	}
	out := *d
	out.FormatVersion = formatVersion

	zw, err := gzip.NewWriterLevel(w, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("digest: gzip: %w", err)
	}
	if err := json.NewEncoder(zw).Encode(&out); err != nil {
		_ = zw.Close()
		return fmt.Errorf("digest: encode: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("digest: close gzip: %w", err)
	}
	return nil
}
