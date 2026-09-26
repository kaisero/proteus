package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/okaiser/go-panos-schema/internal/digest"
	"github.com/okaiser/go-panos-schema/internal/schema"
)

// schemaFiles maps a vendor filename to the platform it describes.
var schemaFiles = map[string]string{
	"schema.xml":     digest.PlatformFirewall,
	"cms-schema.xml": digest.PlatformPanorama,
}

// runDigest turns the vendor schema files in schemaDir into committed digests.
func runDigest(schemaDir, outDir, version string) error {
	//nolint:gosec // G301: schemadigest holds committed repository files, so it
	// must be group and world readable like any other source directory.
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}
	written := 0
	for name, platform := range schemaFiles {
		in := filepath.Join(schemaDir, name)
		f, err := os.Open(in)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("open %s: %w", in, err)
		}
		root, perr := schema.Parse(f)
		if cerr := f.Close(); cerr != nil && perr == nil {
			perr = cerr
		}
		if perr != nil {
			return fmt.Errorf("parse %s: %w", in, perr)
		}
		if err := assertReferencesFound(root, in); err != nil {
			return err
		}

		out := filepath.Join(outDir, digest.Filename(platform, version))
		w, err := os.Create(out)
		if err != nil {
			return fmt.Errorf("create %s: %w", out, err)
		}
		werr := digest.Write(w, &digest.Digest{Platform: platform, Version: version, Root: root})
		cerr := w.Close()
		if werr != nil {
			return fmt.Errorf("write %s: %w", out, werr)
		}
		if cerr != nil {
			return fmt.Errorf("close %s: %w", out, cerr)
		}
		fmt.Printf("wrote %s\n", out)
		written++
	}
	if written == 0 {
		return fmt.Errorf("no schema file found in %s; expected schema.xml or cms-schema.xml "+
			"(run: make schema-pull HOST=user@host)", schemaDir)
	}
	return nil
}

// assertReferencesFound guards the failure mode that cost a proof-of-concept
// cycle: skipping <validate> parses without error and silently loses every
// memberof target.
func assertReferencesFound(root *schema.Node, path string) error {
	count := 0
	root.Walk(func(n *schema.Node) { count += len(n.MemberOf) })
	if count == 0 {
		return fmt.Errorf("%s parsed but declared no references; the parser is "+
			"dropping memberof targets, which live inside <validate>", path)
	}
	return nil
}
