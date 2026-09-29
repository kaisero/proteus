package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/okaiser/proteus/internal/digest"
	"github.com/okaiser/proteus/internal/schema"
)

// schemaFile is the vendor file a firewall carries at /opt/pancfg/mgmt/factory.
const schemaFile = "schema.xml"

// runDigest turns the firewall schema in schemaDir into a committed digest.
func runDigest(schemaDir, outDir, version string) error {
	in := filepath.Join(schemaDir, schemaFile)
	f, err := os.Open(in)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("no %s found in %s (run: make schema-pull HOST=user@host)", schemaFile, schemaDir)
	}
	if err != nil {
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

	//nolint:gosec // G301: schemadigest holds committed repository files, so it
	// must be group and world readable like any other source directory.
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", outDir, err)
	}
	out := filepath.Join(outDir, digest.Filename(digest.PlatformFirewall, version))
	w, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("create %s: %w", out, err)
	}
	werr := digest.Write(w, &digest.Digest{Platform: digest.PlatformFirewall, Version: version, Root: root})
	cerr := w.Close()
	if werr != nil {
		return fmt.Errorf("write %s: %w", out, werr)
	}
	if cerr != nil {
		return fmt.Errorf("close %s: %w", out, cerr)
	}
	fmt.Printf("wrote %s\n", out)
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
