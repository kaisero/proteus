package main

import (
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"strings"

	"github.com/okaiser/go-panos-schema/internal/codegen"
	"github.com/okaiser/go-panos-schema/internal/digest"
	"github.com/okaiser/go-panos-schema/internal/schema"
)

// versionPackage turns a config version into a Go package directory: 11.2.0
// becomes v11_2. The patch level is dropped, because the schema tracks the minor.
func versionPackage(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return "v" + strings.ReplaceAll(version, ".", "_")
	}
	return "v" + parts[0] + "_" + parts[1]
}

// runGenerate writes one Go package per digest found in digestDir.
func runGenerate(digestDir, outDir string) error {
	entries, err := os.ReadDir(digestDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", digestDir, err)
	}
	written := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json.gz") {
			continue
		}
		path := filepath.Join(digestDir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		d, rerr := digest.Read(f)
		if cerr := f.Close(); cerr != nil && rerr == nil {
			rerr = cerr
		}
		if rerr != nil {
			return fmt.Errorf("read %s: %w", path, rerr)
		}

		groups := schema.GroupByShape(schema.EntryTypes(d.Root))
		names := codegen.Names(groups)
		src := codegen.Emit(codegen.ModelPackage, names, groups)

		pretty, ferr := format.Source([]byte(src))
		if ferr != nil {
			return fmt.Errorf("gofmt the generated source for %s: %w", e.Name(), ferr)
		}

		dir := filepath.Join(outDir, versionPackage(d.Version), d.Platform)
		//nolint:gosec // G301: the generated package is committed source, so it
		// must be group and world readable like any other source directory.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		out := filepath.Join(dir, "model.go")
		//nolint:gosec // G306: model.go is committed Go source, not a secret.
		if err := os.WriteFile(out, pretty, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", out, err)
		}
		fmt.Printf("wrote %s (%d types, %d bytes)\n", out, len(names), len(pretty))
		written++
	}
	if written == 0 {
		return fmt.Errorf("no digest found in %s; run: make schema-digest", digestDir)
	}
	return nil
}
