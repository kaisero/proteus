// Command schemadigest turns a PAN-OS schema into the one digest proteus embeds.
// It is a developer tool: run it through make schema-digest to replace the digest
// with the schema of a newer release. -version records that release.
//
// Usage:
//
//	go run ./internal/tools/schemadigest -schema schemas -out internal/config/schemadigest -version 11.2.0
//
// The schema is not published; copy it off an appliance with `make schema-pull`.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	fs := flag.NewFlagSet("schemadigest", flag.ExitOnError)
	schemaDir := fs.String("schema", "schemas", "directory holding a firewall's schema.xml")
	outDir := fs.String("out", "internal/config/schemadigest", "directory to write the digest into")
	ver := fs.String("version", "", "PAN-OS config version the schema came from, e.g. 11.2.0")
	_ = fs.Parse(os.Args[1:])
	if *ver == "" {
		fail(fmt.Errorf("-version is required, e.g. -version 11.2.0"))
	}
	if err := runDigest(*schemaDir, *outDir, *ver); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "schemadigest: %v\n", err)
	os.Exit(1)
}
