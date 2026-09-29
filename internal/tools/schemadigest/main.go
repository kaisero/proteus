// Command schemadigest turns a PAN-OS schema into the digest proteus embeds. It is
// a developer tool: run it when adding a PAN-OS version, through make schema-digest.
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
	outDir := fs.String("out", "internal/config/schemadigest", "directory to write digests into")
	ver := fs.String("version", "", "PAN-OS config version, e.g. 11.2.0")
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
