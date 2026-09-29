// Command panos-schemagen builds the schema digest and generates the Go model.
//
// Usage:
//
//	panos-schemagen digest   -schema schemas -out internal/config/schemadigest -version 11.2.0
//	panos-schemagen generate -digest internal/config/schemadigest -out internal/config
//
// The schema is not published; copy it off an appliance with `make schema-pull`.
package main

import (
	"flag"
	"fmt"
	"os"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "digest":
		fs := flag.NewFlagSet("digest", flag.ExitOnError)
		schemaDir := fs.String("schema", "schemas", "directory holding schema.xml and cms-schema.xml")
		outDir := fs.String("out", "internal/config/schemadigest", "directory to write digests into")
		ver := fs.String("version", "", "PAN-OS config version, e.g. 11.2.0")
		_ = fs.Parse(os.Args[2:])
		if *ver == "" {
			fail(fmt.Errorf("-version is required, e.g. -version 11.2.0"))
		}
		if err := runDigest(*schemaDir, *outDir, *ver); err != nil {
			fail(err)
		}
	case "generate":
		fs := flag.NewFlagSet("generate", flag.ExitOnError)
		digestDir := fs.String("digest", "internal/config/schemadigest", "directory holding committed digests")
		outDir := fs.String("out", "internal/config", "directory to write generated packages into")
		_ = fs.Parse(os.Args[2:])
		if err := runGenerate(*digestDir, *outDir); err != nil {
			fail(err)
		}
	case "-version", "--version", "version":
		fmt.Println(version)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprint(os.Stderr, "usage:\n"+
		"  panos-schemagen digest   -schema <dir> -out <dir> -version <x.y.z>\n"+
		"  panos-schemagen generate -digest <dir> -out <dir>\n")
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "panos-schemagen: %v\n", err)
	os.Exit(1)
}
