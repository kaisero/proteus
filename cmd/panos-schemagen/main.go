// Command panos-schemagen generates the Go configuration model from a PAN-OS
// schema.
//
// Usage:
//
//	panos-schemagen -schema schemas -out config
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
	schemaDir := flag.String("schema", "schemas", "directory holding schema.xml and cms-schema.xml")
	outDir := flag.String("out", "config", "directory to write the generated model into")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	// The generator is deliberately unimplemented. Naming, API surface and
	// version handling are open design questions; see ARCHITECTURE.md.
	fmt.Fprintf(os.Stderr,
		"panos-schemagen: not implemented\n"+
			"  would read schemas from %q and write the model to %q\n"+
			"  the design is still open; see ARCHITECTURE.md\n",
		*schemaDir, *outDir)
	os.Exit(1)
}
