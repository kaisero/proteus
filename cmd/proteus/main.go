// Command proteus fetches PAN-OS firewalls into a snapshot store and answers
// questions about them. The commands live in internal/cli.
package main

import (
	"context"
	"os"
	"runtime/debug"

	"github.com/okaiser/proteus/internal/cli"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	ctx, stop := cli.WithSignals(context.Background())
	info, ok := debug.ReadBuildInfo()
	code := cli.Run(ctx, versionOf(version, info, ok), os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

// versionOf is the version to report. A build through make stamps it with -ldflags.
// A go install build carries none, so it falls back to the module version, or to the
// commit it was built from.
func versionOf(stamped string, info *debug.BuildInfo, ok bool) string {
	if stamped != "dev" || !ok {
		return stamped
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch {
		case s.Key == "vcs.revision":
			rev = s.Value
		case s.Key == "vcs.modified" && s.Value == "true":
			dirty = "-dirty"
		}
	}
	if rev == "" {
		return stamped
	}
	return rev[:min(len(rev), 12)] + dirty
}
