// Command panos-analyst fetches PAN-OS firewalls into a snapshot store and answers
// questions about them. The commands live in internal/cli.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/okaiser/proteus/internal/cli"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Run(ctx, version, os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}
