// Package cli is the panos-analyst command line: it fetches PAN-OS firewalls into a
// snapshot store and answers questions about them. cmd/panos-analyst only calls Run.
// Spec: docs/specs/2026-09-27-panos-analyst-scope.md §15.
//
// Usage:
//
//	panos-analyst fetch <device>... | --label k=v | --all
//	panos-analyst inventory init
//	panos-analyst snapshot list <device>
//	panos-analyst snapshot show [selectors]
//	panos-analyst snapshot diff [selectors] [--from <time>] [--to <time>]
//	panos-analyst search <term> [selectors] [--exact|--within|--contains] [filters]
//	panos-analyst simulate policy <source> <destination> [selectors] [flow flags]
//
// Exit codes: 0 answered completely, 1 error, 2 usage, 3 answered with holes or
// unresolved entries (spec §15 C11).
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/runlog"
)

// The exit codes of spec §15 C11.
const (
	exitOK         = 0
	exitError      = 1
	exitUsage      = 2
	exitIncomplete = 3
)

// exitErr carries an exit code. A usage error prints its message; an incomplete
// answer has already printed its output and says nothing more.
type exitErr struct {
	code int
	err  error
}

func (e *exitErr) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e *exitErr) Unwrap() error { return e.err }

func usageErr(format string, args ...any) error {
	return &exitErr{code: exitUsage, err: fmt.Errorf(format, args...)}
}

// errIncomplete is returned after an answer with holes or unresolved entries.
var errIncomplete = &exitErr{code: exitIncomplete}

// exitCode maps a command's error to the process exit code, printing it when there
// is something to say.
func exitCode(err error, stderr io.Writer) int {
	if err == nil {
		return exitOK
	}
	var e *exitErr
	if errors.As(err, &e) {
		if e.err != nil {
			fmt.Fprintf(stderr, "panos-analyst: %v\n", e.err)
		}
		return e.code
	}
	fmt.Fprintf(stderr, "panos-analyst: %v\n", err)
	return exitError
}

// Run executes one command line and returns the process exit code. version is
// the build's version string, reported by --version and in the run log.
func Run(ctx context.Context, version string, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	a := newApp(stdout, stderr, getenv, time.Now)
	a.version = version
	return a.execute(ctx, args)
}

// execute runs one command and returns its exit code. The run log opens before
// the command runs and records its exit last, so a run that ended badly can be
// read back; the log's path is printed when it did.
func (a *app) execute(ctx context.Context, argv []string) int {
	start := a.now()
	cmd := a.root()
	cmd.SetArgs(argv)
	a.argv = argv
	err := cmd.ExecuteContext(ctx)
	code := exitCode(err, a.stderr)
	if a.log == nil {
		return code
	}
	switch {
	case code == exitIncomplete:
		a.log.Warnf(runlog.TagRun, "the answer is incomplete: it has holes or unresolved entries")
	case err != nil:
		a.log.Errorf(runlog.TagRun, "%v", err)
	}
	a.log.Infof(runlog.TagRun, "exit %d after %s", code, a.now().Sub(start).Round(time.Millisecond))
	if code != exitOK {
		fmt.Fprintf(a.stderr, "log: %s\n", a.log.Path())
	}
	_ = a.log.Close()
	return code
}

// app holds what every command shares: where it writes, how it reads the
// environment and the clock, and the persistent flags.
type app struct {
	stdout, stderr io.Writer
	getenv         func(string) string
	now            func() time.Time
	version        string

	configFlag, storeFlag, outputFlag, maxAgeFlag string
	logLevelFlag, logDirFlag                      string
	verbose                                       bool

	argv   []string
	log    *runlog.Logger // the run log; nil until the command starts
	lookup func(ctx context.Context, name string) ([]netip.Addr, error)
}

func newApp(stdout, stderr io.Writer, getenv func(string) string, now func() time.Time) *app {
	return &app{stdout: stdout, stderr: stderr, getenv: getenv, now: now, version: "dev", lookup: lookupDNS}
}

func (a *app) root() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "panos-analyst",
		Short:         "Fetch PAN-OS firewalls into a snapshot store and ask questions of them",
		Version:       a.version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.SetOut(a.stdout)
	cmd.SetErr(a.stderr)
	cmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &exitErr{code: exitUsage, err: err}
	})
	pf := cmd.PersistentFlags()
	pf.StringVar(&a.configFlag, "config", "", "inventory file (default $PANOS_CONFIG or ~/.config/panos-analyst/config.yaml)")
	pf.StringVar(&a.storeFlag, "store", "", "snapshot store (default $PANOS_STORE, the inventory's store, or ~/.local/share/panos-analyst)")
	pf.StringVar(&a.outputFlag, "output", "", "text or json (default $PANOS_OUTPUT, the inventory's output, or text)")
	pf.StringVar(&a.maxAgeFlag, "max-age", "", "note snapshots older than this, e.g. 24h or 7d (default $PANOS_MAX_SNAPSHOT_AGE, the inventory's, or 24h)")
	pf.StringVar(&a.logLevelFlag, "log-level", "", "error, warn, info or debug (default $PANOS_LOG_LEVEL, the inventory's, or info)")
	pf.StringVar(&a.logDirFlag, "log-dir", "", "where run logs go (default $PANOS_LOG_DIR, the inventory's, or ~/.local/state/panos-analyst/log)")
	pf.BoolVar(&a.verbose, "verbose", false, "echo the run log to stderr")
	cmd.PersistentPreRunE = func(c *cobra.Command, _ []string) error { return a.openLog(c) }

	inv := &cobra.Command{Use: "inventory", Short: "Manage the device inventory"}
	inv.AddCommand(a.inventoryInitCmd())
	snap := &cobra.Command{Use: "snapshot", Short: "List, show and compare stored snapshots"}
	snap.AddCommand(a.snapshotListCmd(), a.snapshotShowCmd(), a.snapshotDiffCmd())
	sim := &cobra.Command{Use: "simulate", Short: "Simulate what a device would do"}
	sim.AddCommand(a.simulateCmds()...)

	cmd.AddCommand(a.fetchCmd(), inv, snap, a.searchCmd(), a.lookupCmd(), sim)
	return cmd
}

// args wraps a cobra argument check so a wrong count is a usage error.
func args(check cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, a []string) error {
		if err := check(cmd, a); err != nil {
			return &exitErr{code: exitUsage, err: err}
		}
		return nil
	}
}
