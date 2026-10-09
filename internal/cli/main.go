// Package cli is the proteus command line: it fetches PAN-OS firewalls into a
// snapshot store and answers questions about them. cmd/proteus only calls Run.
//
// The commands, flags, output formats and exit codes are documented in
// docs/cli-reference.md. The contract every command keeps is
// docs/specs/2026-09-30-cli-consistency.md.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/query"
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

// Run executes one command line and returns the process exit code. version is
// the build's version string, reported by --version and in the run log.
func Run(ctx context.Context, version string, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	a := newApp(stdout, stderr, getenv, time.Now)
	a.version = version
	a.stdoutTTY, a.stderrTTY = isTerminal(stdout), isTerminal(stderr)
	return a.execute(ctx, args)
}

// execute runs one command and returns its exit code. The run log opens before
// the command runs and records its exit last, so a run that ended badly can be
// read back; the log's path is printed when it did.
func (a *app) execute(ctx context.Context, argv []string) int {
	start := a.now()
	a.argv = argv
	a.stderr = &lockedWriter{w: a.stderr}
	cmd := a.root()
	cmd.SetArgs(argv)
	err := cmd.ExecuteContext(ctx)
	code, msg := a.exitCode(ctx, err)
	if a.log != nil {
		switch {
		case code == exitIncomplete:
			a.log.Warnf(runlog.TagRun, "the answer is incomplete: it has holes or unresolved entries")
		case msg != nil:
			if _, signal := errors.AsType[signalCause](msg); signal {
				a.log.Errorf(runlog.TagRun, "interrupted: %v", err)
			} else {
				a.log.Errorf(runlog.TagRun, "%v", msg)
			}
		}
		a.log.Infof(runlog.TagRun, "exit %d after %s", code, a.now().Sub(start).Round(time.Millisecond))
	}
	a.report(code, msg)
	_ = a.log.Close()
	return code
}

// app holds what every command shares: where it writes, how it reads the
// environment and the clock, and the persistent flags.
type app struct {
	stdout, stderr io.Writer
	// stdoutTTY and stderrTTY say whether each is a terminal; Run sets them.
	stdoutTTY, stderrTTY bool
	getenv               func(string) string
	now                  func() time.Time
	version              string

	configFlag, storeFlag, outputFlag, maxAgeFlag string
	logLevelFlag, logDirFlag                      string
	verbose                                       bool
	colorFlag                                     string
	// detail is --detail on a question: summary or full.
	detail string

	// Resolved by resolveSettings in the root hook.
	hookRan      bool
	settingLines []string
	format       format
	color        colorMode
	storeRoot    string
	maxAge       time.Duration
	logLevel     runlog.Level
	logDir       string

	argv   []string
	log    *runlog.Logger // the run log; nil until the command starts
	lookup func(ctx context.Context, name string) ([]netip.Addr, error)
	// canonical gives an FQDN's canonical name; nil gives none.
	canonical func(ctx context.Context, name string) (string, error)
	// peerHost maps an HA peer's reported management address to a host; nil uses
	// the address. Tests point it at a second fake device.
	peerHost func(mgmtIP string) string

	// The inventory, read once per command by resolveSettings before the run log
	// opens, so the log settings and every other setting come from one file.
	invPath string
	inv     *inventory.Inventory
	invErr  error
}

func newApp(stdout, stderr io.Writer, getenv func(string) string, now func() time.Time) *app {
	return &app{stdout: stdout, stderr: stderr, getenv: getenv, now: now, version: "dev", lookup: query.SystemResolve, canonical: query.SystemCanonicalName}
}

func (a *app) root() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "proteus",
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
	for _, s := range append([]setting{a.configSetting()}, a.settingTable()...) {
		pf.StringVar(s.flag, s.name, "", s.help())
	}
	pf.BoolVar(&a.verbose, "verbose", false, "echo the run log to stderr")
	cmd.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		if skipsHook(c) {
			return nil
		}
		if err := a.resolveSettings(); err != nil {
			return err
		}
		if err := a.openLog(c); err != nil {
			return err
		}
		// Cobra checks required flags and flag groups after this hook and returns
		// plain errors, which would exit 1. Checking here keeps them usage errors.
		if err := c.ValidateRequiredFlags(); err != nil {
			return &exitErr{code: exitUsage, err: err}
		}
		if err := c.ValidateFlagGroups(); err != nil {
			return &exitErr{code: exitUsage, err: err}
		}
		return a.checkDetail(c)
	}

	inv := group("inventory", "Manage the device inventory", a.inventoryInitCmd())
	snap := group("snapshot", "List, show and compare stored snapshots",
		a.snapshotListCmd(), a.snapshotShowCmd(), a.snapshotDiffCmd())
	sim := group("simulate", "Simulate what a device would do", a.simulateCmds()...)

	cmd.AddCommand(a.fetchCmd(), inv, snap, a.searchCmd(), a.lookupCmd(), sim)
	cmd.SetHelpCommand(helpCmd(cmd))
	a.registerCompletions(cmd)
	return cmd
}

// group is a command that only holds subcommands. An argument that names none of
// them is an unknown command, exit 2; Cobra checks that only on the root. A bare
// group prints its help.
func group(use, short string, subs ...*cobra.Command) *cobra.Command {
	c := &cobra.Command{
		Use: use, Short: short, Args: args(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	c.AddCommand(subs...)
	return c
}

// helpCmd replaces Cobra's help command, which prints "Unknown help topic" and exits
// 0 for a topic that does not exist. Its ValidArgsFunction matches Cobra's own
// default help command (InitDefaultHelpCmd), so `help <TAB>` still completes.
func helpCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: "Help about any command",
		Long: `Help provides help for any command in the application.
Simply type ` + root.DisplayName() + ` help [path to command] for full details.`,
		RunE: func(_ *cobra.Command, argv []string) error {
			target, rest, err := root.Find(argv)
			if err != nil || len(rest) > 0 {
				return usageErr("unknown help topic %q", strings.Join(argv, " "))
			}
			return target.Help()
		},
		// ValidArgsFunction matches Cobra's own default help command
		// (InitDefaultHelpCmd): find the command named by the args given so far
		// and offer its available, non-hidden subcommand names.
		ValidArgsFunction: func(c *cobra.Command, argv []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			var completions []cobra.Completion
			cmd, _, e := c.Root().Find(argv)
			if e != nil {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			if cmd == nil {
				cmd = c.Root()
			}
			for _, subCmd := range cmd.Commands() {
				if subCmd.IsAvailableCommand() && strings.HasPrefix(subCmd.Name(), toComplete) {
					completions = append(completions, cobra.CompletionWithDesc(subCmd.Name(), subCmd.Short))
				}
			}
			return completions, cobra.ShellCompDirectiveNoFileComp
		},
	}
}

// skipsHook is true for commands that only print: help, shell completion, and the
// command groups. They open no run log and resolve no settings, so a bad setting
// cannot break help or tab completion (spec §4.7).
func skipsHook(c *cobra.Command) bool {
	if c.HasSubCommands() {
		return true
	}
	for p := c; p != nil; p = p.Parent() {
		switch p.Name() {
		case "help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
			return true
		}
	}
	return false
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
