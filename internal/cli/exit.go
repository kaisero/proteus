package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kaisero/proteus/internal/inventory"
	"github.com/kaisero/proteus/internal/query"
)

// exitCode maps a command's error to the exit code and the message to print; a nil
// message prints nothing. A signal wins over the error it caused, but a command that
// finished as the signal arrived still exits 0.
func (a *app) exitCode(ctx context.Context, err error) (int, error) {
	if err == nil {
		return exitOK, nil
	}
	if c, ok := errors.AsType[signalCause](context.Cause(ctx)); ok {
		return c.code(), c
	}
	if e, ok := errors.AsType[*exitErr](err); ok {
		return e.code, e.err
	}
	// A question the query layer cannot take is the user's to fix.
	if u, ok := errors.AsType[*query.UsageError](err); ok {
		return exitUsage, u
	}
	if strings.HasPrefix(err.Error(), "unknown command ") {
		return exitUsage, err
	}
	return exitError, err
}

// report prints what a non-zero exit says on stderr: text, or in json and yaml
// modes one JSON line that is the last line of stderr (spec §4.4).
func (a *app) report(code int, msg error) {
	if code == exitOK {
		return
	}
	logPath := a.log.Path()
	if a.effectiveFormat() != formatText {
		line := struct {
			Format int    `json:"format"`
			Exit   int    `json:"exit"`
			Error  string `json:"error,omitempty"`
			Log    string `json:"log,omitempty"`
		}{Format: formatVersion, Exit: code, Log: logPath}
		if msg != nil && code != exitIncomplete {
			line.Error = msg.Error()
		}
		b, _ := json.Marshal(line)
		fmt.Fprintf(a.stderr, "%s\n", b)
		return
	}
	pal := palette{on: useColor(a.effectiveColor(), formatText, a.getenv, a.stderrTTY)}
	if msg != nil {
		fmt.Fprintf(a.stderr, "%s %v\n", pal.bad("proteus:"), msg)
	}
	if logPath != "" {
		fmt.Fprintf(a.stderr, "%s\n", pal.dim("log: "+logPath))
	}
}

// effectiveFormat is the resolved format, or, when the error came before the root
// hook, the same resolution done here: Cobra leaves --output unparsed after a bad flag
// and before an unknown root command.
func (a *app) effectiveFormat() format {
	if a.hookRan {
		return a.format
	}
	f, err := parseFormat(a.early("output", "PROTEUS_OUTPUT", func(s inventory.Settings) string { return s.Output }, "text"))
	if err != nil {
		return formatText
	}
	return f
}

// effectiveColor is effectiveFormat for --color.
func (a *app) effectiveColor() colorMode {
	if a.hookRan {
		return a.color
	}
	m, err := parseColor(a.early("color", "PROTEUS_COLOR", func(s inventory.Settings) string { return s.Color }, "auto"))
	if err != nil {
		return colorAuto
	}
	return m
}

// early resolves one setting from argv, the environment and the inventory, for an
// error before the root hook.
func (a *app) early(flag, env string, file func(inventory.Settings) string, def string) string {
	if v := lastFlag(a.argv, flag); v != "" {
		return v
	}
	if v := a.getenv(env); v != "" {
		return v
	}
	path := lastFlag(a.argv, "config")
	if path == "" {
		path = a.getenv("PROTEUS_CONFIG")
	}
	if path == "" {
		path, _ = inventory.DefaultPath(a.getenv)
	}
	if a.noInventory {
		// proteus mcp never reads the inventory with credentials.
		return def
	}
	if inv, err := inventory.Load(expandHome(path)); err == nil && file(inv.Defaults) != "" {
		return file(inv.Defaults)
	}
	return def
}

// lastFlag is the value of --name in argv, as pflag would take it: the last one
// given, before any "--".
func lastFlag(argv []string, name string) string {
	var v string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			break
		}
		if rest, ok := strings.CutPrefix(arg, "--"+name+"="); ok {
			v = rest
			continue
		}
		if arg == "--"+name && i+1 < len(argv) {
			v = argv[i+1]
			i++
		}
	}
	return v
}
