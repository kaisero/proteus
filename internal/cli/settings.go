package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/store"
)

// setting is one value of spec §15 C14, resolved with the precedence
// default < file < PROTEUS_* env < flag (spec §8).
type setting struct {
	name    string                          // the flag's name, for the log and errors
	usage   string                          // what it sets, for the help text
	flag    *string                         // the persistent flag's variable
	env     string                          // PROTEUS_*
	fileKey string                          // the inventory key; "" if none
	file    func(inventory.Settings) string // the inventory field
	def     func(getenv func(string) string) (string, error)
	defText string               // the default, for the help text
	path    bool                 // expand ~/ in the value
	set     func(v string) error // parse and store
}

func constant(v string) func(func(string) string) (string, error) {
	return func(func(string) string) (string, error) { return v, nil }
}

// help is the flag's help text, built from the table so the precedence cannot drift.
func (s setting) help() string {
	h := s.usage + " (default $" + s.env
	if s.fileKey != "" {
		h += ", the inventory's " + s.fileKey
	}
	return h + ", or " + s.defText + ")"
}

// configSetting is the inventory path. It has no file source: it names the file.
func (a *app) configSetting() setting {
	return setting{
		name: "config", usage: "inventory file", flag: &a.configFlag, env: "PROTEUS_CONFIG",
		def: inventory.DefaultPath, defText: "~/.config/proteus/config.yaml", path: true,
		set: func(v string) error { a.invPath = v; return nil },
	}
}

// settingTable is every other setting, resolved after the inventory loads.
func (a *app) settingTable() []setting {
	return []setting{
		{
			name: "store", usage: "snapshot store", flag: &a.storeFlag, env: "PROTEUS_STORE",
			fileKey: "store", file: func(s inventory.Settings) string { return s.Store },
			def: store.DefaultRoot, defText: "~/.local/share/proteus", path: true,
			set: func(v string) error { a.storeRoot = v; return nil },
		},
		{
			name: "output", usage: "output format: text or json", flag: &a.outputFlag, env: "PROTEUS_OUTPUT",
			fileKey: "output", file: func(s inventory.Settings) string { return s.Output },
			def: constant("text"), defText: "text",
			set: func(v string) (err error) { a.format, err = parseFormat(v); return err },
		},
		{
			name: "max-age", usage: "note snapshots older than this, e.g. 24h or 7d", flag: &a.maxAgeFlag,
			env: "PROTEUS_MAX_SNAPSHOT_AGE", fileKey: "max_snapshot_age",
			file: func(s inventory.Settings) string { return s.MaxSnapshotAge }, def: constant("24h"), defText: "24h",
			set: func(v string) (err error) { a.maxAge, err = inventory.ParseAge(v); return err },
		},
		{
			name: "log-level", usage: "error, warn, info or debug", flag: &a.logLevelFlag, env: "PROTEUS_LOG_LEVEL",
			fileKey: "log_level", file: func(s inventory.Settings) string { return s.LogLevel },
			def: constant("info"), defText: "info",
			set: func(v string) (err error) { a.logLevel, err = runlog.ParseLevel(v); return err },
		},
		{
			name: "log-dir", usage: "where run logs go", flag: &a.logDirFlag, env: "PROTEUS_LOG_DIR",
			fileKey: "log_dir", file: func(s inventory.Settings) string { return s.LogDir },
			def: defaultLogDir, defText: "~/.local/state/proteus/log", path: true,
			set: func(v string) error { a.logDir = v; return nil },
		},
		{
			name: "color", usage: "auto, always or never", flag: &a.colorFlag, env: "PROTEUS_COLOR",
			fileKey: "color", file: func(s inventory.Settings) string { return s.Color },
			def: constant("auto"), defText: "auto",
			set: func(v string) (err error) { a.color, err = parseColor(v); return err },
		},
	}
}

// resolve finds one setting's value and where it came from.
func (a *app) resolve(s setting, file inventory.Settings) (value, source string, err error) {
	switch {
	case *s.flag != "":
		value, source = *s.flag, "flag"
	case a.getenv(s.env) != "":
		value, source = a.getenv(s.env), s.env
	case s.file != nil && s.file(file) != "":
		value, source = s.file(file), "inventory"
	default:
		if value, err = s.def(a.getenv); err != nil {
			return "", "", err
		}
		source = "default"
	}
	if s.path {
		value = expandHome(value)
	}
	return value, source, nil
}

// resolveSettings resolves the inventory path, loads the inventory once, then
// resolves every other setting with the inventory as its file source. It keeps one
// log line per setting for openLog, because the log's own place is a setting.
func (a *app) resolveSettings() error {
	a.settingLines = nil
	all := append([]setting{a.configSetting()}, a.settingTable()...)
	var file inventory.Settings
	for i, s := range all {
		v, src, err := a.resolve(s, file)
		if err != nil {
			return err
		}
		if err := s.set(v); err != nil {
			return usageErr("%s %q (from %s): %w", s.name, v, src, err)
		}
		a.settingLines = append(a.settingLines, fmt.Sprintf("setting %s=%s from %s", s.name, v, src))
		if i == 0 { // the inventory path is known: load it once
			a.inv, a.invErr = inventory.Load(a.invPath)
			if a.inv != nil {
				file = a.inv.Defaults
			}
		}
	}
	a.hookRan = true
	return nil
}

// openLog opens the run log with the resolved level and directory, and writes the
// command line and the setting lines first.
func (a *app) openLog(c *cobra.Command) error {
	var echo io.Writer
	if a.verbose {
		echo = a.stderr
	}
	keep := 0
	if a.inv != nil {
		keep = a.inv.Defaults.LogKeep
	}
	name := strings.TrimPrefix(c.CommandPath(), c.Root().Name()+" ")
	l, err := runlog.Open(runlog.Options{Dir: a.logDir, Command: name, Keep: keep, Level: a.logLevel, Echo: echo, Now: a.now})
	if err != nil {
		fmt.Fprintf(a.stderr, "proteus: warning: no run log: %v\n", err)
		return nil
	}
	a.log = l
	l.Infof(runlog.TagRun, "proteus %s: %s", a.version, strings.Join(a.argv, " "))
	for _, line := range a.settingLines {
		l.Infof(runlog.TagRun, "%s", line)
	}
	return nil
}

// defaultLogDir is $XDG_STATE_HOME/proteus/log, else ~/.local/state/proteus/log.
func defaultLogDir(getenv func(string) string) (string, error) {
	if x := getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "proteus", "log"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "proteus", "log"), nil
}

// settings are what a command reads from the resolved settings.
type settings struct {
	invPath   string
	inv       *inventory.Inventory // nil when there is no inventory file and none was needed
	storeRoot string
	maxAge    time.Duration
}

// settings returns the resolved settings. needInventory makes a missing inventory an
// error; an inventory that exists but cannot be read is always one.
func (a *app) settings(needInventory bool) (settings, error) {
	s := settings{invPath: a.invPath, inv: a.inv, storeRoot: a.storeRoot, maxAge: a.maxAge}
	if a.invErr != nil {
		if needInventory || !errors.Is(a.invErr, fs.ErrNotExist) {
			return s, a.invErr
		}
		s.inv = nil
	}
	return s, nil
}

func expandHome(p string) string {
	rest, ok := strings.CutPrefix(p, "~/")
	if !ok {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, rest)
}

// selection is the selector flags of spec §15 C7 and C8.
type selection struct {
	devices, labels, vsys []string
	file, at              string
	fresh                 bool
}

func (sel *selection) bind(cmd *cobra.Command, withFresh bool) {
	fs := cmd.Flags()
	fs.StringSliceVar(&sel.devices, "device", nil, "only these devices (repeatable)")
	fs.StringArrayVar(&sel.labels, "label", nil, "only devices with this key=value label (repeatable; all must hold)")
	fs.StringSliceVar(&sel.vsys, "vsys", nil, "only these vsys (repeatable; default every vsys)")
	fs.StringVar(&sel.file, "file", "", "read one configuration file instead of the store")
	fs.StringVar(&sel.at, "at", "", "read each device's newest snapshot at or before this time (id, RFC 3339 or date)")
	// --file reads one configuration; the store's selectors mean nothing with it.
	for _, other := range []string{"device", "label", "at"} {
		cmd.MarkFlagsMutuallyExclusive("file", other)
	}
	if withFresh {
		fs.BoolVar(&sel.fresh, "fresh", false, "fetch the selected devices first")
		cmd.MarkFlagsMutuallyExclusive("file", "fresh")
	}
}

// targets opens what a question runs against: one file, or the selected devices'
// snapshots. A --fresh fetch that fails leaves the previous snapshot in use and adds
// a note to that device's targets.
func (a *app) targets(ctx context.Context, sel selection, s settings, progress io.Writer) ([]estate.Target, []estate.Hole, error) {
	if sel.file != "" {
		return estate.OpenFile(sel.file, sel.vsys, a.log)
	}
	if s.inv == nil {
		return nil, nil, fmt.Errorf("no inventory at %s; run proteus inventory init, or pass --file", s.invPath)
	}
	names, err := s.inv.Select(sel.devices, sel.labels)
	if err != nil {
		return nil, nil, usageErr("%w", err)
	}
	if len(names) == 0 {
		return nil, nil, usageErr("the selection matches no device")
	}
	var when estate.When
	when.Now, when.MaxAge, when.Log = a.now(), s.maxAge, a.log
	if sel.at != "" {
		if when.At, err = estate.ParseAt(sel.at); err != nil {
			return nil, nil, usageErr("%w", err)
		}
	}
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return nil, nil, err
	}
	failed := map[string]string{}
	if sel.fresh {
		errs, _ := a.fetcher(s.inv, st).each(ctx, progress, names)
		for i, e := range errs {
			if e != nil {
				failed[names[i]] = e.Error()
			}
		}
	}
	ts, holes := estate.Open(st, names, sel.vsys, when)
	for i := range ts {
		if msg, ok := failed[ts[i].Device]; ok {
			ts[i].Notes = append(ts[i].Notes, "fresh fetch failed, answering from the previous snapshot: "+msg)
		}
	}
	return ts, holes, nil
}

// openStore opens the store with the app's clock, so snapshot ids follow it.
func (a *app) openStore(root string) (*store.Store, error) {
	st, err := store.Open(root)
	if err != nil {
		return nil, err
	}
	return st.WithClock(a.now), nil
}

// ago renders an age for a person: 45m, 3h, 2d.
func ago(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
