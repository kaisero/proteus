package main

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

	"github.com/spf13/pflag"

	"github.com/okaiser/panos-analyst/estate"
	"github.com/okaiser/panos-analyst/inventory"
	"github.com/okaiser/panos-analyst/store"
)

// settings are the four values of spec §15 C14, resolved with the precedence
// default < file < PANOS_* env < flag.
type settings struct {
	invPath   string
	inv       *inventory.Inventory // nil when there is no inventory file and none was needed
	storeRoot string
	maxAge    time.Duration
	output    string
}

// settings resolves the settings. needInventory makes a missing inventory an error.
func (a *app) settings(needInventory bool) (settings, error) {
	var s settings
	var err error
	s.invPath = a.configFlag
	if s.invPath == "" {
		if s.invPath, err = inventory.DefaultPath(a.getenv); err != nil {
			return s, err
		}
	}
	s.inv, err = inventory.Load(s.invPath)
	if err != nil {
		if needInventory || !errors.Is(err, fs.ErrNotExist) {
			return s, err
		}
		s.inv = nil
	}
	var def inventory.Settings
	if s.inv != nil {
		def = s.inv.Defaults
	}

	switch {
	case a.storeFlag != "":
		s.storeRoot = a.storeFlag
	case a.getenv("PANOS_STORE") != "":
		s.storeRoot = a.getenv("PANOS_STORE")
	case def.Store != "":
		s.storeRoot = expandHome(def.Store)
	default:
		if s.storeRoot, err = store.DefaultRoot(a.getenv); err != nil {
			return s, err
		}
	}

	age := first(a.maxAgeFlag, a.getenv("PANOS_MAX_SNAPSHOT_AGE"), def.MaxSnapshotAge, "24h")
	if s.maxAge, err = inventory.ParseAge(age); err != nil {
		return s, usageErr("%v", err)
	}
	s.output = first(a.outputFlag, a.getenv("PANOS_OUTPUT"), def.Output, "text")
	if s.output != "text" && s.output != "json" {
		return s, usageErr("output %q, want text or json", s.output)
	}
	return s, nil
}

func first(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
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

func (sel *selection) bind(fs *pflag.FlagSet, withFresh bool) {
	fs.StringSliceVar(&sel.devices, "device", nil, "only these devices (repeatable)")
	fs.StringArrayVar(&sel.labels, "label", nil, "only devices with this key=value label (repeatable; all must hold)")
	fs.StringSliceVar(&sel.vsys, "vsys", nil, "only these vsys (repeatable; default every vsys)")
	fs.StringVar(&sel.file, "file", "", "read one configuration file instead of the store")
	fs.StringVar(&sel.at, "at", "", "read each device's newest snapshot at or before this time (id, RFC 3339 or date)")
	if withFresh {
		fs.BoolVar(&sel.fresh, "fresh", false, "fetch the selected devices first")
	}
}

// targets opens what a question runs against: one file, or the selected devices'
// snapshots. A --fresh fetch that fails leaves the previous snapshot in use and adds
// a note to that device's targets.
func (a *app) targets(ctx context.Context, sel selection, s settings, progress io.Writer) ([]estate.Target, []estate.Hole, error) {
	if sel.file != "" {
		if len(sel.devices) > 0 || len(sel.labels) > 0 || sel.at != "" || sel.fresh {
			return nil, nil, usageErr("--file reads one configuration; it cannot be combined with --device, --label, --at or --fresh")
		}
		return estate.OpenFile(sel.file, sel.vsys)
	}
	if s.inv == nil {
		return nil, nil, fmt.Errorf("no inventory at %s; run panos-analyst inventory init, or pass --file", s.invPath)
	}
	names, err := s.inv.Select(sel.devices, sel.labels)
	if err != nil {
		return nil, nil, usageErr("%v", err)
	}
	if len(names) == 0 {
		return nil, nil, usageErr("the selection matches no device")
	}
	var when estate.When
	when.Now, when.MaxAge = a.now(), s.maxAge
	if sel.at != "" {
		if when.At, err = estate.ParseAt(sel.at); err != nil {
			return nil, nil, usageErr("%v", err)
		}
	}
	st, err := a.openStore(s.storeRoot)
	if err != nil {
		return nil, nil, err
	}
	failed := map[string]string{}
	if sel.fresh {
		errs, _ := fetchEach(ctx, progress, s.inv, st, names, a.getenv)
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
