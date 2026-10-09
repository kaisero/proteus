package inventory

import (
	"bytes"
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ExportDir is the store's directory for what fetch shares with proteus mcp. A
// device name needs a leading letter or digit (ValidName), so no device's
// snapshots can land in it.
const ExportDir = ".proteus"

// ExportPath is where fetch writes the inventory export in a store root.
func ExportPath(storeRoot string) string {
	return filepath.Join(storeRoot, ExportDir, "inventory.yaml")
}

// exportHeader opens the export, so a reader knows not to edit it.
const exportHeader = "# Written by proteus fetch after every run (export_inventory: true).\n" +
	"# The inventory without credentials, for proteus mcp. Edits are overwritten.\n"

// Export is the inventory without credentials: no username, password or
// password variable, in the defaults or on any device. The rest stays,
// including the mcp: section (spec 2026-10-09 §5). The inventory is not
// changed.
func (inv *Inventory) Export() *Inventory {
	out := *inv
	out.Defaults.Username, out.Defaults.Password, out.Defaults.PasswordEnv = "", "", ""
	out.Devices = make([]Device, len(inv.Devices))
	for i, d := range inv.Devices {
		d.Username, d.Password, d.PasswordEnv = "", "", ""
		out.Devices[i] = d
	}
	if inv.MCP != nil {
		m := *inv.MCP
		out.MCP = &m
	}
	return &out
}

// WriteExport writes the inventory's export to ExportPath(storeRoot), mode 0600.
// It writes a temporary file in the same directory and renames it into place,
// so a reader sees the old export or the new one, never half of one.
func WriteExport(storeRoot string, inv *Inventory) error {
	b, err := yaml.Marshal(inv.Export())
	if err != nil {
		return fmt.Errorf("inventory export: %w", err)
	}
	path := ExportPath(storeRoot)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("inventory export: %w", err)
	}
	f, err := os.CreateTemp(dir, ".inventory-*.yaml")
	if err != nil {
		return fmt.Errorf("inventory export: %w", err)
	}
	done := false
	defer func() {
		if !done { // a failed write leaves no temporary file behind
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	// CreateTemp makes the file 0600. Sync and Close run even after a failed
	// write; the first error wins.
	_, werr := f.Write(append([]byte(exportHeader), b...))
	if err := cmp.Or(werr, f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("inventory export: %w", err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("inventory export: %w", err)
	}
	done = true
	// The rename lives in the directory: sync it, so the new export survives a
	// crash.
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("inventory export: %w", err)
	}
	return nil
}

// syncDir flushes a directory's entries to disk.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return cmp.Or(d.Sync(), d.Close())
}

// ReadExport reads an inventory export for proteus mcp. It refuses a file that
// holds a credential: the server never reads one (spec 2026-10-09 §4.2). The
// store and log_dir defaults are cleared: the server sets its own.
func ReadExport(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory export: %w", err)
	}
	inv, err := Parse(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if found := inv.credentials(); len(found) > 0 {
		return nil, fmt.Errorf("inventory export: %s holds credentials (%s); the server never reads them, so write it with proteus fetch and export_inventory: true",
			path, strings.Join(found, ", "))
	}
	inv.Defaults.Store, inv.Defaults.LogDir = "", ""
	return inv, nil
}

// credentials names every credential field the inventory sets.
func (inv *Inventory) credentials() []string {
	var out []string
	check := func(where, user, pw, pwEnv string) {
		for _, f := range []struct{ key, v string }{{"username", user}, {"password", pw}, {"password_env", pwEnv}} {
			if f.v != "" {
				out = append(out, where+": "+f.key)
			}
		}
	}
	check("defaults", inv.Defaults.Username, inv.Defaults.Password, inv.Defaults.PasswordEnv)
	for _, d := range inv.Devices {
		check("device "+d.Name, d.Username, d.Password, d.PasswordEnv)
	}
	return out
}
