package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

const withMCP = `version: 1
defaults:
  username: reader
  password: secret-default
  password_env: LAB_PASSWORD
  store: /data/store
  log_dir: /var/log/proteus
  export_inventory: true
devices:
  - name: fw01
    host: 192.0.2.10
    labels: {site: vienna}
  - name: fw02
    host: fw02.example.net
    username: other
    password: secret-fw02
    ha_peer: fw02-b.example.net
mcp:
  listen: 127.0.0.1:8765
  token_file: /run/secrets/proteus-mcp-token
  allowed_hosts: [proteus.example.org]
  identity_header: X-User-Claims
  audit_claims: [sub]
  audit_log: /var/log/proteus/mcp-audit.jsonl
  audit_max_mb: 50
  audit_keep: 5
  log_dir: /var/log/proteus/mcp
  log_keep: 200
  max_concurrent: 4
  max_queue: 16
  max_wait: 10s
  call_timeout: 60s
  max_loads: 2
  max_cache: 2048
`

// The mcp: section of spec 2026-10-09 §4.2 parses with every key.
func TestParseReadsTheMCPSection(t *testing.T) {
	t.Parallel()
	inv, err := Parse(strings.NewReader(withMCP))
	if err != nil {
		t.Fatal(err)
	}
	want := MCP{
		Listen: "127.0.0.1:8765", TokenFile: "/run/secrets/proteus-mcp-token", AllowedHosts: []string{"proteus.example.org"},
		IdentityHeader: "X-User-Claims", AuditClaims: []string{"sub"}, AuditLog: "/var/log/proteus/mcp-audit.jsonl",
		AuditMaxMB: 50, AuditKeep: 5, LogDir: "/var/log/proteus/mcp", LogKeep: 200, MaxConcurrent: 4, MaxQueue: 16, MaxWait: "10s",
		CallTimeout: "60s", MaxLoads: 2, MaxCache: 2048,
	}
	if m := inv.MCP; m == nil || m.Listen != want.Listen || m.TokenFile != want.TokenFile ||
		!slices.Equal(m.AllowedHosts, want.AllowedHosts) || m.IdentityHeader != want.IdentityHeader ||
		!slices.Equal(m.AuditClaims, want.AuditClaims) || m.AuditLog != want.AuditLog || m.AuditMaxMB != want.AuditMaxMB || m.AuditKeep != want.AuditKeep || m.LogDir != want.LogDir ||
		m.LogKeep != want.LogKeep || m.MaxConcurrent != want.MaxConcurrent || m.MaxQueue != want.MaxQueue ||
		m.MaxWait != want.MaxWait || m.CallTimeout != want.CallTimeout || m.MaxLoads != want.MaxLoads || m.MaxCache != want.MaxCache {
		t.Errorf("mcp = %+v", inv.MCP)
	}
	if !inv.Defaults.ExportInventory {
		t.Error("export_inventory is read")
	}
	if inv, err := Parse(strings.NewReader(sample)); err != nil || inv.MCP != nil || inv.Defaults.ExportInventory {
		t.Errorf("no mcp: section: %+v, %v", inv, err)
	}
}

func TestParseRejectsABadMCPSection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, mcp string }{
		{"unknown key", "token: abc"},
		{"negative", "max_queue: -1"},
		{"negative cache", "max_cache: -5"},
		{"negative audit size", "audit_max_mb: -1"},
		{"negative audit keep", "audit_keep: -1"},
		{"bad wait", "max_wait: soon"},
		{"zero timeout", "call_timeout: 0s"},
		{"no port", "listen: 127.0.0.1"},
		{"port range", "listen: 127.0.0.1:70000"},
		{"bare ipv6", "listen: ::1:8765"},
		{"empty host", "allowed_hosts: ['']"},
		{"host with path", "allowed_hosts: [a.example/x]"},
		{"host with a port", "allowed_hosts: ['proteus.example.org:443']"},
		{"bracketed ipv6", "allowed_hosts: ['[::1]']"},
		{"header with a space", "identity_header: 'X User'"},
		{"header with a colon", "identity_header: 'X-User:'"},
		{"empty claim", "audit_claims: [sub, '']"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := "version: 1\ndevices: []\nmcp:\n  " + tc.mcp + "\n"
			if _, err := Parse(strings.NewReader(doc)); err == nil || !strings.HasPrefix(err.Error(), "inventory: ") {
				t.Errorf("%q: %v", tc.mcp, err)
			}
		})
	}
	if _, err := Parse(strings.NewReader("version: 1\ndevices: []\nmcp: {identity_header: X-User-Claims, audit_claims: [sub, email]}\n")); err != nil {
		t.Errorf("a valid header and claims: %v", err)
	}
	if _, err := Parse(strings.NewReader("version: 1\ndevices: []\nmcp: {allowed_hosts: [proteus.example.org, '::1', 198.18.0.1]}\n")); err != nil {
		t.Errorf("valid hosts: %v", err)
	}
	for _, listen := range []string{":8765", "0.0.0.0:8765", "[::1]:8765", "proteus.example.org:443"} {
		if _, err := Parse(strings.NewReader("version: 1\ndevices: []\nmcp: {listen: '" + listen + "'}\n")); err != nil {
			t.Errorf("listen %s: %v", listen, err)
		}
	}
}

// The export keeps everything but the credentials and leaves the inventory
// as it was.
func TestExportDropsCredentials(t *testing.T) {
	t.Parallel()
	inv, err := Parse(strings.NewReader(withMCP))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := WriteExport(root, inv); err != nil {
		t.Fatal(err)
	}
	path := ExportPath(root)
	if path != filepath.Join(root, ".proteus", "inventory.yaml") {
		t.Errorf("path = %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"secret-", "username", "password", "reader", "other", "LAB_PASSWORD"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("the export holds %q:\n%s", bad, b)
		}
	}
	if !strings.HasPrefix(string(b), "# Written by proteus fetch") {
		t.Errorf("header:\n%s", b)
	}
	if inv.Defaults.Password != "secret-default" || inv.Devices[1].Username != "other" {
		t.Error("Export must not change the inventory")
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]os.FileMode{true: 0o700, false: 0o600}[fi.IsDir()]; fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	got, err := ReadExport(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Defaults.Store != "" || got.Defaults.LogDir != "" {
		t.Errorf("the server sets store and log_dir itself: %+v", got.Defaults)
	}
	if !slices.Equal(got.Names(), []string{"fw01", "fw02"}) || got.Devices[0].Labels["site"] != "vienna" ||
		got.Devices[1].HAPeer != "fw02-b.example.net" || got.MCP == nil || got.MCP.LogDir != "/var/log/proteus/mcp" ||
		got.MCP.MaxCache != 2048 || !got.Defaults.ExportInventory {
		t.Errorf("read back = %+v, mcp %+v", got, got.MCP)
	}
	// A second run replaces the export in place.
	inv.Devices = inv.Devices[:1]
	if err := WriteExport(root, inv); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadExport(path); err != nil || !slices.Equal(got.Names(), []string{"fw01"}) {
		t.Errorf("rewritten = %+v, %v", got, err)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Errorf("left behind: %v", entries)
	}
}

// A write that fails leaves the old export, or none, and no temporary file.
func TestAFailedExportLeavesNoPartialFile(t *testing.T) {
	t.Parallel()
	inv, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// A directory where the export goes makes the rename fail.
	if err := os.MkdirAll(filepath.Join(ExportPath(root), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteExport(root, inv); err == nil {
		t.Fatal("want an error")
	}
	entries, err := os.ReadDir(filepath.Join(root, ExportDir))
	if err != nil || len(entries) != 1 || entries[0].Name() != "inventory.yaml" || !entries[0].IsDir() {
		t.Errorf("left behind: %v, %v", entries, err)
	}
	// A directory it cannot write to holds no temporary file.
	locked := t.TempDir()
	if err := os.Mkdir(filepath.Join(locked, ExportDir), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := WriteExport(locked, inv); err == nil {
		t.Error("want an error for a directory without write permission")
	}
	// A store root that is a file cannot hold the directory.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteExport(file, inv); err == nil {
		t.Error("want an error for a store root that is a file")
	}
}

// The server refuses an export that holds any credential, wherever it is.
func TestReadExportRefusesCredentials(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, tc := range []struct{ name, doc, want string }{
		{"defaults username", "version: 1\ndefaults: {username: admin}\ndevices: []\n", "defaults: username"},
		{"defaults password env", "version: 1\ndefaults: {password_env: X}\ndevices: []\n", "defaults: password_env"},
		{"device password", "version: 1\ndevices:\n  - {name: fw01, host: h, password: p}\n", "device fw01: password"},
		{"device username", "version: 1\ndevices:\n  - {name: fw01, host: h, username: u}\n", "device fw01: username"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".yaml")
			if err := os.WriteFile(path, []byte(tc.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := ReadExport(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "secret") {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := ReadExport(filepath.Join(dir, "absent.yaml")); err == nil {
		t.Error("an absent export is an error")
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 1\nhost: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadExport(bad); err == nil {
		t.Error("an unknown key is an error")
	}
}

// .proteus cannot be a device's directory: a device name needs a leading letter
// or digit.
func TestTheExportDirectoryIsNoDeviceName(t *testing.T) {
	t.Parallel()
	if ValidName(ExportDir) {
		t.Errorf("%s must not be a valid device name", ExportDir)
	}
	if _, err := Parse(strings.NewReader("version: 1\ndevices:\n  - {name: .proteus, host: h}\n")); err == nil {
		t.Error("an inventory must not name a device .proteus")
	}
}

// Every key of the defaults and of a device is classified: a credential the
// export drops, or a setting it keeps. A new key fails here until it is
// added to one list, so a new secret cannot reach the export unseen.
func TestEveryExportKeyIsClassified(t *testing.T) {
	t.Parallel()
	credentials := []string{"username", "password", "password_env"}
	kept := map[reflect.Type][]string{
		reflect.TypeFor[Settings](): {
			"insecure_tls", "timeout", "snapshot_keep", "store", "max_snapshot_age", "output",
			"log_level", "log_dir", "log_keep", "color", "export_inventory",
		},
		reflect.TypeFor[Device](): {"name", "host", "insecure_tls", "timeout", "labels", "ha_peer"},
	}
	for ty, keep := range kept {
		for _, f := range reflect.VisibleFields(ty) {
			key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if !slices.Contains(credentials, key) && !slices.Contains(keep, key) {
				t.Errorf("%s: yaml key %q is not classified as a credential or a kept setting", ty.Name(), key)
			}
		}
	}
}

// syncDir fails on a directory that is not there.
func TestSyncDirFails(t *testing.T) {
	t.Parallel()
	if err := syncDir(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("syncDir of an absent directory")
	}
}

// WriteTemplate fails where its directory cannot be made.
func TestWriteTemplateNeedsADirectory(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteTemplate(filepath.Join(file, "proteus", "config.yaml")); err == nil {
		t.Error("WriteTemplate below a file")
	}
}
