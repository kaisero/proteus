package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const sample = `version: 1
defaults:
  insecure_tls: true
  timeout: 30
  snapshot_keep: 5
  username: reader
  password_env: LAB_PASSWORD
devices:
  - name: fw01
    host: 192.0.2.10
    labels: {site: vienna}
  - name: fw02
    host: fw02.example.net
    username: other
    password_env: FW02_PASSWORD
    insecure_tls: false
    timeout: 90
    ha_peer: fw02-b.example.net
`

func TestResolveAppliesDefaults(t *testing.T) {
	inv, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	got, err := inv.Resolve("fw01", env(map[string]string{"LAB_PASSWORD": "secret-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "fw01" || got.Host != "192.0.2.10" || got.Username != "reader" ||
		got.Password != "secret-1" || !got.InsecureTLS || got.Timeout != 30*time.Second ||
		got.SnapshotKeep != 5 || got.Labels["site"] != "vienna" {
		t.Errorf("Resolve(fw01) = %+v", got)
	}
}

func TestADeviceOverridesTheDefaults(t *testing.T) {
	inv, _ := Parse(strings.NewReader(sample))
	got, err := inv.Resolve("fw02", env(map[string]string{"FW02_PASSWORD": "secret-2"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "other" || got.Password != "secret-2" || got.InsecureTLS || got.Timeout != 90*time.Second ||
		got.HAPeer != "fw02-b.example.net" {
		t.Errorf("fw02 = %+v", got)
	}
}

// With nothing said, TLS verification is off (spec S8), a call waits 60 s and 20
// snapshots are kept.
func TestBuiltInDefaults(t *testing.T) {
	inv, err := Parse(strings.NewReader("version: 1\ndevices:\n  - name: a\n    host: h\n    username: u\n    password: p\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := inv.Resolve("a", env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !got.InsecureTLS || got.Timeout != 60*time.Second || got.SnapshotKeep != 20 || got.Password != "p" {
		t.Errorf("defaults = %+v", got)
	}
}

// One account for every device: a literal password under defaults.
func TestADefaultLiteralPassword(t *testing.T) {
	inv, err := Parse(strings.NewReader("version: 1\ndefaults: {username: u, password: shared}\ndevices:\n  - {name: a, host: h}\n"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := inv.Resolve("a", env(nil))
	if err != nil || got.Password != "shared" {
		t.Errorf("got %+v, %v", got, err)
	}
}

func TestResolveNeedsCredentials(t *testing.T) {
	inv, _ := Parse(strings.NewReader(sample))
	_, err := inv.Resolve("fw01", env(nil))
	if err == nil || !strings.Contains(err.Error(), "LAB_PASSWORD") {
		t.Errorf("want an error naming the empty variable, got %v", err)
	}
	if _, err := inv.Resolve("nope", env(nil)); err == nil {
		t.Error("an unknown device must be an error")
	}
	bare, _ := Parse(strings.NewReader("version: 1\ndevices:\n  - {name: a, host: h}\n"))
	if _, err := bare.Resolve("a", env(nil)); err == nil || !strings.Contains(err.Error(), "username") {
		t.Errorf("want a missing-username error, got %v", err)
	}
	userOnly, _ := Parse(strings.NewReader("version: 1\ndevices:\n  - {name: a, host: h, username: u}\n"))
	if _, err := userOnly.Resolve("a", env(nil)); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("want a missing-password error, got %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"wrong version":    "version: 2\ndevices: []\n",
		"unknown field":    "version: 1\ndevices:\n  - name: a\n    host: h\n    hots: typo\n",
		"no host":          "version: 1\ndevices:\n  - name: a\n",
		"duplicate name":   "version: 1\ndevices:\n  - {name: a, host: h}\n  - {name: a, host: i}\n",
		"unsafe name":      "version: 1\ndevices:\n  - {name: ../x, host: h}\n",
		"negative keep":    "version: 1\ndefaults: {snapshot_keep: -1}\ndevices: []\n",
		"negative timeout": "version: 1\ndevices:\n  - {name: a, host: h, timeout: -1}\n",
		"not yaml":         "version: [\n",
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestNamesAreInFileOrder(t *testing.T) {
	inv, _ := Parse(strings.NewReader(sample))
	if got := strings.Join(inv.Names(), ","); got != "fw01,fw02" {
		t.Errorf("Names = %s", got)
	}
}

// The file holds credentials, so it must be private to its owner.
func TestLoadRefusesAReadableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Errorf("want a permissions error, got %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a 0600 file must load: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("a missing file must be an error")
	}
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("version: 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("a bad file's error must name it, got %v", err)
	}
}

// The template is a working inventory, and it states the TLS choice explicitly.
func TestTemplateParsesAndShowsTheTLSChoice(t *testing.T) {
	inv, err := Parse(strings.NewReader(Template))
	if err != nil {
		t.Fatalf("the template does not parse: %v", err)
	}
	if inv.Defaults.InsecureTLS == nil || !*inv.Defaults.InsecureTLS {
		t.Error("the template must set insecure_tls: true explicitly")
	}
	if !strings.Contains(Template, "insecure_tls: false") {
		t.Error("the template must say how to opt in to verification")
	}
	if _, err := inv.Resolve(inv.Names()[0], env(map[string]string{"PANOS_PASSWORD": "x"})); err != nil {
		t.Errorf("the template's device does not resolve: %v", err)
	}
}

func TestWriteTemplate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.yaml")
	if err := WriteTemplate(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	if _, err := Load(path); err != nil {
		t.Errorf("the written template must load: %v", err)
	}
	if err := WriteTemplate(path); err == nil {
		t.Error("an existing inventory must never be overwritten")
	}
}

func TestDefaultPath(t *testing.T) {
	if got, _ := DefaultPath(env(map[string]string{"PROTEUS_CONFIG": "/x/y.yaml"})); got != "/x/y.yaml" {
		t.Errorf("PROTEUS_CONFIG ignored: %s", got)
	}
	if got, _ := DefaultPath(env(map[string]string{"XDG_CONFIG_HOME": "/cfg"})); got != "/cfg/proteus/config.yaml" {
		t.Errorf("XDG_CONFIG_HOME ignored: %s", got)
	}
	got, err := DefaultPath(env(nil))
	if err != nil || !strings.HasSuffix(got, filepath.Join(".config", "proteus", "config.yaml")) {
		t.Errorf("home default = %s, %v", got, err)
	}
}

func TestSelect(t *testing.T) {
	inv, err := Parse(strings.NewReader(`version: 1
devices:
  - {name: a, host: h, labels: {site: vienna, tier: edge}}
  - {name: b, host: h, labels: {site: vienna, tier: core}}
  - {name: c, host: h, labels: {site: graz, tier: edge}}
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		devices, labels []string
		want            string
	}{
		{nil, nil, "a,b,c"},
		{[]string{"c", "a"}, nil, "a,c"},
		{nil, []string{"site=vienna"}, "a,b"},
		{nil, []string{"site=vienna", "tier=edge"}, "a"},
		{[]string{"b", "c"}, []string{"tier=edge"}, "c"},
		{nil, []string{"site=linz"}, ""},
	} {
		got, err := inv.Select(tc.devices, tc.labels)
		if err != nil || strings.Join(got, ",") != tc.want {
			t.Errorf("Select(%v, %v) = %v, %v; want %s", tc.devices, tc.labels, got, err, tc.want)
		}
	}
	if _, err := inv.Select([]string{"nope"}, nil); err == nil {
		t.Error("an unknown device must be an error")
	}
	if _, err := inv.Select(nil, []string{"site"}); err == nil {
		t.Error("a label without = must be an error")
	}
}

func TestParseAge(t *testing.T) {
	for in, want := range map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "0": 0, "90m": 90 * time.Minute} {
		if got, err := ParseAge(in); err != nil || got != want {
			t.Errorf("ParseAge(%s) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"x", "-1h", "xd", "-2d"} {
		if _, err := ParseAge(bad); err == nil {
			t.Errorf("ParseAge(%s) must fail", bad)
		}
	}
}

func TestAnalysisSettingsAreValidated(t *testing.T) {
	for _, doc := range []string{
		"version: 1\ndefaults: {max_snapshot_age: soon}\ndevices: []\n",
		"version: 1\ndefaults: {output: yaml}\ndevices: []\n",
		"version: 1\ndefaults: {log_level: trace}\ndevices: []\n",
		"version: 1\ndefaults: {log_keep: -1}\ndevices: []\n",
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("want an error for %q", doc)
		}
	}
	inv, err := Parse(strings.NewReader("version: 1\ndefaults: {max_snapshot_age: 7d, output: json, store: /s}\ndevices: []\n"))
	if err != nil || inv.Defaults.Output != "json" || inv.Defaults.Store != "/s" {
		t.Errorf("got %+v, %v", inv, err)
	}
}
