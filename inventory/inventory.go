// Package inventory reads the firewalls panos-analyst works with: where each one is,
// how to log in to it, and whether to verify its TLS certificate.
//
// The file is YAML and holds credentials or the names of the variables that do, so
// Load refuses one that anyone but its owner can read. Spec:
// docs/specs/2026-09-27-panos-analyst-scope.md §6.
package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// FormatVersion is the inventory format this build reads.
const FormatVersion = 1

// The values a setting takes when neither the device nor the defaults set it.
const (
	DefaultInsecureTLS  = true // spec S8: lab devices present self-signed certificates
	DefaultTimeout      = 60 * time.Second
	DefaultSnapshotKeep = 20
)

// Inventory is the file as written.
type Inventory struct {
	Version  int      `yaml:"version"`
	Defaults Settings `yaml:"defaults"`
	Devices  []Device `yaml:"devices"`
}

// Settings are the values a device takes unless it sets its own.
type Settings struct {
	InsecureTLS  *bool  `yaml:"insecure_tls"`
	Timeout      int    `yaml:"timeout"` // seconds
	SnapshotKeep int    `yaml:"snapshot_keep"`
	Username     string `yaml:"username"`
	PasswordEnv  string `yaml:"password_env"`
	Password     string `yaml:"password"`
}

// Device is one firewall.
type Device struct {
	Name        string            `yaml:"name"`
	Host        string            `yaml:"host"`
	Username    string            `yaml:"username"`
	PasswordEnv string            `yaml:"password_env"`
	Password    string            `yaml:"password"`
	InsecureTLS *bool             `yaml:"insecure_tls"`
	Timeout     int               `yaml:"timeout"`
	Labels      map[string]string `yaml:"labels"`
}

// Target is one device with every default applied and its password read.
type Target struct {
	Name         string
	Host         string
	Username     string
	Password     string
	InsecureTLS  bool
	Timeout      time.Duration
	SnapshotKeep int
	Labels       map[string]string
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ValidName reports whether a device name is safe to use as a directory name.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// Load reads an inventory file. It refuses a file that its group or others can read,
// because the file holds credentials or points at them.
func Load(path string) (*Inventory, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("inventory: %s is mode %v; it holds credentials, so make it 0600 (chmod 600 %s)",
			path, fi.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	inv, err := Parse(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return inv, nil
}

// Parse reads an inventory. An unknown key is an error, so a typo cannot silently
// leave a setting at its default.
func Parse(r io.Reader) (*Inventory, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var inv Inventory
	if err := dec.Decode(&inv); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	if err := inv.validate(); err != nil {
		return nil, err
	}
	return &inv, nil
}

func (inv *Inventory) validate() error {
	if inv.Version != FormatVersion {
		return fmt.Errorf("inventory: version %d, this build reads version %d", inv.Version, FormatVersion)
	}
	if inv.Defaults.Timeout < 0 || inv.Defaults.SnapshotKeep < 0 {
		return errors.New("inventory: defaults: timeout and snapshot_keep must not be negative")
	}
	seen := map[string]bool{}
	for i, d := range inv.Devices {
		switch {
		case !ValidName(d.Name):
			return fmt.Errorf("inventory: device %d: name %q must be letters, digits, '.', '_' or '-'", i+1, d.Name)
		case seen[d.Name]:
			return fmt.Errorf("inventory: device %q appears twice", d.Name)
		case d.Host == "":
			return fmt.Errorf("inventory: device %q has no host", d.Name)
		case d.Timeout < 0:
			return fmt.Errorf("inventory: device %q: timeout must not be negative", d.Name)
		}
		seen[d.Name] = true
	}
	return nil
}

// Names returns the device names in file order.
func (inv *Inventory) Names() []string {
	out := make([]string, len(inv.Devices))
	for i, d := range inv.Devices {
		out[i] = d.Name
	}
	return out
}

// Resolve returns one device with the defaults applied and its password read.
// getenv is os.Getenv outside tests.
func (inv *Inventory) Resolve(name string, getenv func(string) string) (Target, error) {
	for _, d := range inv.Devices {
		if d.Name == name {
			return inv.resolve(d, getenv)
		}
	}
	return Target{}, fmt.Errorf("inventory: no device named %q; the inventory has %v", name, inv.Names())
}

func (inv *Inventory) resolve(d Device, getenv func(string) string) (Target, error) {
	def := inv.Defaults
	t := Target{
		Name:         d.Name,
		Host:         d.Host,
		Username:     d.Username,
		InsecureTLS:  DefaultInsecureTLS,
		Timeout:      DefaultTimeout,
		SnapshotKeep: DefaultSnapshotKeep,
		Labels:       d.Labels,
	}
	if t.Username == "" {
		t.Username = def.Username
	}
	switch {
	case d.InsecureTLS != nil:
		t.InsecureTLS = *d.InsecureTLS
	case def.InsecureTLS != nil:
		t.InsecureTLS = *def.InsecureTLS
	}
	switch {
	case d.Timeout > 0:
		t.Timeout = time.Duration(d.Timeout) * time.Second
	case def.Timeout > 0:
		t.Timeout = time.Duration(def.Timeout) * time.Second
	}
	if def.SnapshotKeep > 0 {
		t.SnapshotKeep = def.SnapshotKeep
	}
	if t.Username == "" {
		return Target{}, fmt.Errorf("inventory: device %q has no username; set username on it or under defaults", d.Name)
	}
	pw, err := password(d, def, getenv)
	if err != nil {
		return Target{}, err
	}
	t.Password = pw
	return t, nil
}

// password reads a device's password, most specific first: the device's literal,
// the device's variable, the defaults' literal, the defaults' variable.
func password(d Device, def Settings, getenv func(string) string) (string, error) {
	for _, src := range []struct{ literal, env string }{
		{d.Password, d.PasswordEnv},
		{def.Password, def.PasswordEnv},
	} {
		if src.literal != "" {
			return src.literal, nil
		}
		if src.env == "" {
			continue
		}
		if v := getenv(src.env); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("inventory: device %q reads its password from %s, which is empty", d.Name, src.env)
	}
	return "", fmt.Errorf("inventory: device %q has no password; set password_env on it or under defaults", d.Name)
}

// DefaultPath returns where the inventory is read from: PANOS_CONFIG, else
// $XDG_CONFIG_HOME/panos-analyst/config.yaml, else ~/.config/panos-analyst/config.yaml.
func DefaultPath(getenv func(string) string) (string, error) {
	if p := getenv("PANOS_CONFIG"); p != "" {
		return p, nil
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "panos-analyst", "config.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("inventory: no home directory: %w", err)
	}
	return filepath.Join(home, ".config", "panos-analyst", "config.yaml"), nil
}
