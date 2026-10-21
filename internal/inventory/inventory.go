// Package inventory reads the firewalls proteus works with: where each one is,
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
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
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
	// MCP configures proteus mcp. It is written here, in the fetch side's
	// inventory, and reaches the server through the export (spec 2026-10-09
	// §4.2, §5). Nil when the file has no mcp: section.
	MCP *MCP `yaml:"mcp,omitempty"`
}

// MCP is the mcp: section. Each value can also come from a PROTEUS_MCP_*
// variable or a flag, which win over the file; zero leaves the default. The
// token itself is never in the inventory: TokenFile names the file that holds
// it.
type MCP struct {
	Listen         string   `yaml:"listen,omitempty"`          // host:port for --http
	TokenFile      string   `yaml:"token_file,omitempty"`      // the file that holds the bearer token
	AllowedHosts   []string `yaml:"allowed_hosts,omitempty"`   // Host header values --http accepts
	IdentityHeader string   `yaml:"identity_header,omitempty"` // the header with the caller's claims
	AuditClaims    []string `yaml:"audit_claims,omitempty"`    // the claims the audit line records
	AuditLog       string   `yaml:"audit_log,omitempty"`       // the audit file, one JSON line per call; - for standard output
	AuditMaxMB     int      `yaml:"audit_max_mb,omitempty"`    // the audit file's size before it rotates, in MB
	AuditKeep      int      `yaml:"audit_keep,omitempty"`      // rotated audit files kept
	LogDir         string   `yaml:"log_dir,omitempty"`         // run logs of the calls, apart from the CLI's
	LogKeep        int      `yaml:"log_keep,omitempty"`        // run logs kept
	MaxConcurrent  int      `yaml:"max_concurrent,omitempty"`  // calls answered at once
	MaxQueue       int      `yaml:"max_queue,omitempty"`       // calls waiting for a slot
	MaxWait        string   `yaml:"max_wait,omitempty"`        // how long a call waits for a slot, e.g. 10s
	CallTimeout    string   `yaml:"call_timeout,omitempty"`    // how long a call may run, e.g. 60s
	MaxLoads       int      `yaml:"max_loads,omitempty"`       // snapshot loads at once
	MaxCache       int      `yaml:"max_cache,omitempty"`       // cache size in MB
}

// Settings are the values a device takes unless it sets its own.
type Settings struct {
	InsecureTLS  *bool  `yaml:"insecure_tls,omitempty"`
	Timeout      int    `yaml:"timeout,omitempty"` // seconds
	SnapshotKeep int    `yaml:"snapshot_keep,omitempty"`
	Username     string `yaml:"username,omitempty"`
	PasswordEnv  string `yaml:"password_env,omitempty"`
	Password     string `yaml:"password,omitempty"`

	// The analysis settings of spec §15 C14. Each can also come from a PROTEUS_*
	// variable or a flag, which win over the file.
	Store          string `yaml:"store,omitempty"`            // snapshot store root
	MaxSnapshotAge string `yaml:"max_snapshot_age,omitempty"` // e.g. 24h or 7d
	Output         string `yaml:"output,omitempty"`           // text or json
	LogLevel       string `yaml:"log_level,omitempty"`        // error, warn, info or debug
	LogDir         string `yaml:"log_dir,omitempty"`          // where run logs go
	LogKeep        int    `yaml:"log_keep,omitempty"`         // run logs kept
	Color          string `yaml:"color,omitempty"`            // auto, always or never

	// ExportInventory makes fetch write the inventory without credentials to
	// <store>/.proteus/inventory.yaml after every run, for proteus mcp.
	ExportInventory bool `yaml:"export_inventory,omitempty"`
}

// Device is one firewall.
type Device struct {
	Name        string            `yaml:"name,omitempty"`
	Host        string            `yaml:"host,omitempty"`
	Username    string            `yaml:"username,omitempty"`
	PasswordEnv string            `yaml:"password_env,omitempty"`
	Password    string            `yaml:"password,omitempty"`
	InsecureTLS *bool             `yaml:"insecure_tls,omitempty"`
	Timeout     int               `yaml:"timeout,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	// HAPeer is the reachable host of the device's HA peer, for when the address
	// the device reports is not reachable from here.
	HAPeer string `yaml:"ha_peer,omitempty"`
	// Identity set to false turns off the fetch of the device's User-ID data
	// (spec 2026-10-17 D4). Without the key, the data is fetched.
	Identity *bool `yaml:"identity,omitempty"`
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
	HAPeer       string
	Identity     bool // fetch the User-ID data: true unless the device sets identity: false
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
	if inv.Defaults.LogKeep < 0 {
		return errors.New("inventory: defaults: log_keep must not be negative")
	}
	if err := inv.MCP.Validate(); err != nil {
		return fmt.Errorf("inventory: %w", err)
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

// Validate checks the mcp: values that a typo could turn into a default, or
// that the server could not use. A nil section is valid. proteus mcp checks
// the values from every source with it, not only the file's.
func (m *MCP) Validate() error {
	if m == nil {
		return nil
	}
	for _, n := range []struct {
		key string
		v   int
	}{
		{"audit_max_mb", m.AuditMaxMB},
		{"audit_keep", m.AuditKeep},
		{"log_keep", m.LogKeep},
		{"max_concurrent", m.MaxConcurrent},
		{"max_queue", m.MaxQueue},
		{"max_loads", m.MaxLoads},
		{"max_cache", m.MaxCache},
	} {
		if n.v < 0 {
			return fmt.Errorf("mcp: %s must not be negative", n.key)
		}
	}
	for _, d := range []struct{ key, v string }{{"max_wait", m.MaxWait}, {"call_timeout", m.CallTimeout}} {
		if d.v == "" {
			continue
		}
		if v, err := time.ParseDuration(d.v); err != nil || v <= 0 {
			return fmt.Errorf("mcp: %s %q: want a duration like 10s", d.key, d.v)
		}
	}
	if m.Listen != "" {
		host, port, err := net.SplitHostPort(m.Listen)
		if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 || strings.ContainsAny(host, " /") {
			return fmt.Errorf("mcp: listen %q: want host:port, such as 127.0.0.1:8765", m.Listen)
		}
	}
	for _, h := range m.AllowedHosts {
		if h == "" || strings.ContainsAny(h, " /") {
			return fmt.Errorf("mcp: allowed_hosts: %q is not a host name", h)
		}
		// The server compares the Host without its port and brackets, so an
		// entry with them never matches. A colon is fine in an IPv6 address.
		if _, err := netip.ParseAddr(h); strings.ContainsAny(h, "[]") || strings.Contains(h, ":") && err != nil {
			return fmt.Errorf("mcp: allowed_hosts: %q: give the host without a port or brackets", h)
		}
	}
	if m.IdentityHeader != "" && !headerName.MatchString(m.IdentityHeader) {
		return fmt.Errorf("mcp: identity_header %q is not an HTTP header name", m.IdentityHeader)
	}
	if slices.Contains(m.AuditClaims, "") {
		return errors.New("mcp: audit_claims: an entry is empty")
	}
	return nil
}

// headerName is an HTTP field name: one or more token characters (RFC 9110
// §5.1, §5.6.2).
var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// Names returns the device names in file order.
func (inv *Inventory) Names() []string {
	out := make([]string, len(inv.Devices))
	for i, d := range inv.Devices {
		out[i] = d.Name
	}
	return out
}

// Select returns the names of the devices a selection names, in file order.
//
// A device is selected when its name is among devices (if any are given) and it
// carries every key=value in labels (if any are given). No selector selects every
// device. Spec §15 C7.
func (inv *Inventory) Select(devices, labels []string) ([]string, error) {
	want := map[string]bool{}
	for _, d := range devices {
		if !inv.has(d) {
			return nil, fmt.Errorf("inventory: no device named %q; the inventory has %v", d, inv.Names())
		}
		want[d] = true
	}
	need := map[string]string{}
	for _, l := range labels {
		k, v, ok := strings.Cut(l, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("inventory: label %q must be key=value", l)
		}
		need[k] = v
	}
	var out []string
	for _, d := range inv.Devices {
		if len(want) > 0 && !want[d.Name] {
			continue
		}
		match := true
		for k, v := range need {
			if d.Labels[k] != v {
				match = false
			}
		}
		if match {
			out = append(out, d.Name)
		}
	}
	return out, nil
}

func (inv *Inventory) has(name string) bool {
	for _, d := range inv.Devices {
		if d.Name == name {
			return true
		}
	}
	return false
}

// ParseAge reads a snapshot age limit: a Go duration such as 90m or 24h, or a whole
// number of days such as 7d.
func ParseAge(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 {
			return 0, fmt.Errorf("age %q: want a duration like 24h or a day count like 7d", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("age %q: want a duration like 24h or a day count like 7d", s)
	}
	return d, nil
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
		HAPeer:       d.HAPeer,
		Identity:     d.Identity == nil || *d.Identity,
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

// DefaultPath returns where the inventory is read from: PROTEUS_CONFIG, else
// $XDG_CONFIG_HOME/proteus/config.yaml, else ~/.config/proteus/config.yaml.
func DefaultPath(getenv func(string) string) (string, error) {
	if p := getenv("PROTEUS_CONFIG"); p != "" {
		return p, nil
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "proteus", "config.yaml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("inventory: no home directory: %w", err)
	}
	return filepath.Join(home, ".config", "proteus", "config.yaml"), nil
}
