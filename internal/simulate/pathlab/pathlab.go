// Package pathlab is the path fixture for tests: the lab's fw02 and fw01, joined
// by 198.19.0.0/24, with configurations that define the zones the operational data
// names and hold no security rule. A flow from home (198.18.1.10) to the server
// (198.18.10.100) crosses fw02 home -> labor, then fw01 transport -> server, and
// the default rules decide on each hop (spec 2026-10-07 §10.1, "Path fixture").
//
// Only tests import it. It imports what simulate/pathpolicy may import, so the
// pathpolicy tests and the command line tests share one fixture.
package pathlab

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
)

// The two devices, in inventory order, and the lab flow between them.
const (
	FW01        = "fw01"
	FW02        = "fw02"
	Source      = "198.18.1.10"
	Destination = "198.18.10.100"
)

// Devices is the inventory order of the fixture.
var Devices = []string{FW01, FW02}

// root is the repository root, found from this file, so every package's tests
// reach the same files.
func root() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..")
}

// ConfigFile is the path of a device's base configuration.
func ConfigFile(device string) string {
	return filepath.Join(root(), "testdata", "config", "path-"+device+".xml")
}

// OpdataFile is the path of an operational document under testdata/opdata, such
// as "fw02-interface-all.xml".
func OpdataFile(name string) string {
	return filepath.Join(root(), "testdata", "opdata", name)
}

// Read returns a file's content and fails the test when it cannot.
func Read(tb testing.TB, path string) []byte {
	tb.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// Defaults are the default rule entries a variant adds, each as raw <entry> XML:
// Local under the vsys rulebase, Pushed under the shared post-rulebase. The zero
// value adds none, so the built-in default rules decide.
type Defaults struct {
	Local, Pushed string
}

// Entry is a default rule entry. An empty action leaves the action out, as an
// override that changes only logging does.
func Entry(name, action string) string {
	if action == "" {
		return `<entry name="` + name + `"><log-end>yes</log-end></entry>`
	}
	return `<entry name="` + name + `"><action>` + action + `</action></entry>`
}

// Interzone is the default rule that decides on both hops of the lab flow.
const Interzone = "interzone-default"

// Variant is a named set of default rule overrides.
type Variant struct {
	Name     string
	Defaults Defaults
}

// Variants are the default rule overrides of the path fixture: local only, pushed
// only, both equal, both different, and an entry without an action. Each
// overrides interzone-default, the rule the lab flow meets.
var Variants = []Variant{
	{"local only", Defaults{Local: Entry(Interzone, "allow")}},
	{"pushed only", Defaults{Pushed: Entry(Interzone, "reset-both")}},
	{"both equal", Defaults{Local: Entry(Interzone, "allow"), Pushed: Entry(Interzone, "allow")}},
	{"both different", Defaults{Local: Entry(Interzone, "allow"), Pushed: Entry(Interzone, "deny")}},
	{"no action", Defaults{Local: Entry(Interzone, "")}},
}

// Config is a device's configuration with the overrides added.
func Config(tb testing.TB, device string, d Defaults) []byte {
	tb.Helper()
	b := Read(tb, ConfigFile(device))
	if d.Pushed != "" {
		b = replaceOnce(tb, b, "<shared/>",
			"<shared><post-rulebase><default-security-rules><rules>"+d.Pushed+"</rules></default-security-rules></post-rulebase></shared>")
	}
	if d.Local != "" {
		b = replaceOnce(tb, b, "</zone>",
			"</zone><rulebase><default-security-rules><rules>"+d.Local+"</rules></default-security-rules></rulebase>")
	}
	return b
}

func replaceOnce(tb testing.TB, b []byte, old, repl string) []byte {
	tb.Helper()
	if n := bytes.Count(b, []byte(old)); n != 1 {
		tb.Fatalf("pathlab: %q occurs %d times in the base configuration", old, n)
	}
	return bytes.Replace(b, []byte(old), []byte(repl), 1)
}

// ConfigPath writes a device's configuration with the overrides to a temporary
// file and returns its path; with no override it returns the base file.
func ConfigPath(tb testing.TB, device string, d Defaults) string {
	tb.Helper()
	if d == (Defaults{}) {
		return ConfigFile(device)
	}
	path := filepath.Join(tb.TempDir(), "path-"+device+".xml")
	if err := os.WriteFile(path, Config(tb, device, d), 0o600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// Device is a device's operational data, read from its interface list and
// forwarding table.
func Device(tb testing.TB, device string) simulate.DeviceData {
	tb.Helper()
	d := simulate.DeviceData{Name: device, Member: device}
	var err error
	if d.Interfaces, err = resolve.ReadInterfaceStates(Read(tb, OpdataFile(device+"-interface-all.xml"))); err != nil {
		tb.Fatal(err)
	}
	if d.FIB, err = resolve.ReadFIBRoutes(Read(tb, OpdataFile(device+"-advanced-routing-fib.xml"))); err != nil {
		tb.Fatal(err)
	}
	return d
}

// network is simulate.Network over fixed data.
type network map[string]simulate.DeviceData

func (network) Devices() []string { return slices.Clone(Devices) }

func (n network) Device(name string) (simulate.DeviceData, error) {
	d, ok := n[name]
	if !ok {
		return d, fmt.Errorf("no device %q in the inventory", name)
	}
	return d, nil
}

// Network is both devices' operational data.
func Network(tb testing.TB) simulate.Network {
	tb.Helper()
	n := network{}
	for _, dev := range Devices {
		n[dev] = Device(tb, dev)
	}
	return n
}

// Env is a run environment over the fixture: the network, and a loader that
// reads each device's configuration with the overrides, its index and its zones
// from the operational data.
func Env(tb testing.TB, d Defaults) *simulate.Env {
	tb.Helper()
	paths := map[string]string{}
	for _, dev := range Devices {
		paths[dev] = ConfigPath(tb, dev, d)
	}
	// One configuration and one index set per device for the env's life, as a
	// command's loader keeps them for its run.
	var mu sync.Mutex
	sets := map[string]*index.Set{}
	set := func(device string) (*index.Set, error) {
		mu.Lock()
		defer mu.Unlock()
		if s, ok := sets[device]; ok {
			return s, nil
		}
		path, ok := paths[device]
		if !ok {
			return nil, fmt.Errorf("no device %q in the inventory", device)
		}
		cfg, _, err := config.Load(path)
		if err != nil {
			return nil, err
		}
		sets[device] = index.NewSet(cfg)
		return sets[device], nil
	}
	load := func(device, vsys string) (simulate.Target, error) {
		s, err := set(device)
		if err != nil {
			return simulate.Target{}, err
		}
		sc := config.Scope{Sort: config.ScopeVsys, Name: vsys}
		if _, err := s.Index(sc, resolve.Security); err != nil {
			return simulate.Target{}, err
		}
		z, err := index.NewZoneSnapshot(time.Time{}, device,
			bytes.NewReader(Read(tb, OpdataFile(device+"-interface-all.xml"))),
			bytes.NewReader(Read(tb, OpdataFile(device+"-advanced-routing-fib.xml"))))
		if err != nil {
			return simulate.Target{}, err
		}
		return simulate.Target{Config: s.Config(), Indexes: s.Provider(sc), Providers: index.Providers{Zones: z}}, nil
	}
	return &simulate.Env{Network: Network(tb), Load: load}
}
