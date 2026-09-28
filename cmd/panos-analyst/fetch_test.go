package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/config"
	"github.com/okaiser/panos-analyst/fetch"
	"github.com/okaiser/panos-analyst/index"
	"github.com/okaiser/panos-analyst/internal/fakepanos"
	"github.com/okaiser/panos-analyst/inventory"
	"github.com/okaiser/panos-analyst/store"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func lab(t *testing.T) *fakepanos.Device {
	t.Helper()
	return &fakepanos.Device{
		User: "reader", Password: "not-a-real-password", Key: "not-a-real-key",
		Config: read(t, "../../testdata/config/firewall-lab.xml"),
		Ops: map[string]string{
			"<show><system><info/></system></show>":   read(t, "../../testdata/opdata/fw01-system-info.xml"),
			"<show><interface>all</interface></show>": read(t, "../../testdata/opdata/fw01-interface-all.xml"),
			"<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>": read(t,
				"../../testdata/opdata/fw01-advanced-routing-fib.xml"),
		},
	}
}

func inventoryFor(host string) string {
	return "version: 1\ndefaults:\n  insecure_tls: true\n  username: reader\n  password_env: LAB_PW\n" +
		"devices:\n  - name: fw01\n    host: " + host + "\n"
}

func setup(t *testing.T, host string) (*inventory.Inventory, *store.Store) {
	t.Helper()
	inv, err := inventory.Parse(strings.NewReader(inventoryFor(host)))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return inv, st
}

func getenv(k string) string {
	if k == "LAB_PW" {
		return "not-a-real-password"
	}
	return ""
}

// M2's exit criterion (spec S15): an inventory with one device, fetched into the
// store, and a lookup answered from latest.
func TestFetchThenAnswerFromLatest(t *testing.T) {
	inv, st := setup(t, lab(t).Start(t))
	var out bytes.Buffer
	if err := fetchDevices(context.Background(), &out, inv, st, []string{"fw01"}, getenv); err != nil {
		t.Fatalf("fetch: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "TLS certificate verification OFF") {
		t.Errorf("the run must say that verification is off:\n%s", out.String())
	}

	sn, err := st.Resolve("fw01")
	if err != nil {
		t.Fatal(err)
	}
	if sn.Meta.Serial != "007900000000001" || sn.Meta.SWVersion != "11.2.5" {
		t.Errorf("meta = %+v", sn.Meta)
	}
	cfg, _, err := config.Load(sn.Path(store.ConfigDoc))
	if err != nil {
		t.Fatal(err)
	}
	idx, err := index.For(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"})
	if err != nil {
		t.Fatal(err)
	}
	cand, _ := idx.Candidates(index.Source, "198.18.10.100")
	if cand.IsEmpty() {
		t.Error("dc01 is in g-servers, which dc-to-home names; the stored config must answer")
	}
	zones, err := sn.Zones()
	if err != nil {
		t.Fatalf("zones from the store: %v", err)
	}
	if len(zones.Routers()) == 0 {
		t.Error("the stored forwarding table names no router")
	}
}

// Spec S10: a failed document is reported, and the command fails at the end.
func TestFetchReportsAFailedDocument(t *testing.T) {
	d := lab(t)
	delete(d.Ops, "<show><interface>all</interface></show>")
	inv, st := setup(t, d.Start(t))
	var out bytes.Buffer
	err := fetchDevices(context.Background(), &out, inv, st, []string{"fw01"}, getenv)
	if err == nil {
		t.Error("a missing document must make the command fail")
	}
	if !strings.Contains(out.String(), "interfaces") || !strings.Contains(out.String(), "FAILED") {
		t.Errorf("the failed document must be named:\n%s", out.String())
	}
	if _, err := st.Latest("fw01"); err != nil {
		t.Error("the configuration arrived, so latest must still move")
	}
}

// Spec S10: a device that cannot be reached does not stop the next one.
func TestFetchContinuesPastAFailedDevice(t *testing.T) {
	inv, st := setup(t, lab(t).Start(t))
	var out bytes.Buffer
	err := fetchDevices(context.Background(), &out, inv, st, []string{"nope", "fw01"}, getenv)
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("the unknown device must be reported, got %v", err)
	}
	if _, err := st.Latest("fw01"); err != nil {
		t.Error("fw01 must still be fetched after the failure")
	}
}

func TestVerificationOnIsSaid(t *testing.T) {
	inv, err := inventory.Parse(strings.NewReader(strings.Replace(inventoryFor(lab(t).Start(t)),
		"insecure_tls: true", "insecure_tls: false", 1)))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open(t.TempDir())
	var out bytes.Buffer
	_ = fetchDevices(context.Background(), &out, inv, st, []string{"fw01"}, getenv)
	if !strings.Contains(out.String(), "TLS certificate verification on") {
		t.Errorf("the run must say verification is on:\n%s", out.String())
	}
}

// Decision 9: store names the documents it reads; they must be fetch's names.
func TestStoreAndFetchAgreeOnDocumentNames(t *testing.T) {
	for got, want := range map[string]string{
		store.ConfigDoc:     fetch.RunningConfig.Name,
		store.InterfacesDoc: fetch.Interfaces.Name,
		store.FIBDoc:        fetch.RoutingFIB.Name,
	} {
		if got != want {
			t.Errorf("store says %q, fetch says %q", got, want)
		}
	}
}

// The commands end to end, through cobra, against the fake device.
func TestCommands(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	storeRoot := filepath.Join(dir, "store")
	t.Setenv("LAB_PW", "not-a-real-password")

	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		cmd := root()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(append(args, "--config", cfgPath, "--store", storeRoot))
		err := cmd.ExecuteContext(context.Background())
		return out.String(), err
	}

	if out, err := run("init"); err != nil || !strings.Contains(out, "wrote") {
		t.Fatalf("init: %v\n%s", err, out)
	}
	if _, err := run("init"); err == nil {
		t.Error("init must not overwrite an inventory")
	}
	if err := os.WriteFile(cfgPath, []byte(inventoryFor(lab(t).Start(t))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run("fetch"); err == nil {
		t.Error("fetch with no device and no --all must fail")
	}
	if _, err := run("fetch", "fw01", "--all"); err == nil {
		t.Error("fetch with a device and --all must fail")
	}
	if out, err := run("fetch", "--all"); err != nil || !strings.Contains(out, "stored fw01@") {
		t.Fatalf("fetch --all: %v\n%s", err, out)
	}
	out, err := run("snapshots", "fw01")
	if err != nil || !strings.HasPrefix(out, "* ") || !strings.Contains(out, "4 documents, 0 failed") {
		t.Errorf("snapshots: %v\n%s", err, out)
	}
}
