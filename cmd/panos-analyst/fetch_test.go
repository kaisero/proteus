package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func inventoryFor(hosts ...string) string {
	s := "version: 1\ndefaults:\n  insecure_tls: true\n  username: reader\n  password_env: LAB_PW\ndevices:\n"
	for i, h := range hosts {
		n := string(rune('1' + i))
		s += "  - name: fw0" + n + "\n    host: " + h + "\n    labels: {site: s" + n + "}\n"
	}
	return s
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
	if cand, _ := idx.Candidates(index.Source, "198.18.10.100"); cand.IsEmpty() {
		t.Error("dc01 is in g-servers, which dc-to-home names; the stored config must answer")
	}
	zones, err := sn.Zones()
	if err != nil || len(zones.Routers()) == 0 {
		t.Errorf("zones from the store: %v", err)
	}
}

// Spec §15 C11: a device stored with a missing document is a partial failure.
func TestFetchReportsAFailedDocument(t *testing.T) {
	d := lab(t)
	delete(d.Ops, "<show><interface>all</interface></show>")
	inv, st := setup(t, d.Start(t))
	var out bytes.Buffer
	err := fetchDevices(context.Background(), &out, inv, st, []string{"fw01"}, getenv)
	if !errors.Is(err, errIncomplete) {
		t.Errorf("a stored device with a missing document exits 3, got %v", err)
	}
	if !strings.Contains(out.String(), "interfaces") || !strings.Contains(out.String(), "FAILED") {
		t.Errorf("the failed document must be named:\n%s", out.String())
	}
	if _, err := st.Latest("fw01"); err != nil {
		t.Error("the configuration arrived, so latest must still move")
	}
}

// Spec S10: a device that cannot be reached does not stop the next one; nothing
// stored at all is an error.
func TestFetchContinuesPastAFailedDevice(t *testing.T) {
	inv, st := setup(t, lab(t).Start(t))
	var out bytes.Buffer
	err := fetchDevices(context.Background(), &out, inv, st, []string{"nope", "fw01"}, getenv)
	if !errors.Is(err, errIncomplete) || !strings.Contains(out.String(), "nope:") {
		t.Errorf("got %v\n%s", err, out.String())
	}
	if _, err := st.Latest("fw01"); err != nil {
		t.Error("fw01 must still be fetched after the failure")
	}
	if err := fetchDevices(context.Background(), &out, inv, st, []string{"nope"}, getenv); err == nil || errors.Is(err, errIncomplete) {
		t.Errorf("nothing stored is an error, got %v", err)
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

// Store names the documents it reads; they must be fetch's names.
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

// cli runs panos-analyst against a temporary inventory and store.
type cli struct {
	t       *testing.T
	dir     string
	env     map[string]string
	clock   time.Time
	cfgPath string
}

func newCLI(t *testing.T) *cli {
	dir := t.TempDir()
	return &cli{
		t: t, dir: dir, cfgPath: filepath.Join(dir, "config.yaml"),
		env:   map[string]string{"LAB_PW": "not-a-real-password", "PANOS_STORE": filepath.Join(dir, "store")},
		clock: time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC),
	}
}

func (c *cli) inventory(doc string) {
	c.t.Helper()
	if err := os.WriteFile(c.cfgPath, []byte(doc), 0o600); err != nil {
		c.t.Fatal(err)
	}
}

// run returns stdout, stderr and the exit code. Each run moves the clock a minute.
func (c *cli) run(args ...string) (string, string, int) {
	var out, errOut bytes.Buffer
	now := c.clock
	c.clock = c.clock.Add(time.Minute)
	a := newApp(&out, &errOut, func(k string) string { return c.env[k] }, func() time.Time { return now })
	cmd := a.root()
	cmd.SetArgs(append(args, "--config", c.cfgPath))
	err := cmd.ExecuteContext(context.Background())
	code := exitCode(err, &errOut)
	return out.String(), errOut.String(), code
}

func (c *cli) want(code int, args ...string) string {
	c.t.Helper()
	out, errOut, got := c.run(args...)
	if got != code {
		c.t.Errorf("%v: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", args, got, code, out, errOut)
	}
	return out
}

func TestHousekeeping(t *testing.T) {
	c := newCLI(t)
	c.want(1, "fetch", "fw01")
	c.want(1, "snapshot", "list", "fw01")
	if out := c.want(0, "inventory", "init"); !strings.Contains(out, "wrote") {
		t.Errorf("init: %s", out)
	}
	c.want(1, "inventory", "init")
	c.inventory(inventoryFor(lab(t).Start(t)))
	c.want(2, "fetch")
	c.want(2, "fetch", "fw01", "--all")
	c.want(2, "fetch", "--nope")
	if out := c.want(0, "fetch", "--all"); !strings.Contains(out, "stored fw01@") {
		t.Errorf("fetch --all: %s", out)
	}
	c.want(0, "fetch", "--label", "site=s1")
	c.want(1, "snapshot", "list", "../x")
	out := c.want(0, "snapshot", "list", "fw01")
	if !strings.HasPrefix(out, "* ") || !strings.Contains(out, "4 documents, 0 failed") {
		t.Errorf("snapshot list:\n%s", out)
	}
	var env struct{ Results []struct{ Latest bool } }
	if err := json.Unmarshal([]byte(c.want(0, "snapshot", "list", "fw01", "--output", "json")), &env); err != nil || len(env.Results) != 2 {
		t.Errorf("snapshot list json: %v %+v", err, env)
	}
	if out := c.want(0, "snapshot", "show", "--vsys", "vsys1"); !strings.Contains(out, "PA-VM") || !strings.Contains(out, "5 security rules") {
		t.Errorf("snapshot show:\n%s", out)
	}
	if out := c.want(0, "snapshot", "show", "--output", "json"); !strings.Contains(out, `"serial": "007900000000001"`) {
		t.Errorf("snapshot show json:\n%s", out)
	}
}

// Parallel fetch stores every device and reports them in the order named.
func TestParallelFetchKeepsOrder(t *testing.T) {
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), lab(t).Start(t), lab(t).Start(t)))
	out := c.want(0, "fetch", "fw03", "fw01", "fw02")
	i3, i1, i2 := strings.Index(out, "stored fw03@"), strings.Index(out, "stored fw01@"), strings.Index(out, "stored fw02@")
	if i3 < 0 || i1 < 0 || i2 < 0 || i3 > i1 || i1 > i2 {
		t.Errorf("reports out of order:\n%s", out)
	}
}

func TestSearchAcrossTheEstate(t *testing.T) {
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), "127.0.0.1:1"))
	c.want(0, "fetch", "fw01")
	out := c.want(3, "search", "198.18.10.100")
	for _, want := range []string{
		"search 198.18.10.100 (covers)", "fw01 / vsys1   snapshot", "object     address         dc01",
		"reference  security rule   dc-to-home", "hole: fw02:", "1 with results, 1 without, 1 holes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	out = c.want(0, "search", "198.18.10.100", "--device", "fw01", "--output", "json")
	var env struct {
		Format  int
		Results []struct{ Device, Vsys, Stage, Kind, Name, Snapshot string }
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Format != 1 || len(env.Results) == 0 ||
		env.Results[0].Device != "fw01" || env.Results[0].Snapshot == "" {
		t.Errorf("json: %v %+v", err, env)
	}
	c.want(2, "search", "x", "--exact", "--within")
	c.want(2, "search", "x", "--show", "nothing")
	c.want(2, "search", "web", "--within", "--device", "fw01")
	c.want(2, "search", "x", "--file", "f.xml", "--device", "fw01")
	c.want(2, "search", "x", "--label", "nolabel")
	c.want(2, "search", "x", "--label", "site=nowhere")
	c.want(2, "search", "x", "--at", "tuesday", "--device", "fw01")
	c.want(0, "search", "x", "--at", "2026-09-28", "--device", "fw01")
	if out := c.want(0, "search", "198.18.10.100", "--file", "../../testdata/config/firewall-lab.xml"); !strings.Contains(out, "file / vsys1") {
		t.Errorf("--file:\n%s", out)
	}
	c.want(3, "search", "198.18.10.100", "--file", "../../testdata/config/firewall-version-12.2.xml")
	c.want(1, "search", "x", "--file", "../../testdata/config/missing.xml")
}

// --fresh fetches before answering; a device it could not fetch keeps its old
// snapshot and says so.
func TestFreshSearch(t *testing.T) {
	c := newCLI(t)
	d := lab(t)
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	d.Password = "rotated"
	out := c.want(0, "search", "198.18.10.100", "--fresh")
	if !strings.Contains(out, "note: fresh fetch failed") {
		t.Errorf("a failed fresh fetch must be noted:\n%s", out)
	}
}

func TestSettingsPrecedence(t *testing.T) {
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	c.want(0, "fetch", "fw01")
	fileStore := filepath.Join(c.dir, "file-store")
	c.inventory(strings.Replace(inventoryFor("127.0.0.1:1"), "  password_env: LAB_PW\n",
		"  password_env: LAB_PW\n  output: json\n  store: "+fileStore+"\n", 1))
	// The env store wins over the file's; the file's output applies.
	if out := c.want(0, "snapshot", "list", "fw01"); !strings.HasPrefix(out, "{") {
		t.Errorf("the file's output: json must apply:\n%s", out)
	}
	c.env["PANOS_OUTPUT"] = "text"
	if out := c.want(0, "snapshot", "list", "fw01"); strings.HasPrefix(out, "{") {
		t.Errorf("PANOS_OUTPUT must win over the file:\n%s", out)
	}
	if out := c.want(0, "snapshot", "list", "fw01", "--output", "json"); !strings.HasPrefix(out, "{") {
		t.Errorf("--output must win over PANOS_OUTPUT:\n%s", out)
	}
	delete(c.env, "PANOS_STORE")
	c.want(1, "snapshot", "list", "fw01") // the file's store is empty
	c.want(0, "snapshot", "list", "fw01", "--store", filepath.Join(c.dir, "store"))
	c.want(2, "snapshot", "list", "fw01", "--output", "yaml")
	c.want(2, "snapshot", "list", "fw01", "--max-age", "soon")
	c.env["PANOS_MAX_SNAPSHOT_AGE"] = "1m"
	out := c.want(0, "snapshot", "show", "--store", filepath.Join(c.dir, "store"))
	if !strings.Contains(out, "past the 1m0s limit") {
		t.Errorf("an old snapshot must carry a note:\n%s", out)
	}
}

func TestSnapshotDiff(t *testing.T) {
	c := newCLI(t)
	d := lab(t)
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	if out := c.want(3, "snapshot", "diff"); !strings.Contains(out, "nothing to compare") {
		t.Errorf("one snapshot is a hole:\n%s", out)
	}
	d.Config = read(t, "../../testdata/config/firewall-lab-changed.xml")
	c.want(0, "fetch", "fw01")
	out := c.want(0, "snapshot", "diff")
	for _, want := range []string{
		"changed  address         net-home                 198.18.1.0/24 -> 198.18.2.0/24",
		"added    security rule   new-rule", "vsys:vsys2 no changes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if out := c.want(0, "snapshot", "diff", "--output", "json", "--vsys", "vsys1"); !strings.Contains(out, `"op": "removed"`) {
		t.Errorf("json diff:\n%s", out)
	}
	c.want(2, "snapshot", "diff", "--file", "x.xml")
	c.want(0, "snapshot", "diff", "--from", "2026-09-28T10:00:30Z", "--to", "2026-09-28T23:00:00Z")
	c.want(3, "snapshot", "diff", "--from", "2026-01-01")
	c.want(3, "snapshot", "diff", "--to", "garbage")
}

func TestSimulateSecpolicy(t *testing.T) {
	c := newCLI(t)
	file := "../../testdata/config/firewall-zones.xml"
	out := c.want(0, "simulate", "secpolicy", "10.1.0.5", "10.2.0.5", "--file", file, "--vsys", "vsys1")
	if !strings.Contains(out, "not evaluated: application, service, zones") {
		t.Errorf("without zones they are not evaluated:\n%s", out)
	}
	if !strings.Contains(out, "first match: ") && !strings.Contains(out, "no enabled rule matches") {
		t.Errorf("the verdict line is missing:\n%s", out)
	}
	c.want(2, "simulate", "secpolicy", "1.1.1.1", "2.2.2.2", "--file", "../../testdata/config/firewall-multivsys.xml")
	c.want(2, "simulate", "secpolicy", "1.1.1.1", "2.2.2.2", "--file", file, "--from-zone", "inside")
	c.want(2, "simulate", "secpolicy", "1.1.1.1")
	c.want(1, "simulate", "secpolicy", "1.1.1.1", "2.2.2.2", "--file", file, "--vsys", "vsys9")
	out = c.want(0, "simulate", "secpolicy", "198.18.10.100", "198.18.1.5", "--file", "../../testdata/config/firewall-lab.xml",
		"--vsys", "vsys1", "--port", "443", "--from-zone", "a", "--to-zone", "b", "--user", "u")
	if !strings.Contains(out, "zones: from a, to b") || !strings.Contains(out, "tcp/443") || !strings.Contains(out, "user") {
		t.Errorf("zones, port and user must be shown:\n%s", out)
	}
	out = c.want(0, "simulate", "secpolicy", "198.18.10.100", "198.18.1.5", "--file", "../../testdata/config/firewall-lab.xml",
		"--vsys", "vsys1", "--output", "json")
	var env struct {
		Results struct {
			FirstMatch   *struct{ Name string } `json:"first_match"`
			NotEvaluated []string               `json:"not_evaluated"`
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Results.FirstMatch == nil || env.Results.FirstMatch.Name != "dc-to-home" {
		t.Errorf("json: %v %s", err, out)
	}
}

func TestExitCode(t *testing.T) {
	var errOut bytes.Buffer
	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0},
		{errors.New("boom"), 1},
		{usageErr("bad flag"), 2},
		{errIncomplete, 3},
	} {
		if got := exitCode(tc.err, &errOut); got != tc.want {
			t.Errorf("exitCode(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
	if !strings.Contains(errOut.String(), "boom") || strings.Contains(errOut.String(), "exit 3") {
		t.Errorf("stderr = %q", errOut.String())
	}
	if (&exitErr{code: 3}).Error() != "exit 3" {
		t.Error("an exitErr without a message names its code")
	}
}

func TestAgo(t *testing.T) {
	for d, want := range map[time.Duration]string{45 * time.Minute: "45m", 3 * time.Hour: "3h", 72 * time.Hour: "3d"} {
		if got := ago(d); got != want {
			t.Errorf("ago(%v) = %s, want %s", d, got, want)
		}
	}
}
