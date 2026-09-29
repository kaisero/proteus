package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/config"
	"github.com/okaiser/proteus/internal/fakepanos"
	"github.com/okaiser/proteus/internal/fetch"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/search"
	"github.com/okaiser/proteus/internal/store"
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
			"<show><advanced-routing><route><afi>ipv4</afi></route></advanced-routing></show>": read(t,
				"../../testdata/opdata/fw01-advanced-routing-route.xml"),
			// fw01 runs no HA, so its state is fw02's: both say not enabled.
			"<show><high-availability><state/></high-availability></show>": read(t, "../../testdata/opdata/fw02-ha-state.xml"),
		},
	}
}

func inventoryFor(hosts ...string) string {
	var s strings.Builder
	s.WriteString("version: 1\ndefaults:\n  insecure_tls: true\n  username: reader\n  password_env: LAB_PW\ndevices:\n")
	for i, h := range hosts {
		n := string(rune('1' + i))
		s.WriteString("  - name: fw0" + n + "\n    host: " + h + "\n    labels: {site: s" + n + "}\n")
	}
	return s.String()
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
	if err := (fetcher{inv: inv, st: st, getenv: getenv}).devices(context.Background(), &out, []string{"fw01"}); err != nil {
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
	err := (fetcher{inv: inv, st: st, getenv: getenv}).devices(context.Background(), &out, []string{"fw01"})
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
	err := (fetcher{inv: inv, st: st, getenv: getenv}).devices(context.Background(), &out, []string{"nope", "fw01"})
	if !errors.Is(err, errIncomplete) || !strings.Contains(out.String(), "nope:") {
		t.Errorf("got %v\n%s", err, out.String())
	}
	if _, err := st.Latest("fw01"); err != nil {
		t.Error("fw01 must still be fetched after the failure")
	}
	if err := (fetcher{inv: inv, st: st, getenv: getenv}).devices(context.Background(), &out, []string{"nope"}); err == nil || errors.Is(err, errIncomplete) {
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
	_ = (fetcher{inv: inv, st: st, getenv: getenv}).devices(context.Background(), &out, []string{"fw01"})
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

// cli runs proteus against a temporary inventory and store.
type cli struct {
	t       *testing.T
	dir     string
	env     map[string]string
	clock   time.Time
	cfgPath string
	// peerHost is passed to every app the harness builds.
	peerHost func(string) string
}

func newCLI(t *testing.T) *cli {
	dir := t.TempDir()
	return &cli{
		t: t, dir: dir, cfgPath: filepath.Join(dir, "config.yaml"),
		env: map[string]string{
			"LAB_PW": "not-a-real-password", "PROTEUS_STORE": filepath.Join(dir, "store"),
			"PROTEUS_LOG_DIR": filepath.Join(dir, "log"),
		},
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
	a.peerHost = c.peerHost
	code := a.execute(context.Background(), append(args, "--config", c.cfgPath))
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
	if !strings.HasPrefix(out, "* ") || !strings.Contains(out, "6 documents, 0 failed") {
		t.Errorf("snapshot list:\n%s", out)
	}
	var env struct{ Results []struct{ Latest bool } }
	if err := json.Unmarshal([]byte(c.want(0, "snapshot", "list", "fw01", "--output", "json")), &env); err != nil || len(env.Results) != 2 {
		t.Errorf("snapshot list json: %v %+v", err, env)
	}
	if out := c.want(0, "snapshot", "show", "--vsys", "vsys1"); !strings.Contains(out, "PA-VM") || !strings.Contains(out, "security rules: 5") {
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
		"search 198.18.10.100 (covers)", "fw01 / vsys1   snapshot", "object     address              dc01",
		"reference  security rule        dc-to-home", "hole: fw02:", "1 with results, 1 without, 1 holes",
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
	if out := c.want(0, "search", "198.18.10.100", "--device", "fw01", "--show", "objects,refs"); strings.Contains(out, "\n  group ") || !strings.Contains(out, "reference") {
		t.Errorf("--show objects,refs:\n%s", out)
	}
	if _, errOut, code := c.run("search", "web", "--within", "--device", "fw01"); code != 2 || !strings.Contains(errOut, "--within: ") {
		t.Errorf("--within on a name: exit %d, stderr %q", code, errOut)
	}
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
	c.env["PROTEUS_OUTPUT"] = "text"
	if out := c.want(0, "snapshot", "list", "fw01"); strings.HasPrefix(out, "{") {
		t.Errorf("PROTEUS_OUTPUT must win over the file:\n%s", out)
	}
	if out := c.want(0, "snapshot", "list", "fw01", "--output", "json"); !strings.HasPrefix(out, "{") {
		t.Errorf("--output must win over PROTEUS_OUTPUT:\n%s", out)
	}
	delete(c.env, "PROTEUS_STORE")
	c.want(1, "snapshot", "list", "fw01") // the file's store is empty
	c.want(0, "snapshot", "list", "fw01", "--store", filepath.Join(c.dir, "store"))
	c.want(2, "snapshot", "list", "fw01", "--output", "yaml")
	c.want(2, "snapshot", "list", "fw01", "--max-age", "soon")
	c.env["PROTEUS_MAX_SNAPSHOT_AGE"] = "1m"
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
		"changed  address              net-home                 198.18.1.0/24 -> 198.18.2.0/24",
		"added    security rule        new-rule", "vsys:vsys2 no changes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if out := c.want(0, "snapshot", "diff", "--output", "json", "--vsys", "vsys1"); !strings.Contains(out, `"op": "removed"`) {
		t.Errorf("json diff:\n%s", out)
	}
	if strings.Contains(out, "different firewalls") {
		t.Errorf("one firewall, no failover note:\n%s", out)
	}
	// After a failover the entry is answered by the other member of the pair.
	d.Ops["<show><system><info/></system></show>"] = fakepanos.Success("<system><hostname>fw01-b</hostname><serial>000000000009</serial></system>")
	c.want(0, "fetch", "fw01")
	if out := c.want(0, "snapshot", "diff"); !strings.Contains(out, "note: the snapshots come from different firewalls (serial 007900000000001, then 000000000009)") {
		t.Errorf("failover:\n%s", out)
	}
	c.want(2, "snapshot", "diff", "--file", "x.xml")
	c.want(0, "snapshot", "diff", "--from", "2026-09-28T10:00:30Z", "--to", "2026-09-28T23:00:00Z")
	c.want(3, "snapshot", "diff", "--from", "2026-01-01")
	c.want(3, "snapshot", "diff", "--to", "garbage")
}

func TestSimulatePolicy(t *testing.T) {
	c := newCLI(t)
	file := "../../testdata/config/firewall-zones.xml"
	out := c.want(0, "simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", file, "--vsys", "vsys1", "--why")
	for _, want := range []string{
		"zones      from inside, to dmz (configuration)", "fidelity   inferred; not evaluated: service, application",
		"derive-zones         inferred", "first-match          overmatch", "first match: from-inside (allow)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	c.want(2, "simulate", "policy", "1.1.1.1", "2.2.2.2", "--file", "../../testdata/config/firewall-multivsys.xml")
	c.want(2, "simulate", "policy", "1.1.1.1", "2.2.2.2", "--file", file, "--from-zone", "inside")
	c.want(2, "simulate", "policy", "1.1.1.1")
	c.want(2, "simulate", "policy", "10.0.0.0/8", "2.2.2.2", "--file", file)
	c.want(2, "simulate", "policy", "host", "2.2.2.2", "--file", file)
	c.want(2, "simulate", "policy", "1.1.1.1", "2.2.2.2", "--file", file, "--port", "https")
	c.want(2, "simulate", "policy", "1.1.1.1", "2.2.2.2", "--file", file, "--source-port", "70000")
	c.want(1, "simulate", "policy", "1.1.1.1", "2.2.2.2", "--file", file, "--vsys", "vsys9")
	out = c.want(0, "simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", file, "--from-zone", "dmz", "--to-zone", "inside")
	c.want(2, "simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", file, "--from-zone", "dmz")
	if !strings.Contains(out, "no enabled rule matches") {
		t.Errorf("no match:\n%s", out)
	}
	out = c.want(0, "simulate", "policy", "198.18.10.100", "198.18.1.5", "--file", "../../testdata/config/firewall-lab.xml",
		"--vsys", "vsys1", "--port", "tcp/443", "--output", "json")
	var env struct {
		Results struct {
			FirstMatch *struct{ Name string } `json:"first_match"`
			Fidelity   struct{ Level string }
			Stages     []struct{ Slug string }
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Results.FirstMatch == nil ||
		env.Results.FirstMatch.Name != "dc-to-home" || len(env.Results.Stages) != 8 || env.Results.Fidelity.Level == "" {
		t.Errorf("json: %v %s", err, out)
	}
}

// A URL and a port narrow the candidates; an FQDN resolves through DNS.
func TestSimulateDimensions(t *testing.T) {
	c := newCLI(t)
	file := "../../testdata/config/firewall-simulate.xml"
	out := c.want(0, "simulate", "policy", "10.0.0.1", "10.6.0.1", "--file", file, "--url", "shop.example.com/cart")
	if !strings.Contains(out, "first match: shop (allow)") || !strings.Contains(out, "social") {
		t.Errorf("url:\n%s", out)
	}
	out = c.want(0, "simulate", "policy", "10.0.0.1", "10.5.0.1", "--file", file, "--port", "8443")
	if !strings.Contains(out, "first match: custom-port (allow)") || !strings.Contains(out, "app-default") {
		t.Errorf("port:\n%s", out)
	}
	out = c.want(3, "simulate", "policy", "10.0.0.1", "www.example.com", "--file", file, "--no-dns")
	if strings.Count(out, "resolved to no address") != 2 { // the fidelity line and one unresolved line
		t.Errorf("an unresolved FQDN is an incomplete answer, said once:\n%s", out)
	}
}

func TestSimulateResolvesAnFQDN(t *testing.T) {
	var out, errOut bytes.Buffer
	dir := t.TempDir()
	a := newApp(&out, &errOut, func(k string) string {
		return map[string]string{"PROTEUS_LOG_DIR": filepath.Join(dir, "log"), "PROTEUS_CONFIG": filepath.Join(dir, "none.yaml")}[k]
	}, time.Now)
	a.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	code := a.execute(context.Background(), []string{
		"simulate", "policy", "10.0.0.1", "WWW.example.com",
		"--file", "../../testdata/config/firewall-simulate.xml",
	})
	if code != 0 || !strings.Contains(out.String(), "dns        www.example.com -> [203.0.113.10]") ||
		!strings.Contains(out.String(), "to-web-by-address") {
		t.Errorf("exit %d:\n%s\n%s", code, out.String(), errOut.String())
	}
	out.Reset()
	a = newApp(&out, &errOut, func(k string) string {
		return map[string]string{"PROTEUS_LOG_DIR": filepath.Join(dir, "log"), "PROTEUS_CONFIG": filepath.Join(dir, "none.yaml")}[k]
	}, time.Now)
	a.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	if code := a.execute(context.Background(), []string{
		"simulate", "policy", "10.0.0.1", "www.example.com",
		"--file", "../../testdata/config/firewall-simulate.xml",
	}); code != 3 {
		t.Errorf("a failed lookup leaves the FQDN unresolved: exit %d", code)
	}
}

// Zones derive from a fetched device's forwarding table.
func TestSimulateDerivesZonesFromTheStore(t *testing.T) {
	c := newCLI(t)
	d := lab(t)
	d.Config = read(t, "../../testdata/config/firewall-fw01-zones.xml")
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	out := c.want(0, "simulate", "policy", "198.18.11.5", "198.18.10.5", "--device", "fw01", "--why")
	for _, want := range []string{"zones      from client, to server (forwarding table)", "relevant   198.18.", "first match: client-to-server (allow)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	out = c.want(0, "simulate", "policy", "8.8.8.8", "1.1.1.1", "--device", "fw01")
	if !strings.Contains(out, "not relevant: only a default route") {
		t.Errorf("relevance:\n%s", out)
	}
}

func TestExitCode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		want   int
		stderr string
	}{
		{"complete", nil, 0, ""},
		{"an error", errors.New("boom"), 1, "proteus: boom\n"},
		{"a usage error", usageErr("bad flag"), 2, "proteus: bad flag\n"},
		{"an incomplete answer says nothing more", errIncomplete, 3, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var errOut bytes.Buffer
			if got := exitCode(tc.err, &errOut); got != tc.want || errOut.String() != tc.stderr {
				t.Errorf("exitCode(%v) = %d, stderr %q; want %d, %q", tc.err, got, errOut.String(), tc.want, tc.stderr)
			}
		})
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

func TestSearchWithAUserSnapshot(t *testing.T) {
	c := newCLI(t)
	file := "../../testdata/config/firewall-users.xml"
	if out := c.want(0, "search", `ACME\carol`, "--file", file); strings.Contains(out, "engineering-allowed") {
		t.Errorf("without PROTEUS_USERS carol reaches nothing:\n%s", out)
	}
	c.env["PROTEUS_USERS"] = "../../testdata/users-snapshot.json"
	if out := c.want(0, "search", `ACME\carol`, "--file", file); !strings.Contains(out, "engineering-allowed") {
		t.Errorf("with PROTEUS_USERS carol reaches engineering-allowed:\n%s", out)
	}
	c.env["PROTEUS_USERS"] = "../../testdata/missing.json"
	c.want(1, "search", "x", "--file", file)
	c.env["PROTEUS_USERS"] = "../../testdata/config/firewall-lab.xml"
	c.want(1, "search", "x", "--file", file)
}

func TestModeName(t *testing.T) {
	for term, want := range map[string]string{"10.0.0.1": "covers", "tcp/443": "covers", "443": "covers", "10.0.0.0/8": "overlaps", "web": "matches"} {
		if got := modeName(search.Query{Term: term}); got != want {
			t.Errorf("modeName(%s) = %s, want %s", term, got, want)
		}
	}
}

// Every run writes a log with its command, settings, snapshots and exit; a run that
// ends badly prints where the log is.
func TestRunLog(t *testing.T) {
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	c.want(0, "fetch", "fw01", "--log-level", "debug")
	_, errOut, code := c.run("search", "198.18.10.100", "--device", "fw01", "--vsys", "vsys9")
	if code != 3 || !strings.Contains(errOut, "log: ") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	logs, _ := filepath.Glob(filepath.Join(c.dir, "log", "*.log"))
	if len(logs) != 2 {
		t.Fatalf("logs = %v", logs)
	}
	fetchLog, searchLog := read(t, logs[0]), read(t, logs[1])
	for _, want := range []string{"[INFO] [RUN] proteus dev: fetch fw01", "[DEBUG] [API] fw01: keygen -> HTTP 200", "[INFO] [SNAP] fw01: stored", "[INFO] [RUN] exit 0"} {
		if !strings.Contains(fetchLog, want) {
			t.Errorf("fetch log misses %q:\n%s", want, fetchLog)
		}
	}
	for _, want := range []string{"[INFO] [RUN] settings: inventory", "[INFO] [SNAP] fw01: snapshot", "[WARN] [SNAP] fw01/vsys9: hole", "[WARN] [RUN] the answer is incomplete", "[INFO] [RUN] exit 3"} {
		if !strings.Contains(searchLog, want) {
			t.Errorf("search log misses %q:\n%s", want, searchLog)
		}
	}
	if strings.Contains(fetchLog+searchLog, "not-a-real-password") || strings.Contains(fetchLog+searchLog, "not-a-real-key") {
		t.Error("a secret reached a log")
	}
	c.want(2, "search", "x", "--log-level", "trace")
	_, errOut, _ = c.run("search", "198.18.10.100", "--device", "fw01", "--verbose", "--log-level", "debug")
	if !strings.Contains(errOut, "[DEBUG] [FIND] fw01/vsys1: object address dc01") {
		t.Errorf("--verbose must echo the log:\n%s", errOut)
	}
	c.env["PROTEUS_LOG_DIR"] = filepath.Join(c.cfgPath, "not-a-dir") // under a file, so it cannot be created
	if _, errOut, code := c.run("search", "x", "--device", "fw01"); code != 0 || !strings.Contains(errOut, "no run log") {
		t.Errorf("an unwritable log dir warns and carries on: exit %d, %q", code, errOut)
	}
}

// With no flags and no PROTEUS_STORE or PROTEUS_LOG_DIR, the store and the log follow
// the XDG directories, and the inventory comes from PROTEUS_CONFIG.
func TestDefaultsFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "inv.yaml")
	if err := os.WriteFile(cfg, []byte(inventoryFor(lab(t).Start(t))), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"LAB_PW": "not-a-real-password", "PROTEUS_CONFIG": cfg,
		"XDG_DATA_HOME": filepath.Join(dir, "data"), "XDG_STATE_HOME": filepath.Join(dir, "state"),
	}
	run := func(args ...string) int {
		var out, errOut bytes.Buffer
		return newApp(&out, &errOut, func(k string) string { return env[k] }, time.Now).execute(context.Background(), args)
	}
	if code := run("fetch", "fw01"); code != 0 {
		t.Fatalf("fetch: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "data", "proteus", "fw01", "latest")); err != nil {
		t.Errorf("the store must default to $XDG_DATA_HOME/proteus: %v", err)
	}
	if logs, _ := filepath.Glob(filepath.Join(dir, "state", "proteus", "log", "fetch-*.log")); len(logs) != 1 {
		t.Errorf("the log must default to $XDG_STATE_HOME/proteus/log: %v", logs)
	}
	if got := expandHome("~/x"); !strings.HasSuffix(got, string(filepath.Separator)+"x") || strings.HasPrefix(got, "~") {
		t.Errorf("expandHome = %s", got)
	}
	if expandHome("/abs") != "/abs" {
		t.Error("an absolute path stays")
	}
}

// An inventory entry naming the passive HA peer stores the active peer's data and
// says so. The pair shape is synthetic: no lab device runs HA.
func TestFetchFollowsThePassivePeer(t *testing.T) {
	haCmd := "<show><high-availability><state/></high-availability></show>"
	state := func(local, localSerial, peer, peerSerial string) string {
		return fakepanos.Success(`<enabled>yes</enabled><group><mode>active-passive</mode><local-info><state>` + local +
			`</state><serial-num>` + localSerial + `</serial-num></local-info><peer-info><state>` + peer +
			`</state><serial-num>` + peerSerial + `</serial-num><mgmt-ip>192.0.2.2</mgmt-ip></peer-info></group>`)
	}
	passive, active := lab(t), lab(t)
	passive.Ops[haCmd] = state("passive", "A", "active", "B")
	active.Ops[haCmd] = state("active", "B", "passive", "A")
	activeHost := active.Start(t)
	c := newCLI(t)
	c.peerHost = func(string) string { return activeHost }
	c.inventory(inventoryFor(passive.Start(t)))
	if out := c.want(0, "fetch", "fw01"); !strings.Contains(out, "fw01 is the passive HA peer; fetched from the active peer "+activeHost) {
		t.Errorf("fetch:\n%s", out)
	}
	if out := c.want(0, "snapshot", "show", "--device", "fw01"); !strings.Contains(out, "fetched from the active HA peer "+activeHost) {
		t.Errorf("snapshot show:\n%s", out)
	}
	passive.Ops[haCmd] = state("passive", "A", "suspended", "B")
	if out := c.want(0, "fetch", "fw01"); !strings.Contains(out, `note: passive, but the peer is "suspended"`) {
		t.Errorf("fetch with a suspended peer:\n%s", out)
	}
}

// Run is what main calls. It must report the version main passes in.
func TestRunReportsTheBuildVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	dir := t.TempDir()
	env := map[string]string{"HOME": dir, "PROTEUS_LOG_DIR": dir, "PROTEUS_CONFIG": filepath.Join(dir, "none.yaml")}
	code := Run(context.Background(), "1.2.3", []string{"--version"}, &out, &errOut, func(k string) string { return env[k] })
	if code != exitOK || !strings.Contains(out.String(), "1.2.3") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}

// Each match flag reaches search with its mode; the docs show these two runs.
func TestSearchModeFlags(t *testing.T) {
	c := newCLI(t)
	out := c.want(0, "search", "10.124.0.0/16", "--exact", "--show", "objects", "--vsys", "vsys1",
		"--file", "../../testdata/config/firewall-multivsys.xml")
	if !strings.Contains(out, "(exact)") || !strings.Contains(out, "corp-location-vienna") {
		t.Errorf("--exact:\n%s", out)
	}
	out = c.want(0, "search", "azureapps", "--contains", "--file", "../../testdata/config/firewall-urlcat.xml")
	if !strings.Contains(out, "(contains)") || !strings.Contains(out, "custom-azuresite-group") {
		t.Errorf("--contains:\n%s", out)
	}
}

// A fan-out cancelled while one device hangs returns at once with the other
// device stored, and TestMain's leak check proves no goroutine is left behind.
func TestACancelledFanOutEndsPromptly(t *testing.T) {
	hung := lab(t)
	hung.Stall = "export"
	inv, err := inventory.Parse(strings.NewReader(inventoryFor(lab(t).Start(t), hung.Start(t))))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out bytes.Buffer
	start := time.Now()
	err = (fetcher{inv: inv, st: st, getenv: getenv}).devices(ctx, &out, []string{"fw01", "fw02"})
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("the fan-out took %s after its context ended", elapsed)
	}
	if !errors.Is(err, errIncomplete) {
		t.Errorf("one device stored and one cancelled is an incomplete fetch, got %v\n%s", err, out.String())
	}
	if _, err := st.Latest("fw01"); err != nil {
		t.Errorf("the device that answered must be stored: %v", err)
	}
}
