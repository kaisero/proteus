package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/config"
	"github.com/kaisero/proteus/internal/fakepanos"
	"github.com/kaisero/proteus/internal/fetch"
	"github.com/kaisero/proteus/internal/identity"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/inventory"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/store"
	"github.com/kaisero/proteus/internal/testconfig"
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
	t.Parallel()
	inv, st := setup(t, lab(t).Start(t))
	var out bytes.Buffer
	res := (fetcher{inv: inv, st: st, getenv: getenv}).each(context.Background(), []string{"fw01"})
	if len(res) != 1 || !res[0].Stored || res[0].Error != "" {
		t.Fatalf("fetch: %+v", res)
	}
	ans := fetchAnswer{results: res}
	_ = ans.Text(&textOut{w: &out})
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
	idx, err := index.New(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, resolve.Security)
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

// fetchText fetches the devices and returns fetch's text answer and exit status.
func fetchText(ctx context.Context, f fetcher, names ...string) (string, error) {
	var out bytes.Buffer
	ans := fetchAnswer{results: f.each(ctx, names)}
	_ = ans.Text(&textOut{w: &out})
	return out.String(), ans.Status()
}

// Spec §15 C11: a device stored with a missing document is a partial failure.
func TestFetchReportsAFailedDocument(t *testing.T) {
	t.Parallel()
	d := lab(t)
	delete(d.Ops, "<show><interface>all</interface></show>")
	inv, st := setup(t, d.Start(t))
	out, err := fetchText(context.Background(), fetcher{inv: inv, st: st, getenv: getenv}, "fw01")
	if !errors.Is(err, errIncomplete) {
		t.Errorf("a stored device with a missing document exits 3, got %v", err)
	}
	if !strings.Contains(out, "interfaces") || !strings.Contains(out, "FAILED") {
		t.Errorf("the failed document must be named:\n%s", out)
	}
	if _, err := st.Latest("fw01"); err != nil {
		t.Error("the configuration arrived, so latest must still move")
	}
}

// Spec S10: a device that cannot be reached does not stop the next one; nothing
// stored at all is an error.
func TestFetchContinuesPastAFailedDevice(t *testing.T) {
	t.Parallel()
	inv, st := setup(t, lab(t).Start(t))
	out, err := fetchText(context.Background(), fetcher{inv: inv, st: st, getenv: getenv}, "nope", "fw01")
	if !errors.Is(err, errIncomplete) || !strings.Contains(out, "nope/resolve:") {
		t.Errorf("got %v\n%s", err, out)
	}
	if _, err := st.Latest("fw01"); err != nil {
		t.Error("fw01 must still be fetched after the failure")
	}
	if _, err := fetchText(context.Background(), fetcher{inv: inv, st: st, getenv: getenv}, "nope"); err == nil || errors.Is(err, errIncomplete) {
		t.Errorf("nothing stored is an error, got %v", err)
	}
}

func TestVerificationOnIsSaid(t *testing.T) {
	t.Parallel()
	inv, err := inventory.Parse(strings.NewReader(strings.Replace(inventoryFor(lab(t).Start(t)),
		"insecure_tls: true", "insecure_tls: false", 1)))
	if err != nil {
		t.Fatal(err)
	}
	st, _ := store.Open(t.TempDir())
	out, _ := fetchText(context.Background(), fetcher{inv: inv, st: st, getenv: getenv}, "fw01")
	if !strings.Contains(out, "TLS certificate verification on") {
		t.Errorf("the run must say verification is on:\n%s", out)
	}
}

// Store names the documents it reads; they must be fetch's names.
func TestStoreAndFetchAgreeOnDocumentNames(t *testing.T) {
	t.Parallel()
	for got, want := range map[string]string{
		store.ConfigDoc:     fetch.RunningConfig.Name,
		store.InterfacesDoc: fetch.Interfaces.Name,
		store.FIBDoc:        fetch.RoutingFIB.Name,
		store.RIBDoc:        fetch.RoutingRIB.Name,
		store.HADoc:         fetch.HAState.Name,
	} {
		if got != want {
			t.Errorf("store says %q, fetch says %q", got, want)
		}
	}
	// config reads the predefined services next to the configuration by file name.
	if config.PredefinedFile != fetch.Predefined.Name+".xml" {
		t.Errorf("config reads %q, fetch stores %q", config.PredefinedFile, fetch.Predefined.Name+".xml")
	}
}

// The predefined services are stored with the snapshot, and the stored
// configuration sees them (L4).
func TestFetchStoresThePredefinedServices(t *testing.T) {
	t.Parallel()
	inv, st := setup(t, lab(t).Start(t))
	if _, err := fetchText(context.Background(), fetcher{inv: inv, st: st, getenv: getenv}, "fw01"); err != nil {
		t.Fatal(err)
	}
	sn, err := st.Resolve("fw01")
	if _, statErr := os.Stat(sn.Path(fetch.Predefined.Name)); err != nil || statErr != nil {
		t.Fatalf("predefined.xml not stored: %v", err)
	}
	cfg, _, err := config.Load(sn.Path(store.ConfigDoc))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, o := range resolve.ObjectsInScope(cfg, config.Scope{Sort: config.ScopeVsys, Name: "vsys1"}, "service") {
		if o.Scope.Sort == config.ScopePredefined {
			names = append(names, o.Name+" "+o.Value)
		}
	}
	if got := strings.Join(names, ", "); got != "service-http tcp/80,8080, service-https tcp/443" {
		t.Errorf("predefined services = %s", got)
	}
}

// A device that refuses the predefined services gives a note and a complete
// fetch; the snapshot records the note and no failed document.
func TestFetchWithoutThePredefinedServicesIsComplete(t *testing.T) {
	t.Parallel()
	d := lab(t)
	d.Ops[fakepanos.PredefinedCmd] = fakepanos.Refusal("17", "show -> predefined is unexpected")
	inv, st := setup(t, d.Start(t))
	f := fetcher{inv: inv, st: st, getenv: getenv}
	ans := fetchAnswer{results: f.each(context.Background(), []string{"fw01"})}
	if err := ans.Status(); err != nil {
		t.Errorf("a refused optional document is a complete fetch, got %v", err)
	}
	q := ans.Qualifiers()
	if len(q.Notes) != 2 || q.Notes[1].Code != "note.fetch-predefined-missing" {
		t.Errorf("notes = %+v", q.Notes)
	}
	var out bytes.Buffer
	_ = ans.Text(&textOut{w: &out})
	if !strings.Contains(out.String(), "note: the device did not return its predefined services") || strings.Contains(out.String(), "FAILED") {
		t.Errorf("text:\n%s", out.String())
	}
	sn, err := st.Resolve("fw01")
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(sn.Path(fetch.Predefined.Name)); statErr == nil || len(sn.Meta.Documents) != 6 || len(sn.Meta.Notes) != 1 {
		t.Errorf("meta = %+v", sn.Meta)
	}
}

// meta.json names where the configuration came from (spec 2026-10-17 §2.1): the
// running configuration merged with the pushed template, kept as template.xml;
// the running configuration of a device without a template, with no note (C7);
// or the export of a device that refuses show config running, with its note. A
// template lost to the network makes the fetch incomplete.
func TestFetchRecordsTheConfigSource(t *testing.T) {
	t.Parallel()
	template := read(t, fixture("firewall-lab-template.xml"))
	for name, tc := range map[string]struct {
		device func(d *fakepanos.Device)
		code   int
		source string
		note   string
		file   bool
	}{
		"template":    {func(d *fakepanos.Device) { d.Template = template }, 0, "running+template", "", true},
		"no template": {func(*fakepanos.Device) {}, 0, "running", "", false},
		"refused": {func(d *fakepanos.Device) {
			d.Ops[fakepanos.RunningConfigCmd] = fakepanos.Refusal("17", "show -> config is unexpected")
		}, 0, "export", "note.config-not-running", false},
		"dropped": {func(d *fakepanos.Device) {
			d.Template = template
			d.DropCmd = map[string]int{fakepanos.PushedTemplateCmd: 2}
		}, exitIncomplete, "running", "", false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := lab(t)
			tc.device(d)
			c := newCLI(t)
			c.inventory(inventoryFor(d.Start(t)))
			out := c.want(tc.code, "fetch", "fw01", "--output", "json")
			var notes []string
			for _, n := range fetchNotes(t, out) {
				if n.Code != "note.tls-off" {
					notes = append(notes, string(n.Code))
				}
			}
			if got := strings.Join(notes, ","); got != tc.note {
				t.Errorf("notes %s, want %q", got, tc.note)
			}
			sn, err := store.At(c.env["PROTEUS_STORE"]).Latest("fw01")
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(sn.Dir, "meta.json"))
			if err != nil {
				t.Fatal(err)
			}
			if sn.Meta.ConfigSource != tc.source || !strings.Contains(string(b), `"config_source": "`+tc.source+`"`) {
				t.Errorf("source %q, meta.json:\n%s", sn.Meta.ConfigSource, b)
			}
			if _, err := os.Stat(sn.Path(fetch.PushedTemplate.Name)); (err == nil) != tc.file {
				t.Errorf("template.xml: %v, want stored %v", err, tc.file)
			}
		})
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
	// lookup, when set, is passed to every app the harness builds, in place of
	// the real DNS resolver.
	lookup func(context.Context, string) ([]netip.Addr, error)
	// canonical goes with lookup: with a fake resolver, the canonical name
	// comes from this fake too, nil for none.
	canonical func(context.Context, string) (string, error)
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
	return c.runRaw(append(args, "--config", c.cfgPath)...)
}

// runRaw runs the arguments as given, without the harness's --config.
func (c *cli) runRaw(args ...string) (string, string, int) {
	var out, errOut bytes.Buffer
	now := c.clock
	c.clock = c.clock.Add(time.Minute)
	a := newApp(&out, &errOut, func(k string) string { return c.env[k] }, func() time.Time { return now })
	a.peerHost = c.peerHost
	if c.lookup != nil {
		a.lookup, a.canonical = c.lookup, c.canonical
	}
	code := a.execute(context.Background(), args)
	return out.String(), errOut.String(), code
}

// logFile is the newest run log the harness's commands wrote.
func (c *cli) logFile() string {
	c.t.Helper()
	dir := c.env["PROTEUS_LOG_DIR"]
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return ""
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names) // the names embed a sortable UTC timestamp
	b, err := os.ReadFile(filepath.Join(dir, names[len(names)-1]))
	if err != nil {
		c.t.Fatal(err)
	}
	return string(b)
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
	t.Parallel()
	c := newCLI(t)
	c.want(1, "fetch", "fw01")
	c.want(3, "snapshot", "list", "fw01")
	if out := c.want(0, "inventory", "init"); !strings.Contains(out, "wrote") {
		t.Errorf("init: %s", out)
	}
	c.want(2, "inventory", "init")
	c.inventory(inventoryFor(lab(t).Start(t)))
	c.want(2, "fetch")
	c.want(2, "fetch", "fw01", "--all")
	c.want(2, "fetch", "--nope")
	if out := c.want(0, "fetch", "--all"); !strings.Contains(out, "stored fw01@") {
		t.Errorf("fetch --all: %s", out)
	}
	c.want(0, "fetch", "--label", "site=s1")
	c.want(2, "snapshot", "list", "../x")
	out := c.want(0, "snapshot", "list", "fw01")
	if !strings.HasPrefix(out, "* ") || !strings.Contains(out, "7 documents, 0 failed") {
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

// A damaged snapshot becomes a hole in snapshot list, and the good ones still show.
func TestSnapshotListGoesOnPastADamagedSnapshot(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	for range 3 {
		c.want(0, "fetch", "fw01")
	}
	type listed struct {
		Results []struct {
			ID     string
			Latest bool
		}
		Holes []struct{ Device, Code, Text string }
	}
	var before listed
	if err := json.Unmarshal([]byte(c.want(0, "snapshot", "list", "fw01", "--output", "json")), &before); err != nil || len(before.Results) != 3 {
		t.Fatalf("snapshot list json: %v %+v", err, before)
	}
	damaged := before.Results[1].ID
	if err := os.Remove(filepath.Join(c.env["PROTEUS_STORE"], "fw01", damaged, "meta.json")); err != nil {
		t.Fatal(err)
	}
	out := c.want(3, "snapshot", "list", "fw01")
	for _, want := range []string{
		"* " + before.Results[0].ID, "  " + before.Results[2].ID,
		"hole: fw01: store: fw01@" + damaged + ": meta.json: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	var after listed
	if err := json.Unmarshal([]byte(c.want(3, "snapshot", "list", "fw01", "--output", "json")), &after); err != nil {
		t.Fatal(err)
	}
	if len(after.Results) != 2 || after.Results[0].ID != before.Results[0].ID || !after.Results[0].Latest ||
		after.Results[1].ID != before.Results[2].ID {
		t.Errorf("results = %+v", after.Results)
	}
	if len(after.Holes) != 1 || after.Holes[0].Device != "fw01" || after.Holes[0].Code != "gap.load-failed" ||
		!strings.Contains(after.Holes[0].Text, damaged) {
		t.Errorf("holes = %+v", after.Holes)
	}
	// --at passes over the damaged snapshot to the older one, with a note.
	at, _ := time.Parse("2006-01-02T15-04-05Z", damaged)
	atFlag := at.Add(30 * time.Second).Format(time.RFC3339)
	note := "note: snapshot " + damaged + " skipped: its meta.json cannot be read; " + before.Results[2].ID + " answers"
	if out := c.want(0, "snapshot", "show", "--device", "fw01", "--at", atFlag); !strings.Contains(out, note) {
		t.Errorf("snapshot show --at: missing %q in:\n%s", note, out)
	}
	var shown struct{ Notes []struct{ Code, Text string } }
	if err := json.Unmarshal([]byte(c.want(0, "snapshot", "show", "--device", "fw01", "--at", atFlag, "--output", "json")), &shown); err != nil ||
		len(shown.Notes) == 0 || shown.Notes[0].Code != "note.snapshot-skipped" {
		t.Errorf("snapshot show --at json: %v %+v", err, shown)
	}
}

// A snapshot pruned between List and Get no longer exists: it is left out, with
// no hole.
func TestSnapshotRowsSkipAPrunedSnapshot(t *testing.T) {
	t.Parallel()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st = st.WithClock(func() time.Time { return time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC) })
	sn, err := st.Write(store.Meta{Device: "fw01"}, map[string][]byte{store.ConfigDoc: []byte("<config/>")}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	rows, holes := snapshotRows(st, "fw01", []string{"2026-09-28T11-00-00Z", sn.ID})
	if len(rows) != 1 || rows[0].ID != sn.ID || !rows[0].Latest || len(holes) != 0 {
		t.Errorf("rows = %+v, holes = %+v", rows, holes)
	}
}

// Parallel fetch stores every device and reports them in the order named.
func TestParallelFetchKeepsOrder(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), lab(t).Start(t), lab(t).Start(t)))
	out := c.want(0, "fetch", "fw03", "fw01", "fw02")
	i3, i1, i2 := strings.Index(out, "stored fw03@"), strings.Index(out, "stored fw01@"), strings.Index(out, "stored fw02@")
	if i3 < 0 || i1 < 0 || i2 < 0 || i3 > i1 || i1 > i2 {
		t.Errorf("reports out of order:\n%s", out)
	}
}

// A device named twice is fetched once: two fetches in one second would write the
// same snapshot, and one of them would fail.
func TestFetchNamesADeviceOnce(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), lab(t).Start(t)))
	out := c.want(0, "fetch", "fw02", "fw01", "fw02", "fw01")
	if n := strings.Count(out, "stored fw01@"); n != 1 {
		t.Errorf("fw01 stored %d times:\n%s", n, out)
	}
	if i2, i1 := strings.Index(out, "stored fw02@"), strings.Index(out, "stored fw01@"); i2 < 0 || i2 > i1 {
		t.Errorf("reports out of order:\n%s", out)
	}
	var env struct{ Results []struct{ Device string } }
	if err := json.Unmarshal([]byte(c.want(0, "fetch", "fw01", "fw01", "--output", "json")), &env); err != nil ||
		len(env.Results) != 1 || env.Results[0].Device != "fw01" {
		t.Errorf("fetch fw01 fw01 json: %v %+v", err, env)
	}
}

func TestSearchAcrossTheEstate(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), "127.0.0.1:1"))
	c.want(0, "fetch", "fw01")
	out := c.want(3, "search", "198.18.10.100")
	for _, want := range []string{
		"search 198.18.10.100 (covers)", "fw01 / vsys1   snapshot", "object    address       dc01",
		"reference security rule dc-to-home", "hole: fw02:", "1 with results, 1 without, 1 holes",
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
	if err := json.Unmarshal([]byte(out), &env); err != nil || env.Format != 2 || len(env.Results) == 0 ||
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
	c.want(0, "search", "198.18.10.100", "--file", "../../testdata/config/firewall-version-12.2.xml")
	c.want(1, "search", "x", "--file", "../../testdata/config/missing.xml")
}

// --fresh fetches before answering; a device it could not fetch keeps its old
// snapshot and says so.
func TestFreshSearch(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	c.want(3, "snapshot", "list", "fw01") // the file's store is empty
	c.want(0, "snapshot", "list", "fw01", "--store", filepath.Join(c.dir, "store"))
	c.want(2, "snapshot", "list", "fw01", "--output", "xml")
	c.want(2, "snapshot", "list", "fw01", "--max-age", "soon")
	c.env["PROTEUS_MAX_SNAPSHOT_AGE"] = "1m"
	out := c.want(0, "snapshot", "show", "--store", filepath.Join(c.dir, "store"))
	if !strings.Contains(out, "past the 1m0s limit") {
		t.Errorf("an old snapshot must carry a note:\n%s", out)
	}
}

// A secret's value never reaches the diff's output, in any format.
func TestSnapshotDiffHidesSecrets(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	d := lab(t)
	d.Config = read(t, "../../testdata/drift/before.xml")
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	d.Config = read(t, "../../testdata/drift/secrets.xml")
	c.want(0, "fetch", "fw01")
	raw := []string{"DUMMYKEYBEFORE0000", "DUMMYKEYAFTER00000", "DUMMYBINDBEFORE000", "DUMMYBINDAFTER0000", "DUMMYHASHBEFORE0000", "DUMMYHASHAFTER00000"}
	text := c.want(0, "snapshot", "diff", "--vsys", "vsys1")
	for _, want := range []string{
		"private-key: changed (secret, not shown)", "bind-password: changed (secret, not shown)", "phash: changed (secret, not shown)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	for _, format := range []string{"text", "json", "yaml"} {
		out := c.want(0, "snapshot", "diff", "--vsys", "vsys1", "--output", format)
		for _, v := range raw {
			if strings.Contains(out, v) {
				t.Errorf("%s output shows %s:\n%s", format, v, out)
			}
		}
		if format != "text" && !strings.Contains(out, "(secret)") {
			t.Errorf("%s output must mark the secrets:\n%s", format, out)
		}
	}
	// Lookup and search read no secret either.
	file := "../../testdata/drift/before.xml"
	for _, args := range [][]string{
		{"lookup", "cert-web", "--file", file, "--output", "json"},
		{"lookup", "ldap-corp", "--file", file, "--output", "json"},
		{"search", "--contains", "AQ==", "--file", file, "--output", "json"},
		{"search", "--contains", "$5$", "--file", file, "--output", "json"},
	} {
		out, errOut, code := c.run(args...)
		if code != 0 && code != 1 {
			t.Errorf("%v: exit %d: %s", args, code, errOut)
		}
		for _, v := range raw {
			if strings.Contains(out+errOut, v) {
				t.Errorf("%v shows %s:\n%s", args, v, out)
			}
		}
	}
}

// A value the schema does not describe never reaches the diff's output: it
// may be a secret a newer release added.
func TestSnapshotDiffHidesUndescribedValues(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	d := lab(t)
	d.Config = read(t, "../../testdata/drift/before.xml")
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	d.Config = read(t, "../../testdata/drift/undescribed.xml")
	c.want(0, "fetch", "fw01")
	text := c.want(0, "snapshot", "diff", "--vsys", "vsys1")
	if want := "new-secret: changed (not described by the schema; values not shown)"; !strings.Contains(text, want) {
		t.Errorf("missing %q in:\n%s", want, text)
	}
	for _, format := range []string{"text", "json", "yaml"} {
		if out := c.want(0, "snapshot", "diff", "--vsys", "vsys1", "--output", format); strings.Contains(out, "s3cr3t") {
			t.Errorf("%s output shows the value:\n%s", format, out)
		}
	}
	out, errOut, _ := c.run("lookup", "ldap-corp", "--file", "../../testdata/drift/undescribed.xml", "--output", "json")
	if strings.Contains(out+errOut, "s3cr3t") {
		t.Errorf("lookup shows the value:\n%s", out)
	}
	// An added object that holds an undescribed value has no short line: here
	// a zone's tag list, which the schema does not describe.
	d.Config = strings.Replace(read(t, "../../testdata/drift/before.xml"), "<zone>",
		`<zone><entry name="dmz"><tag><member>DUMMYTAGA</member><member>DUMMYTAGB</member></tag></entry>`, 1)
	c.want(0, "fetch", "fw01")
	for _, format := range []string{"text", "json", "yaml"} {
		if out := c.want(0, "snapshot", "diff", "--vsys", "vsys1", "--output", format); !strings.Contains(out, "dmz") || strings.Contains(out, "DUMMYTAG") {
			t.Errorf("%s output must name the zone and none of its tags:\n%s", format, out)
		}
	}
}

func TestSnapshotDiff(t *testing.T) {
	t.Parallel()
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
		"changed address       net-home\n      ip-netmask: 198.18.1.0/24 -> 198.18.2.0/24\n",
		"added   security rule new-rule", "vsys:vsys2 no changes",
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
	// A time that does not read is a usage error that names its flag.
	for _, flag := range []string{"--from", "--to"} {
		if _, errOut, code := c.run("snapshot", "diff", flag, "garbage"); code != exitUsage || !strings.Contains(errOut, flag+` "garbage": want a snapshot id`) {
			t.Errorf("%s garbage: exit %d, stderr %q", flag, code, errOut)
		}
	}
}

func TestSimulatePolicy(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	file := "../../testdata/config/firewall-zones.xml"
	out := c.want(0, "simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", file, "--vsys", "vsys1", "--why")
	for _, want := range []string{
		"zones      from inside, to dmz (configuration)", "fidelity   inferred; not evaluated: service",
		"derive-zones        inferred", "first-match         exact", "first match: from-inside (allow)",
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
	c.want(3, "simulate", "policy", "1.1.1.1", "2.2.2.2", "--file", file, "--vsys", "vsys9")
	out = c.want(0, "simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", file, "--from-zone", "dmz", "--to-zone", "inside")
	c.want(2, "simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", file, "--from-zone", "dmz")
	if !strings.Contains(out, "first match: interzone-default (deny), default rule (built-in)") {
		t.Errorf("no match, the default rule decides:\n%s", out)
	}
	out = c.want(0, "simulate", "policy", "10.1.0.5", "10.2.0.5", "--file", file,
		"--vsys", "vsys1", "--port", "tcp/443", "--output", "json")
	var env struct {
		Results []struct {
			FirstMatch *struct{ Name string } `json:"first_match"`
			Fidelity   struct{ Level string }
			Stages     []struct{ Slug string }
		}
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Results) != 1 || env.Results[0].FirstMatch == nil ||
		env.Results[0].FirstMatch.Name != "from-inside" || len(env.Results[0].Stages) != 10 || env.Results[0].Fidelity.Level == "" {
		t.Errorf("json: %v %s", err, out)
	}
}

// A file of another PAN-OS version decides as the 11.2 file does: no note, no
// unresolved entry, exit 0.
func TestSimulatePolicyOtherVersion(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../testdata/config/firewall-doubt.xml")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "doubt-12.2.xml")
	doc := strings.Replace(string(src), `version="11.2.0" urldb="paloaltonetworks" detail-version="11.2.5"`,
		`version="12.2.0" urldb="paloaltonetworks" detail-version="12.2.3"`, 1)
	if err := os.WriteFile(file, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newCLI(t)
	args := []string{"simulate", "policy", "198.18.1.68", "192.0.2.1", "--port", "udp/443", "--from-zone", "home", "--to-zone", "wan", "--file", file}
	out := c.want(0, args...)
	if strings.Contains(out, "note: ") || strings.Contains(out, "unresolved:") ||
		strings.Contains(out, "fidelity   inferred") || !strings.Contains(out, "first match: block-udp-443 (deny)") {
		t.Errorf("text:\n%s", out)
	}
	out = c.want(0, append(args, "--output", "json")...)
	var env struct {
		Unresolved []any
		Notes      []struct{ Text string }
		Results    []struct{ Verdict string }
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || len(env.Unresolved) != 0 || len(env.Notes) != 0 ||
		env.Results[0].Verdict != "stop" {
		t.Errorf("json: %v\n%s", err, out)
	}
}

// A URL and a port narrow the candidates; an FQDN resolves through DNS.
func TestSimulateDimensions(t *testing.T) {
	t.Parallel()
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
	// The fidelity line, one unresolved line, and the undecided line that the
	// undermatch causes.
	if strings.Count(out, "resolved to no address") != 3 || !strings.Contains(out, "undecided: www.example.com resolved to no address") {
		t.Errorf("an unresolved FQDN is an incomplete answer, said once, and undecided:\n%s", out)
	}
}

func TestSimulateResolvesAnFQDN(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	dir := t.TempDir()
	a := newApp(&out, &errOut, func(k string) string {
		return map[string]string{"PROTEUS_LOG_DIR": filepath.Join(dir, "log"), "PROTEUS_CONFIG": filepath.Join(dir, "none.yaml")}[k]
	}, time.Now)
	a.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
	}
	a.canonical = nil
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
	a.canonical = nil
	if code := a.execute(context.Background(), []string{
		"simulate", "policy", "10.0.0.1", "www.example.com",
		"--file", "../../testdata/config/firewall-simulate.xml",
	}); code != 3 {
		t.Errorf("a failed lookup leaves the FQDN unresolved: exit %d", code)
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want int
		msg  string
	}{
		{"complete", nil, 0, ""},
		{"an error", errors.New("boom"), 1, "boom"},
		{"a usage error", usageErr("bad flag"), 2, "bad flag"},
		{"an incomplete answer says nothing more", errIncomplete, 3, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := newApp(&bytes.Buffer{}, &bytes.Buffer{}, func(string) string { return "" }, time.Now)
			got, msg := a.exitCode(context.Background(), tc.err)
			var gotMsg string
			if msg != nil {
				gotMsg = msg.Error()
			}
			if got != tc.want || gotMsg != tc.msg {
				t.Errorf("exitCode(%v) = %d, %q; want %d, %q", tc.err, got, gotMsg, tc.want, tc.msg)
			}
		})
	}
	if (&exitErr{code: 3}).Error() != "exit 3" {
		t.Error("an exitErr without a message names its code")
	}
}

func TestAgo(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]string{45 * time.Minute: "45m", 3 * time.Hour: "3h", 72 * time.Hour: "3d"} {
		if got := ago(d); got != want {
			t.Errorf("ago(%v) = %s, want %s", d, got, want)
		}
	}
}

// identityFile copies the User-ID fixture configuration into a directory of
// the harness and returns its path; with data, the identity fixture lies
// beside it as identity.json.gz (spec 2026-10-17 §7).
func (c *cli) identityFile(data bool) string {
	c.t.Helper()
	dir, err := os.MkdirTemp(c.dir, "file-")
	if err != nil {
		c.t.Fatal(err)
	}
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, []byte(read(c.t, "../../testdata/config/firewall-identity.xml")), 0o600); err != nil {
		c.t.Fatal(err)
	}
	if data {
		testconfig.Identity(c.t, filepath.Join(dir, identity.FileName))
	}
	return path
}

// search --file reads identity.json.gz beside the configuration: carol
// reaches the rule of her XML API group, and the note names the file.
// Without the file, the group is unknown.
func TestSearchWithTheIdentityFile(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	if out := c.want(0, "search", `example.com\carol`, "--file", c.identityFile(false)); strings.Contains(out, "u-xmlapi") {
		t.Errorf("without the identity file carol reaches nothing:\n%s", out)
	}
	file := c.identityFile(true)
	out := c.want(0, "search", `example.com\carol`, "--file", file)
	if !strings.Contains(out, "u-xmlapi") || !strings.Contains(out, filepath.Join(filepath.Dir(file), identity.FileName)) {
		t.Errorf("with the identity file carol reaches u-xmlapi:\n%s", out)
	}
}

// Every run writes a log with its command, settings, snapshots and exit; a run that
// ends badly prints where the log is.
func TestRunLog(t *testing.T) {
	t.Parallel()
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
	for _, want := range []string{"[INFO] [RUN] setting log-level=info from default", "[INFO] [SNAP] fw01: snapshot", "[WARN] [SNAP] fw01/vsys9: hole", "[WARN] [RUN] the answer is incomplete", "[INFO] [RUN] exit 3"} {
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// A misspelt --kind is a usage error that lists the kinds, not an empty answer.
func TestSearchRefusesAnUnknownKind(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	out, errOut, code := c.run("search", "web", "--kind", "addr", "--file", "../../testdata/config/firewall-lab.xml")
	if code != 2 || out != "" || !strings.Contains(errOut, `--kind "addr": did you mean address, address-group?`) ||
		!strings.Contains(errOut, "\nknown kinds: address, address-group") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	c.want(0, "search", "web", "--kind", "address-group", "--file", "../../testdata/config/firewall-lab.xml")
}

// A fan-out cancelled while one device hangs returns at once with the other
// device stored, and TestMain's leak check proves no goroutine is left behind.
func TestACancelledFanOutEndsPromptly(t *testing.T) {
	t.Parallel()
	for _, stall := range []string{fakepanos.RunningConfigCmd, fakepanos.PushedTemplateCmd} {
		t.Run(stall, func(t *testing.T) {
			t.Parallel()
			hung := lab(t)
			hung.Stall = stall
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
			start := time.Now()
			out, err := fetchText(ctx, fetcher{inv: inv, st: st, getenv: getenv}, "fw01", "fw02")
			if elapsed := time.Since(start); elapsed > 20*time.Second {
				t.Fatalf("the fan-out took %s after its context ended", elapsed)
			}
			if !errors.Is(err, errIncomplete) {
				t.Errorf("one device stored and one cancelled is an incomplete fetch, got %v\n%s", err, out)
			}
			if _, err := st.Latest("fw01"); err != nil {
				t.Errorf("the device that answered must be stored: %v", err)
			}
		})
	}
}

// A failed login is in the answer once and on stderr not at all (spec §4.5).
func TestAFailedFetchPrintsOnce(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor("127.0.0.1:1"))
	out, errOut, code := c.run("fetch", "fw01")
	if code != exitError || strings.Count(out, "fw01/login") != 1 || strings.Contains(errOut, "fw01/login") ||
		!strings.Contains(errOut, "no device was fetched") || strings.Contains(out, "fw01: fw01") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
}

func TestFetchAnUnknownNameIsAUsageError(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	c.want(2, "fetch", "fw09")
}

// --fresh keeps what the fetch found, as target notes (spec §6.3).
func TestFreshFetchFindingsAreNotes(t *testing.T) {
	t.Parallel()
	d := lab(t)
	c := newCLI(t)
	c.inventory(inventoryFor(d.Start(t)))
	c.want(0, "fetch", "fw01")
	delete(d.Ops, "<show><interface>all</interface></show>")
	out := c.want(0, "search", "198.18.10.100", "--fresh", "--output", "json")
	for _, want := range []string{"TLS certificate verification is off (insecure_tls)", "fresh fetch: interfaces failed"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing note %q:\n%s", want, out)
		}
	}
}

func TestFetchWhyShowsTheStages(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	out := c.want(0, "fetch", "fw01", "--why")
	for _, slug := range []string{"resolve", "login", "ha", "documents", "template", "applications", "identity", "store"} {
		if !strings.Contains(out, "  "+slug+" ") {
			t.Errorf("missing stage %s:\n%s", slug, out)
		}
	}
	// The command's help lists the stages in the order they run.
	if long := newApp(nil, nil, getenv, nil).fetchCmd().Long; !strings.Contains(long, "documents, template, applications, identity, store") {
		t.Errorf("fetch help: %s", long)
	}
}

// Once the context is done no device starts, and each one named is still in the
// answer, so none drops silently.
func TestAnInterruptedFetchListsEveryDevice(t *testing.T) {
	t.Parallel()
	inv, st := setup(t, lab(t).Start(t))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := (fetcher{inv: inv, st: st, getenv: getenv}).each(ctx, []string{"fw01"})
	if len(res) != 1 || res[0].Stored || res[0].Error != "fw01: not started: interrupted" {
		t.Errorf("results = %+v", res)
	}
}

// fetchNotes is the top-level notes of fetch's JSON envelope.
func fetchNotes(t *testing.T, out string) []note {
	t.Helper()
	var env struct {
		Notes []note `json:"notes"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	return env.Notes
}

// Every note the text shows is in the envelope's notes too (spec §3.2): TLS
// verification off, and an HA state that was not followed.
func TestFetchNotesReachTheEnvelope(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	if got := fetchNotes(t, c.want(0, "fetch", "fw01", "--output", "json")); !slices.Contains(got, note{Device: "fw01", Code: "note.tls-off", Note: tlsOff().Text}) {
		t.Errorf("a lab fetch has the TLS note, got %+v", got)
	}

	haCmd := "<show><high-availability><state/></high-availability></show>"
	d := lab(t)
	d.Ops[haCmd] = fakepanos.Success(`<enabled>yes</enabled><group><mode>active-passive</mode><local-info><state>passive` +
		`</state><serial-num>A</serial-num></local-info><peer-info><state>suspended</state><serial-num>B</serial-num>` +
		`<mgmt-ip>192.0.2.2</mgmt-ip></peer-info></group>`)
	c = newCLI(t)
	c.inventory(inventoryFor(d.Start(t)))
	got := fetchNotes(t, c.want(0, "fetch", "fw01", "--output", "json"))
	if !slices.ContainsFunc(got, func(n note) bool {
		return n.Device == "fw01" && strings.Contains(n.Note, `passive, but the peer is "suspended"`)
	}) {
		t.Errorf("the HA note is missing from the envelope: %+v", got)
	}
}

// A selection that matches no device is a command line to change (spec §4.1).
func TestFetchAnEmptySelectionIsAUsageError(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	if _, errOut, code := c.run("fetch", "--label", "site=nowhere"); code != exitUsage || !strings.Contains(errOut, "matches no device") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

// A failed device's error colours where it failed, not the whole line (spec §9.3).
func TestFailedDeviceColoursItsPrefix(t *testing.T) {
	t.Parallel()
	p := palette{on: true}
	if got, want := failedDevice(p, "fw01/login: refused"), p.bad("fw01/login")+": refused"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := failedDevice(p, "gone"); got != p.bad("gone") {
		t.Errorf("an error without a prefix is coloured whole, got %q", got)
	}
}

// exporting turns on export_inventory in an inventory of inventoryFor.
func exporting(doc string) string {
	return strings.Replace(doc, "defaults:\n", "defaults:\n  export_inventory: true\n", 1)
}

// With export_inventory, every fetch run writes the inventory without
// credentials into the store, a failed run too (spec 2026-10-09 §5).
func TestFetchExportsTheInventory(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	path := inventory.ExportPath(c.env["PROTEUS_STORE"])
	c.inventory(inventoryFor(lab(t).Start(t)))
	c.want(0, "fetch", "fw01")
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no export without the setting: %v", err)
	}

	c.inventory(exporting(inventoryFor(lab(t).Start(t))))
	c.want(0, "fetch", "fw01")
	b := read(t, path)
	if strings.Contains(b, "reader") || strings.Contains(b, "LAB_PW") || !strings.Contains(b, "name: fw01") {
		t.Errorf("export:\n%s", b)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("export mode: %v, %v", fi, err)
	}
	if inv, err := inventory.ReadExport(path); err != nil || !slices.Equal(inv.Names(), []string{"fw01"}) {
		t.Errorf("ReadExport = %+v, %v", inv, err)
	}

	// A run whose every device fails still exports the inventory it read.
	c.inventory(exporting(inventoryFor("127.0.0.1:1", "127.0.0.1:1")))
	c.want(exitError, "fetch", "--all")
	if inv, err := inventory.ReadExport(path); err != nil || !slices.Equal(inv.Names(), []string{"fw01", "fw02"}) {
		t.Errorf("after a failed run: %+v, %v", inv, err)
	}
}

// An export that cannot be written leaves the fetch rules in place (C11):
// a complete run becomes incomplete with a coded note, an incomplete run stays
// incomplete, and a run that stored nothing stays an error.
func TestAFailedExportMakesTheFetchIncomplete(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		hosts  func(t *testing.T) []string
		args   []string
		code   int
		stored bool
	}{
		{"all stored", func(t *testing.T) []string { return []string{lab(t).Start(t)} }, []string{"fw01"}, exitIncomplete, true},
		{"some stored", func(t *testing.T) []string { return []string{lab(t).Start(t), "127.0.0.1:1"} }, []string{"--all"}, exitIncomplete, true},
		{"none stored", func(*testing.T) []string { return []string{"127.0.0.1:1"} }, []string{"fw01"}, exitError, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := newCLI(t)
			c.inventory(exporting(inventoryFor(tc.hosts(t)...)))
			// A directory where the export goes: the rename fails.
			if err := os.MkdirAll(filepath.Join(inventory.ExportPath(c.env["PROTEUS_STORE"]), "x"), 0o700); err != nil {
				t.Fatal(err)
			}
			out, errOut, code := c.run(append([]string{"fetch"}, tc.args...)...)
			if code != tc.code || !strings.Contains(out, "note: inventory export") || strings.Contains(out, "stored fw01@") != tc.stored {
				t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
			}
			if !tc.stored && !strings.Contains(errOut, "no device was fetched") {
				t.Errorf("stderr:\n%s", errOut)
			}
			out, _, _ = c.run(append([]string{"fetch", "--output", "json"}, tc.args...)...)
			if !strings.Contains(out, `"code": "note.export-failed"`) {
				t.Errorf("json:\n%s", out)
			}
		})
	}
}

// contentFiles lists the files in the store's content directory.
func contentFiles(t *testing.T, c *cli) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(c.env["PROTEUS_STORE"], store.ContentDir))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// metaJSON is a device's latest snapshot and its raw meta.json.
func metaJSON(t *testing.T, c *cli, device string) (store.Snapshot, string) {
	t.Helper()
	sn, err := store.At(c.env["PROTEUS_STORE"]).Latest(device)
	if err != nil {
		t.Fatal(err)
	}
	return sn, read(t, filepath.Join(sn.Dir, "meta.json"))
}

// Two devices of one content version share one content file, and each snapshot
// names it. A later fetch reuses it without asking the device (spec 2026-10-16
// §3.1, §2.2).
func TestFetchStoresContentOnce(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	d1, d2 := lab(t), lab(t)
	c.inventory(inventoryFor(d1.Start(t), d2.Start(t)))
	c.want(0, "fetch", "--all")
	if got := contentFiles(t, c); !slices.Equal(got, []string{"8000-1000.v1.xml.gz"}) {
		t.Errorf("content files = %v", got)
	}
	for _, dev := range []string{"fw01", "fw02"} {
		if sn, _ := metaJSON(t, c, dev); sn.Meta.AppVersion != "8000-1000" || sn.ContentPath() == "" {
			t.Errorf("%s: meta = %+v", dev, sn.Meta)
		}
	}
	before := len(d1.Requests())
	c.want(0, "fetch", "fw01")
	for _, r := range d1.Requests()[before:] {
		if r.Cmd == fakepanos.ApplicationsCmd || r.Cmd == fakepanos.ContainersCmd {
			t.Errorf("a stored content file was fetched again: %s", r.Cmd)
		}
	}
	if sn, _ := metaJSON(t, c, "fw01"); sn.Meta.AppVersion != "8000-1000" {
		t.Errorf("a hit names the file too: %+v", sn.Meta)
	}
}

// A device that refuses its application data is stored without app_version,
// and the fetch is complete (spec 2026-10-16 §3.1).
func TestFetchRefusedLeavesAppVersionEmpty(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	d := lab(t)
	d.Ops[fakepanos.ApplicationsCmd] = fakepanos.Refusal("17", "show -> application is unexpected")
	c.inventory(inventoryFor(d.Start(t)))
	out := c.want(0, "fetch", "fw01", "--output", "json")
	if _, raw := metaJSON(t, c, "fw01"); strings.Contains(raw, "app_version") {
		t.Errorf("meta.json:\n%s", raw)
	}
	if !slices.ContainsFunc(fetchNotes(t, out), func(n note) bool { return n.Code == "note.fetch-applications-missing" }) {
		t.Errorf("no note:\n%s", out)
	}
}

// A content file that cannot be written leaves the snapshot without
// app_version, adds the note with the cause and makes the run incomplete
// (spec 2026-10-16 §3.1). The prune of the same run fails, and the run goes on.
func TestFetchContentWriteFailureIsANote(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	root := c.env["PROTEUS_STORE"]
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, store.ContentDir), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := c.want(exitIncomplete, "fetch", "fw01", "--output", "json")
	sn, raw := metaJSON(t, c, "fw01")
	if sn.ID == "" || strings.Contains(raw, "app_version") || !strings.Contains(raw, "application data") {
		t.Errorf("meta.json:\n%s", raw)
	}
	if !slices.ContainsFunc(fetchNotes(t, out), func(n note) bool {
		return n.Code == "note.fetch-applications-missing" && strings.Contains(n.Note, "not a directory")
	}) {
		t.Errorf("no note with the cause:\n%s", out)
	}
	if !strings.Contains(out, `"slug": "store",
          "name": "store the snapshot",
          "status": "partial"`) {
		t.Errorf("the store stage must be partial:\n%s", out)
	}
	if !strings.Contains(c.logFile(), "pruning the content files") {
		t.Errorf("the failed prune is not logged:\n%s", c.logFile())
	}
}

// One prune per run, after every device, removes an old file that no snapshot
// names (spec 2026-10-16 §3.4).
func TestFetchPrunesContentOnce(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t), lab(t).Start(t)))
	dir := filepath.Join(c.env["PROTEUS_STORE"], store.ContentDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "7000-0001.v1.xml.gz")
	if err := os.WriteFile(old, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	then := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, then, then); err != nil {
		t.Fatal(err)
	}
	c.want(0, "fetch", "--all", "--log-level", "debug")
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the old file is still there: %v", err)
	}
	if got := contentFiles(t, c); !slices.Equal(got, []string{"8000-1000.v1.xml.gz"}) {
		t.Errorf("content files = %v", got)
	}
	if n := strings.Count(c.logFile(), "pruned the content files"); n != 1 {
		t.Errorf("pruned %d times:\n%s", n, c.logFile())
	}
}

// The snapshot keeps the identity data of the device as identity.json.gz,
// mode 0600, and meta.json says so (spec 2026-10-17 §4.1).
func TestFetchStoresTheIdentityFile(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	c.want(0, "fetch", "fw01")
	sn, raw := metaJSON(t, c, "fw01")
	fi, err := os.Stat(sn.IdentityPath())
	if err != nil || fi.Mode().Perm() != 0o600 || filepath.Base(sn.IdentityPath()) != identity.FileName {
		t.Fatalf("identity file: %v, %v", fi, err)
	}
	if !strings.Contains(raw, `"identity": true`) {
		t.Errorf("meta.json:\n%s", raw)
	}
	d, err := identity.Load(sn.IdentityPath())
	if err != nil || d.Counts().Users != 4 || len(d.PartsMissing()) != 0 {
		t.Errorf("identity data %+v, %v", d, err)
	}
}

// identity: false on a device keeps the identity data out of its snapshot:
// no file, no key in meta.json, a note, and the fetch is complete (spec
// 2026-10-17 D4).
func TestFetchWithIdentityOffStoresNoFile(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(strings.Replace(inventoryFor(lab(t).Start(t)), "    labels: {site: s1}\n", "    labels: {site: s1}\n    identity: false\n", 1))
	out := c.want(0, "fetch", "fw01", "--output", "json")
	sn, raw := metaJSON(t, c, "fw01")
	if _, err := os.Stat(filepath.Join(sn.Dir, identity.FileName)); !errors.Is(err, os.ErrNotExist) || sn.IdentityPath() != "" || strings.Contains(raw, `"identity"`) {
		t.Errorf("identity file: %v\nmeta.json:\n%s", err, raw)
	}
	if !slices.ContainsFunc(fetchNotes(t, out), func(n note) bool { return n.Code == "note.identity-off" }) {
		t.Errorf("no note:\n%s", out)
	}
}

// A transport error while the identity data arrives stores the snapshot
// without the file, and the fetch exits 3 (spec 2026-10-17 §3.4, PD4).
func TestFetchIdentityTransportFailureExits3(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	d := lab(t)
	d.DropCmd = map[string]int{fakepanos.UserIDsCmd: 2}
	c.inventory(inventoryFor(d.Start(t)))
	out := c.want(exitIncomplete, "fetch", "fw01")
	sn, raw := metaJSON(t, c, "fw01")
	if _, err := os.Stat(filepath.Join(sn.Dir, identity.FileName)); !errors.Is(err, os.ErrNotExist) || sn.IdentityPath() != "" || strings.Contains(raw, `"identity": true`) {
		t.Errorf("identity file: %v\nmeta.json:\n%s", err, raw)
	}
	if !strings.Contains(out, "identity") || !strings.Contains(out, "FAILED") || !strings.Contains(raw, `"name": "identity"`) {
		t.Errorf("the failed identity data must be named:\n%s\nmeta.json:\n%s", out, raw)
	}
}
