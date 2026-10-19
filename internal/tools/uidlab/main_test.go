package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/tools/labkit"
)

// TestMain makes the test binary a fake proteus when the tool runs it: the
// tool sets PROTEUS_STORE, and the first argument is a proteus command.
func TestMain(m *testing.M) {
	if os.Getenv("PROTEUS_STORE") != "" && len(os.Args) > 1 && slices.Contains([]string{"fetch", "simulate", "lookup", "search"}, os.Args[1]) {
		os.Exit(fakeProteus(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeProteus answers fetch with a snapshot in the shape of internal/store,
// and simulate, lookup and search with the answers of the fake device. Each
// answer names the temporary directories of the tool in "trace", so a test
// can check that the tool removed them.
func fakeProteus(args []string) int {
	st := os.Getenv("PROTEUS_STORE")
	logDir := os.Getenv("PROTEUS_LOG_DIR")
	if args[0] == "fetch" {
		return fakeFetch(st, args[1])
	}
	file := args[slices.Index(args, "--file")+1]
	trace := fmt.Sprintf(`"trace":{"store":%q,"log":%q,"copy":%q}`, st, logDir, filepath.Dir(file))
	switch args[0] {
	case "simulate":
		fmt.Printf(`{%s,"results":[{"verdict":"pass","rule":"uid-lab-user","default":"","fidelity":{"level":"exact"},`+
			`"first_match":{"name":"uid-lab-user","action":"allow"}}],"notes":[]}`+"\n", trace)
	case "lookup":
		if slices.Contains(args, "identity-group") {
			fmt.Printf(`{%s,"results":[{"card":{"kind":"identity-group","name":"g","sections":[`+
				`{"title":"source","rows":[{"text":"ldap:example.com"}]},`+
				`{"title":"members","rows":[{"text":"3 members"},{"items":[{"name":"example.com\\alice"},{"name":"example.com\\bob"},{"name":"example.com\\carol"}]}]}]}}]}`+"\n", trace)
			break
		}
		fmt.Printf(`{%s,"results":[{"card":{"kind":"identity-user","name":"example.com\\alice","sections":[`+
			`{"title":"primary","rows":[{"text":"example.com\\alice"}]},`+
			`{"title":"alternate names","rows":[{"items":[{"name":"Alice@example.com"},{"name":"example.com\\alice"}]}]},`+
			`{"title":"email","rows":[{"text":"alice@example.com"}]},`+
			`{"title":"groups","rows":[{"items":[{"name":"cn=domain users,cn=users,dc=example,dc=com"},{"name":"engineering"},{"name":"dug-a"},{"name":"dug-ab"},{"name":"custom-a"}]}]}]}}]}`+"\n", trace)
	case "search":
		fmt.Printf(`{%s,"results":[{"kind":"mapping","name":"198.51.100.11","via":"user example.com\\alice, XMLAPI, timeout 14400 s"}]}`+"\n", trace)
	}
	return 0
}

// fakeFetch writes a snapshot of device into the store at st: a partial
// fetch (exit 3) of fw-test, a snapshot without identity data for fw-noid,
// one with tags missing for fw-missing, one with a partial mapping table for
// fw-partial, and a failure for fw-broken.
func fakeFetch(st, device string) int {
	if device == "fw-broken" {
		return 1
	}
	id := "2026-10-18T10-00-00Z"
	dir := filepath.Join(st, device, id)
	f := identity.File{Format: identity.Format}
	switch device {
	case "fw-missing":
		f.PartsMissing = []string{identity.PartTags}
	case "fw-partial":
		f.MappingsPartial = true
	}
	var gz bytes.Buffer
	if err := identity.Encode(&gz, f); err != nil {
		return 1
	}
	meta := fmt.Sprintf(`{"device":%q,"documents":[],"identity":%t}`, device, device != "fw-noid")
	for p, s := range map[string]string{
		filepath.Join(dir, "config.xml"):      "<config/>",
		filepath.Join(dir, "predefined.xml"):  "<predefined/>",
		filepath.Join(dir, "meta.json"):       meta,
		filepath.Join(dir, identity.FileName): gz.String(),
	} {
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p, []byte(s), 0o600)
	}
	_ = os.Symlink(id, filepath.Join(st, device, "latest"))
	return 3 // a partial fetch: the tool goes on when the identity data is whole
}

// The answers of the fake device, keyed by a part of the command.
const (
	policyRule  = `<response status="success"><result><rules><entry name='uid-lab-user'><action>allow</action></entry></rules></result></response>`
	policyOther = `<response status="success"><result><rules><entry name='uid-lab-catch'><action>deny</action></entry></rules></result></response>`
)

// fakeDevice is a fake lab device: it answers each command and counts the
// policy commands. policy gives the answer of the n-th policy command.
type fakeDevice struct {
	mu       sync.Mutex
	calls    int
	policies int
	policy   func(n int) string
}

func (d *fakeDevice) serve(t *testing.T) http.HandlerFunc {
	ids := func(name string) string { return string(identityAnswer(t, name)) }
	return func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.calls++
		cmd := r.FormValue("cmd")
		if r.Header.Get("X-PAN-KEY") != "dummy-key" || strings.Contains(r.URL.String(), "dummy-key") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case strings.HasPrefix(cmd, "<test>"):
			d.policies++
			fmt.Fprint(w, d.policy(d.policies))
		case strings.Contains(cmd, "<user-attributes>"):
			fmt.Fprint(w, u8Alice)
		case strings.Contains(cmd, "<match-user>"):
			fmt.Fprint(w, ids("answer-user-ids-match.xml"))
		case strings.Contains(cmd, "<ip-user-mapping-mp>"):
			fmt.Fprint(w, ids("answer-mapping-ip.xml"))
		case strings.Contains(cmd, "<group>"):
			fmt.Fprint(w, ids("answer-group-name.xml"))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func (d *fakeDevice) counts() (calls, policies int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, d.policies
}

// fourFlows is a flow list with one flow of each check.
const fourFlows = header +
	"pol\tM1\tpolicy\t${ZONE_FROM}\t${ZONE_TO}\t${IP_U}\t192.0.2.10\t${USER_A}\t-\t-\n" +
	"usr\tN5\tuser\t-\t-\t-\t-\t${USER_A}\t${UPN_A}\t-\n" +
	"adr\tN4\tip\t-\t-\t-\t-\t-\t${IP_A}\t-\n" +
	"grp\tU4\tgroup\t-\t-\t-\t-\t-\t${GROUP_DN}\t-\n"

// labSetup writes an inventory for the fake device, the flow list, the
// variables file and the key header file, and returns the flags.
func labSetup(t *testing.T, d *fakeDevice, name, flows string) []string {
	t.Helper()
	srv := httptest.NewTLSServer(d.serve(t))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	write := func(file, s string) string {
		p := filepath.Join(dir, file)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inv := write("config.yaml", "version: 1\ndefaults:\n  insecure_tls: true\ndevices:\n"+
		"  - {name: "+name+", host: "+strings.TrimPrefix(srv.URL, "https://")+", username: u, password: dummy}\n"+
		"  - {name: fw-broken, host: "+strings.TrimPrefix(srv.URL, "https://")+", username: u, password: dummy}\n")
	vars := write("lab.vars", "ZONE_FROM=zone-a\nZONE_TO=zone-b\nIP_U=198.51.100.99\nIP_A=198.51.100.11\n"+
		"USER_A=example.com\\alice\nUPN_A=alice@example.com\nGROUP_DN=cn=domain users,cn=users,dc=example,dc=com\n"+
		"USER_X=example.com\\xavier\n")
	login := write("login.xml", `<uid-message><version>2.0</version><type>update</type><payload>`+
		`<groups><entry name="uid-lab-xmlapi"><members><entry name="${USER_X}"/><entry name="other\ghost"/></members></entry></groups>`+
		`</payload></uid-message>`)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		"-device", name, "-config", inv, "-flows", write("flows.tsv", flows), "-vars", vars, "-login", login,
		"-key-header", write("key", "X-PAN-KEY: dummy-key\n"), "-proteus", self,
		"-out", filepath.Join(dir, "out"), "-settle", "0", "-retry-wait", "0",
	}
}

// writeFile writes a file into dir and returns its path.
func writeFile(t *testing.T, dir, name, s string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// flagValue returns the value of a flag in args.
func flagValue(args []string, name string) string { return args[slices.Index(args, name)+1] }

// gone fails when a temporary directory of the trace in a proteus answer is
// still there.
func gone(t *testing.T, answer string) {
	t.Helper()
	b, err := os.ReadFile(answer)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Trace map[string]string `json:"trace"`
	}
	if err := json.Unmarshal(b, &out); err != nil || len(out.Trace) != 3 {
		t.Fatalf("no trace in %s: %v", answer, err)
	}
	for what, dir := range out.Trace {
		if dir == "" {
			t.Errorf("the %s directory is not set", what)
		} else if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the temporary %s directory %s is still there: %v", what, dir, err)
		}
	}
}

func TestRunComparesAndCleansUp(t *testing.T) {
	t.Parallel()
	d := &fakeDevice{policy: func(int) string { return policyRule }}
	args := labSetup(t, d, "fw-test", fourFlows)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "all 4 flows agree") || strings.Contains(stdout.String()+stderr.String(), "dummy-key") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}
	out := flagValue(args, "-out")
	for _, name := range []string{"pol.try-1.device-1.xml", "pol.proteus.json", "usr.try-1.device-1.xml", "usr.try-1.device-2.xml", "adr.try-1.device-1.xml", "grp.proteus.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Error(err)
		}
	}
	gone(t, filepath.Join(out, "pol.proteus.json"))
	if calls, policies := d.counts(); calls != 5 || policies != 1 {
		t.Errorf("the device got %d commands, %d of them policy tests; want 5 and 1", calls, policies)
	}
}

func TestRunStopsOnMissingParts(t *testing.T) {
	t.Parallel()
	for device, want := range map[string]string{
		"fw-missing": identity.PartTags,
		"fw-partial": identity.PartMappings,
		"fw-noid":    "no identity data",
	} {
		d := &fakeDevice{policy: func(int) string { return policyRule }}
		args := labSetup(t, d, device, fourFlows)
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), want) {
			t.Errorf("%s: exit %d, stderr:\n%s", device, code, stderr.String())
		}
		if calls, _ := d.counts(); calls != 0 {
			t.Errorf("%s: the device got %d commands before the stop", device, calls)
		}
	}
}

func TestRunRetriesADifferingPolicyFlow(t *testing.T) {
	t.Parallel()
	policyOnly := strings.Join(strings.Split(fourFlows, "\n")[:2], "\n") + "\n"
	// The device keeps its earlier answer for a while after a User-ID
	// message (M18): the second try agrees.
	d := &fakeDevice{policy: func(n int) string {
		if n == 1 {
			return policyOther
		}
		return policyRule
	}}
	var stdout, stderr bytes.Buffer
	if code := run(labSetup(t, d, "fw-test", policyOnly), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "ok after 2 tries") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if _, policies := d.counts(); policies != 2 {
		t.Errorf("%d tries, want 2", policies)
	}
	// Each try keeps its device answer (M18).
	out := t.TempDir()
	d = &fakeDevice{policy: func(n int) string { return map[bool]string{true: policyOther, false: policyRule}[n == 1] }}
	args := labSetup(t, d, "fw-test", policyOnly)
	args[slices.Index(args, "-out")+1] = out
	if code := run(args, io.Discard, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for try, want := range map[int]string{1: "uid-lab-catch", 2: "uid-lab-user"} {
		b, err := os.ReadFile(filepath.Join(out, fmt.Sprintf("pol.try-%d.device-1.xml", try)))
		if err != nil || !strings.Contains(string(b), want) {
			t.Errorf("try %d: %q, %v", try, b, err)
		}
	}
	// Three tries that differ are a difference.
	d = &fakeDevice{policy: func(int) string { return policyOther }}
	stdout.Reset()
	stderr.Reset()
	if code := run(labSetup(t, d, "fw-test", policyOnly), &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "1 of 1 flows differ") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if _, policies := d.counts(); policies != 3 {
		t.Errorf("%d tries, want 3", policies)
	}
	// A flow whose answer does not depend on the device is tried once: a
	// mark that records the device answer only, and an undecided proteus.
	for _, row := range []string{
		"pol\tM4\tpolicy\t${ZONE_FROM}\t${ZONE_TO}\t${IP_U}\t192.0.2.17\t-\t-\tunknown-inferred\n",
		"pol\tD1\tpolicy\t${ZONE_FROM}\t${ZONE_TO}\t${IP_U}\t192.0.2.29\t${USER_A}\t-\tdoubt\n",
	} {
		d = &fakeDevice{policy: func(int) string { return policyOther }}
		_ = run(labSetup(t, d, "fw-test", header+row), io.Discard, io.Discard)
		if _, policies := d.counts(); policies != 1 {
			t.Errorf("%q: %d tries, want 1", row, policies)
		}
	}
}

func TestRunRenders(t *testing.T) {
	t.Parallel()
	d := &fakeDevice{policy: func(int) string { return policyRule }}
	args := labSetup(t, d, "fw-test", fourFlows)
	file := filepath.Join(t.TempDir(), "login.xml")
	if err := os.WriteFile(file, []byte(`<entry name="${UPN_A}" ip="${IP_A}" timeout="240"/>`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(append(args, "-render", file), &stdout, &stderr); code != 0 ||
		stdout.String() != `<entry name="alice@example.com" ip="198.51.100.11" timeout="240"/>`+"\n" {
		t.Errorf("exit %d: %q %q", code, stdout.String(), stderr.String())
	}
	if calls, _ := d.counts(); calls != 0 {
		t.Errorf("-render sent %d commands to the device", calls)
	}
	// An unknown placeholder is an error that names it.
	if err := os.WriteFile(file, []byte("${NOPE}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run(append(args, "-render", file), io.Discard, &stderr); code != 1 || !strings.Contains(stderr.String(), "NOPE in "+flagValue(args, "-vars")) {
		t.Errorf("exit %d: %q", code, stderr.String())
	}
}

func TestRunStopsOnForbidden(t *testing.T) {
	t.Parallel()
	d := &fakeDevice{policy: func(int) string { return policyRule }}
	args := labSetup(t, d, "fw-test", fourFlows)
	key := flagValue(args, "-key-header")
	if err := os.WriteFile(key, []byte("X-PAN-KEY: wrong-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "403") {
		t.Errorf("exit %d\nstderr:\n%s", code, stderr.String())
	}
	gone(t, filepath.Join(flagValue(args, "-out"), "pol.proteus.json"))
}

func TestRunRefusesBadInput(t *testing.T) {
	t.Parallel()
	d := &fakeDevice{policy: func(int) string { return policyRule }}
	good := labSetup(t, d, "fw-test", fourFlows)
	set := func(name, value string) []string {
		args := slices.Clone(good)
		args[slices.Index(args, name)+1] = value
		return args
	}
	dir := t.TempDir()
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"bad flag":          {[]string{"-nope"}, ""},
		"no device":         {set("-device", ""), "name the lab device"},
		"unknown device":    {set("-device", "fw-none"), "no device named"},
		"broken fetch":      {set("-device", "fw-broken"), "proteus fetch fw-broken"},
		"no key header":     {set("-key-header", ""), "key header file"},
		"bad key file":      {set("-key-header", flagValue(good, "-vars")), "one line"},
		"missing flows":     {set("-flows", filepath.Join(dir, "none")), "no such file"},
		"bad flows":         {set("-flows", flagValue(good, "-vars")), "header"},
		"out in the repo":   {set("-out", "."), "inside the repository"},
		"missing inventory": {set("-config", filepath.Join(dir, "none")), "inventory"},
		"render missing":    {append(slices.Clone(good), "-render", filepath.Join(dir, "none")), "no such file"},
		"bad vars":          {set("-vars", flagValue(good, "-key-header")), "variables"},
		"missing login":     {set("-login", filepath.Join(dir, "none")), "no such file"},
		"bad login":         {set("-login", flagValue(good, "-vars")), "login file"},
		"unfilled flows":    {set("-vars", filepath.Join(dir, "none")), "in " + filepath.Join(dir, "none")},
		// U18: a user check that names a member of the lab XML API group.
		"xmlapi member": {set("-flows", writeFile(t, dir, "x.tsv", header+
			"usr\tN5\tuser\t-\t-\t-\t-\t${USER_X}\tx@example.com\t-\n")), "member of the lab XML API group"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(c.args, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr.String())
		}
	}
}

// fakeOps answers each op command from a function.
type fakeOps func(cmd string) ([]byte, error)

func (f fakeOps) Op(_ context.Context, cmd string) ([]byte, error) {
	if err := labkit.CheckOp(cmd); err != nil {
		return nil, err
	}
	return f(cmd)
}

func TestCheckFlows(t *testing.T) {
	t.Parallel()
	flows := []Flow{
		{Case: "pol", Fact: "M1", Check: "policy", From: "a", To: "b", Source: "s", Destination: "d"},
		{Case: "adr", Fact: "N4", Check: "ip", Subject: "198.51.100.11"},
	}
	agree := func(_ context.Context, args []string) ([]byte, []byte, int, error) {
		if args[0] == "search" {
			return []byte(`{"results":[{"kind":"mapping","name":"198.51.100.11","via":"user example.com\\alice, XMLAPI, timeout 14400 s"}]}`), nil, 0, nil
		}
		return []byte(`{"results":[{"verdict":"pass","rule":"uid-lab-user","first_match":{"name":"uid-lab-user","action":"allow"}}]}`), nil, 0, nil
	}
	ok := fakeOps(func(cmd string) ([]byte, error) {
		if strings.HasPrefix(cmd, "<test>") {
			return []byte(policyRule), nil
		}
		return identityAnswer(t, "answer-mapping-ip.xml"), nil
	})
	check := func(dev opSender, run proteusRunner, flows []Flow) (int, string, error) {
		var w bytes.Buffer
		n, err := checkFlows(context.Background(), &w, t.TempDir(), dev, run, flows, "config.xml", "vsys1", 0)
		return n, w.String(), err
	}
	if n, out, err := check(ok, agree, flows); err != nil || n != 0 || strings.Count(out, " ok") != 2 {
		t.Errorf("agree: %d, %v\n%s", n, err, out)
	}
	// A device error counts as a difference, and the run goes on.
	reset := fakeOps(func(string) ([]byte, error) { return nil, errors.New("reset") })
	if n, out, err := check(reset, agree, flows); err != nil || n != 2 || !strings.Contains(out, "DIFF: device: reset") {
		t.Errorf("device error: %d, %v\n%s", n, err, out)
	}
	// A proteus error is a difference, without a retry.
	failing := func(context.Context, []string) ([]byte, []byte, int, error) {
		return nil, []byte(`{"format":2,"exit":1,"error":"boom"}`), 1, nil
	}
	if n, out, err := check(ok, failing, flows[:1]); err != nil || n != 1 || !strings.Contains(out, "boom") {
		t.Errorf("proteus error: %d, %v\n%s", n, err, out)
	}
	// A 403 stops the run.
	forbidden := fakeOps(func(string) ([]byte, error) { return nil, labkit.ErrForbidden })
	if _, _, err := check(forbidden, agree, flows); !errors.Is(err, labkit.ErrForbidden) {
		t.Errorf("403: %v", err)
	}
	// A proteus that cannot start stops the run.
	broken := func(context.Context, []string) ([]byte, []byte, int, error) {
		return nil, nil, 0, errors.New("no binary")
	}
	if _, _, err := check(ok, broken, flows); err == nil {
		t.Error("a proteus that cannot start gave no error")
	}
	// A cancelled run stops, also during the wait before a retry.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := checkFlows(ctx, io.Discard, t.TempDir(), ok, agree, flows, "c", "vsys1", 0); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
	differ := fakeOps(func(string) ([]byte, error) { return []byte(policyOther), nil })
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := checkFlows(ctx, io.Discard, t.TempDir(), differ, agree, flows[:1], "c", "vsys1", time.Hour); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("cancelled in the wait: %v", err)
	}
}
