package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestMain makes the test binary a fake proteus when the tool runs it: the
// tool sets PROTEUS_STORE, and its first argument is a proteus command.
func TestMain(m *testing.M) {
	if os.Getenv("PROTEUS_STORE") != "" && len(os.Args) > 1 && (os.Args[1] == "fetch" || os.Args[1] == "simulate") {
		os.Exit(fakeProteus(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeProteus answers fetch with a snapshot in the shape of internal/store,
// and simulate policy with a default rule, or a refusal for giphy.
func fakeProteus(args []string) int {
	st := os.Getenv("PROTEUS_STORE")
	logDir := os.Getenv("PROTEUS_LOG_DIR")
	_ = os.MkdirAll(logDir, 0o700)
	_ = os.WriteFile(filepath.Join(logDir, "store-path"), []byte(st), 0o600)
	if args[0] == "fetch" {
		if args[1] == "fw-broken" {
			return 1
		}
		id := "2026-10-17T10-00-00Z"
		dir := filepath.Join(st, args[1], id)
		for p, s := range map[string]string{
			filepath.Join(dir, "config.xml"):                     "<config/>",
			filepath.Join(dir, "predefined.xml"):                 "<predefined/>",
			filepath.Join(dir, "meta.json"):                      `{"device":"` + args[1] + `","app_version":"8000-1000","documents":[]}`,
			filepath.Join(st, ".content", "8000-1000.v1.xml.gz"): "gz",
		} {
			_ = os.MkdirAll(filepath.Dir(p), 0o700)
			_ = os.WriteFile(p, []byte(s), 0o600)
		}
		_ = os.Symlink(id, filepath.Join(st, args[1], "latest"))
		return 3 // a partial fetch: the tool goes on when the files are there
	}
	if slices.Contains(args, "giphy") {
		fmt.Fprintln(os.Stderr, `{"format":2,"exit":2,"error":"--application giphy: a container"}`)
		return 2
	}
	fmt.Println(`{"results":[{"verdict":"stop","rule":"interzone-default","default":"interzone-default","default_action":"deny","first_match":null}]}`)
	return 0
}

// labSetup writes an inventory for a fake device, the flow list, the
// variables file and the key header file, and returns the flags.
func labSetup(t *testing.T, status int) []string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if strings.Contains(r.FormValue("cmd"), "giphy") {
			fmt.Fprint(w, `<response status="error"><msg><line>Unrecognized application</line></msg></response>`)
			return
		}
		fmt.Fprint(w, `<response status="success"><result/></response>`)
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	inv := write("config.yaml", "version: 1\ndefaults:\n  insecure_tls: true\ndevices:\n"+
		"  - {name: fw-test, host: "+strings.TrimPrefix(srv.URL, "https://")+", username: u, password: dummy}\n")
	flows := write("flows.tsv", header+
		"a\tS1\tlab-zone-in\tlab-zone-out\t${SRC_1}\t${DST_1}\t6\t443\tssl\t-\n"+
		"b\tP10\tlab-zone-in\tlab-zone-out\t${SRC_1}\t${DST_1}\t6\t443\tgiphy\trefused\n")
	vars := write("lab.vars", "SRC_1=198.18.0.1\nDST_1=198.18.1.1\n")
	key := write("key", "X-PAN-KEY: dummy-key\n")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		"-device", "fw-test", "-config", inv, "-flows", flows, "-vars", vars, "-key-header", key,
		"-proteus", self, "-out", filepath.Join(dir, "out"),
	}
}

func TestRunComparesAndCleansUp(t *testing.T) {
	t.Parallel()
	args := labSetup(t, http.StatusOK)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "all 2 flows agree") || strings.Contains(stdout.String()+stderr.String(), "dummy-key") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", stdout.String(), stderr.String())
	}
	out := args[len(args)-1]
	st, err := os.ReadFile(filepath.Join(out, "log", "store-path"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(st)); !os.IsNotExist(err) {
		t.Errorf("the temporary store %s is still there: %v", st, err)
	}
	for _, name := range []string{"a.device.xml", "a.proteus.json", "b.proteus.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Error(err)
		}
	}
}

func TestRunStopsOnForbidden(t *testing.T) {
	t.Parallel()
	args := labSetup(t, http.StatusForbidden)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "403") {
		t.Errorf("exit %d\nstderr:\n%s", code, stderr.String())
	}
	st, err := os.ReadFile(filepath.Join(args[len(args)-1], "log", "store-path"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(string(st)); !os.IsNotExist(err) {
		t.Errorf("the temporary store %s is still there after a failure", st)
	}
}

func TestRunFailsOnADifference(t *testing.T) {
	t.Parallel()
	args := labSetup(t, http.StatusOK)
	// The device refuses giphy, but the flow is not marked refused.
	flows := args[slices.Index(args, "-flows")+1]
	if err := os.WriteFile(flows, []byte(header+"b\tP10\tz\tz\t${SRC_1}\t${DST_1}\t6\t443\tgiphy\t-\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "1 of 1 flows differ") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, stdout.String(), stderr.String())
	}
}

func TestRunRenders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	vars := filepath.Join(dir, "v")
	file := filepath.Join(dir, "set.tsv")
	if err := os.WriteFile(vars, []byte("SRC_1=198.18.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x\t<member>${SRC_1}</member>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-vars", vars, "-render", file}, &stdout, &stderr); code != 0 || stdout.String() != "x\t<member>198.18.0.1</member>\n" {
		t.Errorf("exit %d: %q %q", code, stdout.String(), stderr.String())
	}
}

func TestRunRefusesBadInput(t *testing.T) {
	t.Parallel()
	good := labSetup(t, http.StatusOK)
	with := func(flag, value string) []string {
		args := slices.Clone(good)
		args[slices.Index(args, flag)+1] = value
		return args
	}
	dir := t.TempDir()
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"bad flag":          {[]string{"-nope"}, ""},
		"no device":         {with("-device", ""), "name the lab device"},
		"unknown device":    {with("-device", "fw-none"), "no device named"},
		"no key header":     {with("-key-header", ""), "key header file"},
		"missing key file":  {with("-key-header", filepath.Join(dir, "none")), "no such file"},
		"bad key file":      {with("-key-header", good[slices.Index(good, "-vars")+1]), "one line"},
		"missing flows":     {with("-flows", filepath.Join(dir, "none")), "no such file"},
		"out in the repo":   {with("-out", "."), "inside the repository"},
		"missing inventory": {with("-config", filepath.Join(dir, "none")), "inventory"},
		"render missing":    {append(slices.Clone(good), "-render", filepath.Join(dir, "none")), "no such file"},
		"bad vars":          {with("-vars", good[slices.Index(good, "-key-header")+1]), "variables"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(c.args, &stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr.String())
		}
	}
}

func TestRunStopsWhenTheFetchFails(t *testing.T) {
	t.Parallel()
	args := labSetup(t, http.StatusOK)
	// The fake fetch fails for fw-broken.
	inv := args[slices.Index(args, "-config")+1]
	b, err := os.ReadFile(inv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, append(b, []byte("  - {name: fw-broken, host: 192.0.2.1, username: u, password: dummy}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	args[slices.Index(args, "-device")+1] = "fw-broken"
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "proteus fetch fw-broken") {
		t.Errorf("exit %d\nstderr:\n%s", code, stderr.String())
	}
}

func TestRepoRoot(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := repoRoot(wd)
	if !ok || r != filepath.Clean(filepath.Join(wd, root)) {
		t.Errorf("repoRoot = %q, %v", r, ok)
	}
	if _, ok := repoRoot("/"); ok {
		t.Error("/ has a go.mod")
	}
}
