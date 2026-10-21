package labkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// root is the repository root, seen from this package.
const root = "../../.."

// TestMain makes the test binary a helper command when Command runs it with
// LABKIT_HELPER set.
func TestMain(m *testing.M) {
	if os.Getenv("LABKIT_HELPER") == "echo" {
		fmt.Println("helper", os.Getenv("LABKIT_VALUE"))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestReadVars(t *testing.T) {
	t.Parallel()
	vars, err := ReadVars(strings.NewReader("# a comment\n\nSRC_1=198.18.0.1\n DST_1 = 198.18.1.1 \n"))
	if err != nil {
		t.Fatal(err)
	}
	if vars["SRC_1"] != "198.18.0.1" || vars["DST_1"] != "198.18.1.1" || len(vars) != 2 {
		t.Errorf("vars = %v", vars)
	}
	for _, bad := range []string{"SRC_1 198.18.0.1\n", "=198.18.0.1\n", "src-1=x\n", "SRC_1=a\nSRC_1=b\n"} {
		if _, err := ReadVars(strings.NewReader(bad)); err == nil {
			t.Errorf("ReadVars(%q) gave no error", bad)
		}
	}
}

func TestReadVarsFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// A missing file reads as empty.
	vars, err := ReadVarsFile(filepath.Join(dir, "none"))
	if err != nil || vars == nil || len(vars) != 0 {
		t.Errorf("missing file: %v, %v", vars, err)
	}
	p := filepath.Join(dir, "lab.vars")
	if err := os.WriteFile(p, []byte("SRC_1=192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if vars, err := ReadVarsFile(p); err != nil || vars["SRC_1"] != "192.0.2.1" {
		t.Errorf("file: %v, %v", vars, err)
	}
	// A directory is not a variables file.
	if _, err := ReadVarsFile(dir); err == nil {
		t.Error("a directory gave no error")
	}
}

func TestFill(t *testing.T) {
	t.Parallel()
	got, err := Fill("a ${SRC_1} b ${SRC_1}", map[string]string{"SRC_1": "${X}"})
	if err != nil || got != "a ${X} b ${X}" {
		t.Errorf("Fill = %q, %v", got, err)
	}
	if _, err := Fill("${NOPE}", nil); err == nil || !strings.Contains(err.Error(), "NOPE") {
		t.Errorf("Fill of an unknown placeholder: %v", err)
	}
}

// matchAnswer is a test security-policy-match answer in the XML API shape,
// with dummy values.
const matchAnswer = `<response status="success"><result><rules>
<entry name="lab-rule-i1">
  <index>1</index>
  <from>lab-zone-in</from>
  <source>198.18.0.20</source>
  <to>lab-zone-out</to>
  <destination>any</destination>
  <category>any</category>
  <application>ssl/application-default(implicit)</application>
  <action>allow</action>
  <terminal>yes</terminal>
</entry>
</rules></result></response>`

func TestParsePolicyMatchReadsTheImplicitMarker(t *testing.T) {
	t.Parallel()
	a, err := ParsePolicyMatch([]byte(matchAnswer), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a != (PolicyAnswer{Rule: "lab-rule-i1", Action: "allow", Implicit: true}) {
		t.Errorf("answer = %+v", a)
	}
	explicit := strings.Replace(matchAnswer, "(implicit)", "", 1)
	if a, err := ParsePolicyMatch([]byte(explicit), nil); err != nil || a.Implicit {
		t.Errorf("explicit answer = %+v, %v", a, err)
	}
	// The older answer gives the rule as text.
	old := `<response status="success"><result><rules><entry>lab-rule-p1; index: 3<action>deny</action></entry></rules></result></response>`
	if a, err := ParsePolicyMatch([]byte(old), nil); err != nil || a.Rule != "lab-rule-p1" || a.Action != "deny" {
		t.Errorf("text answer = %+v, %v", a, err)
	}
	if _, err := ParsePolicyMatch([]byte(`<response status="success"><result><rules><entry name="r"/></rules></result></response>`), nil); err == nil {
		t.Error("an answer without an action gave no error")
	}
}

// fw02Answer is the shape of a test security-policy-match answer on fw02,
// PAN-OS 12.2.3, with dummy values: the winner comes first, and an
// <Implicit> element stands right before an entry that matches through
// implicit use. %s is the element before the first entry.
const fw02Answer = `<response cmd="status" status="success"><result><rules>
%s<entry name='lab-rule-a'>
<index>2</index>
<from>lab-zone-in</from>
<source>198.18.0.21</source>
<to>lab-zone-out</to>
<application_service><member>0:app-a/tcp/any/443</member></application_service>
<application_service_implicit_><member>0:ssl/tcp/any/443</member></application_service_implicit_>
<action>allow</action>
<terminal>yes</terminal>
</entry>
<Implicit>rule matched</Implicit>
<entry name='lab-rule-b'>
<index>1</index>
<application_service_implicit_><member>0:ssl/tcp/any/443</member></application_service_implicit_>
<action>allow</action>
</entry>
</rules>
</result></response>`

func TestParsePolicyMatchReadsTheImplicitElement(t *testing.T) {
	t.Parallel()
	// An explicit winner: no <Implicit> before it, even when the entry lists
	// implicit applications and a later entry is implicit.
	a, err := ParsePolicyMatch(fmt.Appendf(nil, fw02Answer, ""), nil)
	if err != nil || a != (PolicyAnswer{Rule: "lab-rule-a", Action: "allow"}) {
		t.Errorf("explicit answer = %+v, %v", a, err)
	}
	// An implicit winner.
	a, err = ParsePolicyMatch(fmt.Appendf(nil, fw02Answer, "<Implicit>rule matched</Implicit>\n"), nil)
	if err != nil || a != (PolicyAnswer{Rule: "lab-rule-a", Action: "allow", Implicit: true}) {
		t.Errorf("implicit answer = %+v, %v", a, err)
	}
}

func TestParsePolicyMatchNoRule(t *testing.T) {
	t.Parallel()
	for _, b := range []string{
		`<response status="success"><result/></response>`,
		`<response status="success"><result><rules/></result></response>`,
	} {
		a, err := ParsePolicyMatch([]byte(b), nil)
		if err != nil || a != (PolicyAnswer{}) {
			t.Errorf("%s: answer = %+v, %v", b, a, err)
		}
	}
}

func TestParsePolicyMatchErrors(t *testing.T) {
	t.Parallel()
	// A device error is an error, with the device's message.
	other := `<response status="error"><msg><line>invalid zone</line></msg></response>`
	if a, err := ParsePolicyMatch([]byte(other), nil); err == nil || !strings.Contains(err.Error(), "invalid zone") || a != (PolicyAnswer{}) {
		t.Errorf("other error: %+v, %v", a, err)
	}
	plain := `<response status="error"><msg>invalid zone</msg></response>`
	if _, err := ParsePolicyMatch([]byte(plain), nil); err == nil || !strings.Contains(err.Error(), "invalid zone") {
		t.Errorf("plain message: %v", err)
	}
	if _, err := ParsePolicyMatch(nil, errors.New("connection reset")); err == nil {
		t.Error("a transport error gave no error")
	}
	if _, err := ParsePolicyMatch([]byte("not xml"), nil); err == nil {
		t.Error("a broken answer gave no error")
	}
}

func TestProteusOutput(t *testing.T) {
	t.Parallel()
	stdout, stderr := []byte("out"), []byte("err")
	for exit, want := range map[int]string{0: "out", 3: "out", 1: "err", 2: "err"} {
		if got := ProteusOutput(stdout, stderr, exit); string(got) != want {
			t.Errorf("exit %d: %q, want %q", exit, got, want)
		}
	}
}

func TestLastError(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"noise\n" + `{"format":2,"exit":2,"error":"--port: bad"}` + "\n": "--port: bad",
		"proteus: bad\n":               "proteus: bad",
		`{"format":2,"exit":1}`:        `{"format":2,"exit":1}`,
		"first\n" + `{"error":"last"}`: "last",
	} {
		if got := LastError([]byte(in)); got != want {
			t.Errorf("LastError(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOnlyShowAndPolicyMatch(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-PAN-KEY") != "dummy-key" || r.FormValue("type") != "op" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fmt.Fprint(w, `<response status="success"><result/></response>`)
	}))
	defer srv.Close()
	d := NewDevice(strings.TrimPrefix(srv.URL, "https://"), true, 0, "X-PAN-KEY", "dummy-key")

	for _, cmd := range []string{
		"<show><system><info/></system></show>",
		"<test><security-policy-match><from>a</from><to>b</to></security-policy-match></test>",
	} {
		if _, err := d.Op(context.Background(), cmd); err != nil {
			t.Errorf("%s: %v", cmd, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("the device saw %d calls, want 2", calls.Load())
	}
	for _, cmd := range []string{
		"<request><restart><system/></restart></request>",
		"<test><nat-policy-match><from>a</from></nat-policy-match></test>",
		"<test><security-policy-match/><nat-policy-match/></test>",
		"<show><system><info/></system></show><request><restart><system/></restart></request>",
		"<commit/>",
		"<set><system/></set>",
		"<clear><session><all/></session></clear>",
		" <show/>",
		"<show>",
		"",
		"text",
	} {
		if _, err := d.Op(context.Background(), cmd); err == nil {
			t.Errorf("%q: the guard let it pass", cmd)
		}
		if err := CheckOp(cmd); err == nil {
			t.Errorf("%q: CheckOp let it pass", cmd)
		}
	}
	if calls.Load() != 2 {
		t.Errorf("a refused command reached the device: %d calls", calls.Load())
	}
}

func TestDeviceStopsOnForbidden(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<response status="error"><msg>Invalid credentials.</msg></response>`)
	}))
	defer srv.Close()
	d := NewDevice(strings.TrimPrefix(srv.URL, "https://"), true, 0, "X-PAN-KEY", "dummy-key")
	_, err := d.Op(context.Background(), "<show><system><info/></system></show>")
	if !errors.Is(err, ErrForbidden) || strings.Contains(err.Error(), "dummy-key") {
		t.Errorf("err = %v", err)
	}

	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<response status="error"><msg>Unrecognized application</msg></response>`)
	}))
	defer bad.Close()
	d = NewDevice(strings.TrimPrefix(bad.URL, "https://"), true, 0, "X-PAN-KEY", "dummy-key")
	b, err := d.Op(context.Background(), "<show><system><info/></system></show>")
	if err == nil || errors.Is(err, ErrForbidden) || !bytes.Contains(b, []byte("Unrecognized")) {
		t.Errorf("400: %q, %v", b, err)
	}

	// A device that does not answer is a transport error, without the key.
	d = NewDevice("127.0.0.1:1", true, 0, "X-PAN-KEY", "dummy-key")
	if _, err := d.Op(context.Background(), "<show/>"); err == nil || strings.Contains(err.Error(), "dummy-key") {
		t.Errorf("no device: %v", err)
	}
}

func TestReadKeyHeader(t *testing.T) {
	t.Parallel()
	name, value, err := ReadKeyHeader(strings.NewReader("X-PAN-KEY: dummy-key\n"))
	if err != nil || name != "X-PAN-KEY" || value != "dummy-key" {
		t.Errorf("got %q %q %v", name, value, err)
	}
	for _, bad := range []string{"", "dummy-key\n", "X-PAN-KEY:\n", "X-PAN-KEY: a\nX-PAN-KEY: b\n", "Bad Name: a\n"} {
		// The error is one fixed text, so it cannot show the file.
		_, _, err := ReadKeyHeader(strings.NewReader(bad))
		if err == nil || err.Error() != "the key header file must hold one line: X-PAN-KEY: <key>" {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestKeyHeader(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "key")
	if err := os.WriteFile(good, []byte("X-PAN-KEY: dummy-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if name, value, err := KeyHeader(good); err != nil || name != "X-PAN-KEY" || value != "dummy-key" {
		t.Errorf("got %q %q %v", name, value, err)
	}
	badFile := filepath.Join(dir, "bad")
	if err := os.WriteFile(badFile, []byte("dummy-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"":                         "key header file",
		filepath.Join(dir, "none"): "no such file",
		badFile:                    badFile + ": the key header file must hold one line",
	} {
		_, _, err := KeyHeader(path)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "dummy-key") {
			t.Errorf("%q: %v", path, err)
		}
	}
}

func TestLookup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inv := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(inv, []byte("version: 1\ndevices:\n"+
		"  - {name: fw01, host: 192.0.2.10, username: u, password: dummy, insecure_tls: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tg, err := Lookup(inv, "fw01")
	if err != nil || tg.Host != "192.0.2.10" || !tg.InsecureTLS || tg.Password != "" {
		t.Errorf("Lookup = %+v, %v", tg, err)
	}
	if _, err := Lookup(inv, "fw02"); err == nil {
		t.Error("an unknown device gave no error")
	}
	if _, err := Lookup(filepath.Join(dir, "none"), "fw01"); err == nil {
		t.Error("a missing inventory gave no error")
	}
}

//nolint:paralleltest // it sets PROTEUS_CONFIG
func TestLookupDefaultPath(t *testing.T) {
	inv := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(inv, []byte("version: 1\ndevices:\n"+
		"  - {name: fw01, host: 192.0.2.10, username: u, password: dummy}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROTEUS_CONFIG", inv)
	if tg, err := Lookup("", "fw01"); err != nil || tg.Host != "192.0.2.10" || tg.Password != "" {
		t.Errorf("Lookup = %+v, %v", tg, err)
	}
}

func TestOutDir(t *testing.T) {
	t.Parallel()
	// No directory gives a new temporary one, named after the tool.
	dir, err := OutDir("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() || !strings.HasPrefix(filepath.Base(dir), "labkit-out-") {
		t.Errorf("OutDir() = %q, %v", dir, err)
	}
	// A directory outside the repository is made.
	want := filepath.Join(t.TempDir(), "a", "b")
	if got, err := OutDir(want); err != nil || got != want {
		t.Errorf("OutDir(%q) = %q, %v", want, got, err)
	}
	if fi, err := os.Stat(want); err != nil || !fi.IsDir() {
		t.Errorf("%s: %v", want, err)
	}
	// A directory in the repository is refused.
	if _, err := OutDir("."); err == nil || !strings.Contains(err.Error(), "inside the repository") {
		t.Errorf("OutDir(.) = %v", err)
	}
}

func TestInsideRepo(t *testing.T) {
	t.Parallel()
	for dir, want := range map[string]bool{
		"/r/repo":        true,
		"/r/repo/docs":   true,
		"/r/repo-out":    false,
		"/tmp/applab-1":  false,
		"/r":             false,
		"/r/repo/../out": false,
	} {
		if got := insideRepo(dir, "/r/repo"); got != want {
			t.Errorf("insideRepo(%q) = %v, want %v", dir, got, want)
		}
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

func TestCommand(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var w bytes.Buffer
	if err := Command(context.Background(), &w, []string{"LABKIT_HELPER=echo", "LABKIT_VALUE=x"}, self); err != nil || w.String() != "helper x\n" {
		t.Errorf("Command = %q, %v", w.String(), err)
	}
	if err := Command(context.Background(), &w, nil, filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("a missing command gave no error")
	}
}

// fakeSnapshot writes a store with one snapshot of device fw-test and its
// content file, in the layout of internal/store.
func fakeSnapshot(t *testing.T, content bool) string {
	t.Helper()
	st := t.TempDir()
	id := "2026-10-17T10-00-00Z"
	dir := filepath.Join(st, "fw-test", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		filepath.Join(dir, "config.xml"):       "<config/>",
		filepath.Join(dir, "predefined.xml"):   "<predefined/>",
		filepath.Join(dir, "identity.json.gz"): "id",
		filepath.Join(dir, "meta.json"):        `{"device":"fw-test","id":"` + id + `","app_version":"8000-1000","identity":true,"documents":[]}`,
	}
	if content {
		files[filepath.Join(st, ".content", "8000-1000.v1.xml.gz")] = "gz"
	}
	for p, s := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(id, filepath.Join(st, "fw-test", "latest")); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCopySnapshot(t *testing.T) {
	t.Parallel()
	st := fakeSnapshot(t, true)
	dst := t.TempDir()
	ver, err := CopySnapshot(st, "fw-test", dst, []string{"config.xml", "predefined.xml", "apps.xml.gz"})
	if err != nil || ver != "8000-1000" {
		t.Fatalf("CopySnapshot = %q, %v", ver, err)
	}
	for name, want := range map[string]string{"config.xml": "<config/>", "predefined.xml": "<predefined/>", "apps.xml.gz": "gz"} {
		b, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil || string(b) != want {
			t.Errorf("%s: %q, %v", name, b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "identity.json.gz")); !os.IsNotExist(err) {
		t.Errorf("a file not asked for was copied: %v", err)
	}
	// Only the files asked for: a snapshot without a content file serves a
	// copy without apps.xml.gz.
	dst = t.TempDir()
	if _, err := CopySnapshot(fakeSnapshot(t, false), "fw-test", dst, []string{"config.xml", "identity.json.gz"}); err != nil {
		t.Errorf("no content file asked for: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "identity.json.gz")); err != nil || string(b) != "id" {
		t.Errorf("identity.json.gz: %q, %v", b, err)
	}
	if _, err := CopySnapshot(fakeSnapshot(t, false), "fw-test", t.TempDir(), []string{"apps.xml.gz"}); err == nil || !strings.Contains(err.Error(), "content") {
		t.Errorf("no content file: %v", err)
	}
	// A missing second file is found before the first file is copied.
	dst = t.TempDir()
	if _, err := CopySnapshot(st, "fw-test", dst, []string{"config.xml", "none.xml"}); err == nil || !strings.Contains(err.Error(), "lacks a file") {
		t.Errorf("a missing file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "config.xml")); !os.IsNotExist(err) {
		t.Errorf("config.xml was copied before the missing file stopped the copy: %v", err)
	}
	// A directory passes the check but cannot be read.
	if err := os.Mkdir(filepath.Join(st, "fw-test", "2026-10-17T10-00-00Z", "adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := CopySnapshot(st, "fw-test", t.TempDir(), []string{"adir"}); err == nil || !strings.Contains(err.Error(), "lacks a file") {
		t.Errorf("a directory: %v", err)
	}
	for _, name := range []string{"../meta.json", "a/config.xml", "..", ""} {
		if _, err := CopySnapshot(st, "fw-test", t.TempDir(), []string{name}); err == nil || !strings.Contains(err.Error(), "not a file name") {
			t.Errorf("%q: %v", name, err)
		}
	}
	if _, err := CopySnapshot(st, "fw-test", filepath.Join(t.TempDir(), "none"), []string{"config.xml"}); err == nil {
		t.Error("a missing destination gave no error")
	}
	if _, err := CopySnapshot(t.TempDir(), "fw-test", t.TempDir(), []string{"config.xml"}); err == nil {
		t.Error("an empty store gave no error")
	}
}

func TestLabDataInCatchesLabData(t *testing.T) {
	t.Parallel()
	docs := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	// applab's ranges: the documentation ranges and the benchmark range.
	withBench := slices.Concat(docs, []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")})
	text := "src 198.18.0.1 and 192.0.2.7, not 10.1.2.3 or 012345678901; 999.1.2.3 is no address"
	if got := LabDataIn(text, withBench); !slices.Equal(got, []string{"address 10.1.2.3", "serial 012345678901"}) {
		t.Errorf("LabDataIn with the benchmark range = %q", got)
	}
	// The ranges are the caller's: without the benchmark range, its
	// address is lab data.
	if got := LabDataIn(text, docs); !slices.Equal(got, []string{"address 198.18.0.1", "address 10.1.2.3", "serial 012345678901"}) {
		t.Errorf("LabDataIn = %q", got)
	}
}

func TestLabDataInCatchesIPv6(t *testing.T) {
	t.Parallel()
	nets := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	text := "src 2001:db8::5 and 2001:DB8:1::/48, not fe80::1 or 2001:db9::7; 12:30:35 is a time"
	if got := LabDataIn(text, nets); !slices.Equal(got, []string{"address fe80::1", "address 2001:db9::7"}) {
		t.Errorf("LabDataIn = %q", got)
	}
	// Hex letters next to an address do not hide it.
	if got := LabDataIn("cafe2001:db9::7 and 2001:db9::8beef", nets); !slices.Equal(got, []string{"address 2001:db9::7", "address 2001:db9::8bee"}) {
		t.Errorf("LabDataIn next to hex letters = %q", got)
	}
	// Without the IPv6 range, every IPv6 address is lab data.
	if got := LabDataIn("2001:db8::5", nets[:1]); !slices.Equal(got, []string{"address 2001:db8::5"}) {
		t.Errorf("LabDataIn without the IPv6 range = %q", got)
	}
}

func TestLabDomainsInCatchesDomains(t *testing.T) {
	t.Parallel()
	allowed := []string{"example.com"}
	text := "alice@example.com, EXAMPLE.COM\\alice, eu.example.com and dc=eu,dc=example,dc=com are dummy; " +
		"bob@corp.test, corp.test\\bob, dc=corp, DC=Test and www.example.com.evil.test are lab data; " +
		"localhost.localdomain is the PAN-OS default; user-id-flows.tsv, config.xml, identity.json.gz, " +
		"PAN-OS 11.2.5, e.g. and §10.3 are no domains"
	want := []string{"domain corp.test", "domain corp.test", "domain www.example.com.evil.test", "domain corp.test"}
	if got := LabDomainsIn(text, allowed); !slices.Equal(got, want) {
		t.Errorf("LabDomainsIn =\n%q\nwant\n%q", got, want)
	}
	// The allowed domains are the caller's.
	if got := LabDomainsIn("alice@example.com", nil); !slices.Equal(got, []string{"domain example.com"}) {
		t.Errorf("LabDomainsIn without allowed domains = %q", got)
	}
	// md, sh and py are country domains: such a name is a file only after a /.
	if got := LabDomainsIn("evil.md, corp.sh, docs/lab/app-id-lab.md and scripts/x.sh", allowed); !slices.Equal(got, []string{"domain evil.md", "domain corp.sh"}) {
		t.Errorf("LabDomainsIn with country domains = %q", got)
	}
	// An example.com look-alike is no subdomain.
	if got := LabDomainsIn("notexample.com", allowed); !slices.Equal(got, []string{"domain notexample.com"}) {
		t.Errorf("LabDomainsIn = %q", got)
	}
}
