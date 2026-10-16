package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// root is the repository root, seen from this package.
const root = "../../.."

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

const header = "case\tfact\tfrom\tto\tsource\tdestination\tprotocol\tport\tapplication\texpected\n"

func TestReadFlowsFillsPlaceholders(t *testing.T) {
	t.Parallel()
	vars := map[string]string{"SRC_1": "198.18.0.1", "DST_1": "198.18.1.1"}
	in := "# comment\n" + header +
		"S1-a\tS1,I6\tlab-zone-in\tlab-zone-out\t${SRC_1}\t${DST_1}\t6\t443\tssl\t-\n" +
		"P4-a\tP4\tlab-zone-in\tlab-zone-out\t${SRC_1}\t${DST_1}\t89\t-\tospf\t-\n" +
		"P10-a\tP10\tlab-zone-in\tlab-zone-out\t${SRC_1}\t${DST_1}\ttcp\t443\tgiphy\trefused\n" +
		"N-a\t§4.1\tlab-zone-in\tlab-zone-out\t${SRC_1}\t${DST_1}\t6\t80\t-\tdoubt\n"
	flows, err := ReadFlows(strings.NewReader(in), vars)
	if err != nil {
		t.Fatal(err)
	}
	want := []Flow{
		{Case: "S1-a", Fact: "S1,I6", Source: "198.18.0.1", Destination: "198.18.1.1", From: "lab-zone-in", To: "lab-zone-out", Protocol: "6", Port: 443, Application: "ssl"},
		{Case: "P4-a", Fact: "P4", Source: "198.18.0.1", Destination: "198.18.1.1", From: "lab-zone-in", To: "lab-zone-out", Protocol: "89", Port: 1, Application: "ospf"},
		{Case: "P10-a", Fact: "P10", Source: "198.18.0.1", Destination: "198.18.1.1", From: "lab-zone-in", To: "lab-zone-out", Protocol: "6", Port: 443, Application: "giphy", Expect: "refused"},
		{Case: "N-a", Fact: "§4.1", Source: "198.18.0.1", Destination: "198.18.1.1", From: "lab-zone-in", To: "lab-zone-out", Protocol: "6", Port: 80, Expect: "doubt"},
	}
	if !slices.Equal(flows, want) {
		t.Errorf("flows =\n%+v\nwant\n%+v", flows, want)
	}

	row := func(fields ...string) string { return header + strings.Join(fields, "\t") + "\n" }
	for name, bad := range map[string]string{
		"unknown placeholder": row("c", "S1", "z", "z", "${SRC_9}", "${DST_1}", "6", "443", "ssl", "-"),
		"no header":           "c\tS1\tz\tz\ta\tb\t6\t443\tssl\t-\n",
		"short row":           row("c", "S1", "z", "z", "${SRC_1}"),
		"bad protocol":        row("c", "S1", "z", "z", "${SRC_1}", "${DST_1}", "256", "443", "ssl", "-"),
		"no port":             row("c", "S1", "z", "z", "${SRC_1}", "${DST_1}", "6", "-", "ssl", "-"),
		"bad port":            row("c", "S1", "z", "z", "${SRC_1}", "${DST_1}", "6", "70000", "ssl", "-"),
		"port on portless":    row("c", "S1", "z", "z", "${SRC_1}", "${DST_1}", "89", "22", "ospf", "-"),
		"bad expected":        row("c", "S1", "z", "z", "${SRC_1}", "${DST_1}", "6", "443", "ssl", "maybe"),
		"refused without app": row("c", "S1", "z", "z", "${SRC_1}", "${DST_1}", "6", "443", "-", "refused"),
		"duplicate case":      row("c", "S1", "z", "z", "${SRC_1}", "${DST_1}", "6", "443", "ssl", "-") + "c\tS1\tz\tz\t${SRC_1}\t${DST_1}\t6\t443\tssl\t-\n",
		"unsafe case":         row("c/1", "S1", "z", "z", "${SRC_1}", "${DST_1}", "6", "443", "ssl", "-"),
		"empty zone":          row("c", "S1", "", "z", "${SRC_1}", "${DST_1}", "6", "443", "ssl", "-"),
	} {
		if _, err := ReadFlows(strings.NewReader(bad), vars); err == nil {
			t.Errorf("%s: ReadFlows gave no error", name)
		}
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

func TestDeviceCmdUsesPortOne(t *testing.T) {
	t.Parallel()
	f := Flow{From: "lab-zone-in", To: "lab-zone-out", Source: "198.18.0.1", Destination: "198.18.1.1", Protocol: "89", Port: 1, Application: "ospf"}
	cmd := DeviceCmd(f)
	want := "<test><security-policy-match><from>lab-zone-in</from><to>lab-zone-out</to>" +
		"<source>198.18.0.1</source><destination>198.18.1.1</destination><protocol>89</protocol>" +
		"<destination-port>1</destination-port><application>ospf</application></security-policy-match></test>"
	if cmd != want {
		t.Errorf("DeviceCmd =\n%s\nwant\n%s", cmd, want)
	}
	// A port of 0 still gives port 1: the command needs 1-65535 (P9).
	f.Port = 0
	if !strings.Contains(DeviceCmd(f), "<destination-port>1</destination-port>") {
		t.Errorf("port 0: %s", DeviceCmd(f))
	}
	// No application: the element is left out. A value is escaped.
	f = Flow{From: "a&b", To: "z", Source: "s", Destination: "d", Protocol: "6", Port: 443}
	if cmd := DeviceCmd(f); strings.Contains(cmd, "<application>") || !strings.Contains(cmd, "<from>a&amp;b</from>") {
		t.Errorf("DeviceCmd = %s", cmd)
	}
	if err := checkOp(DeviceCmd(f)); err != nil {
		t.Errorf("the guard refuses the device command: %v", err)
	}
}

func TestProteusArgs(t *testing.T) {
	t.Parallel()
	f := Flow{From: "lab-zone-in", To: "lab-zone-out", Source: "198.18.0.1", Destination: "198.18.1.1", Protocol: "6", Port: 443, Application: "ssl"}
	got := ProteusArgs(f, "/tmp/x/config.xml", "vsys1")
	want := []string{
		"simulate", "policy", "198.18.0.1", "198.18.1.1", "--file", "/tmp/x/config.xml", "--vsys", "vsys1",
		"--from-zone", "lab-zone-in", "--to-zone", "lab-zone-out", "--protocol", "6", "--no-dns", "--output", "json",
		"--port", "443", "--application", "ssl",
	}
	if !slices.Equal(got, want) {
		t.Errorf("args = %q", got)
	}
	// A protocol without ports gets no port; no application gets no flag.
	f.Protocol, f.Port, f.Application = "89", 1, ""
	got = ProteusArgs(f, "c", "vsys1")
	if slices.Contains(got, "--port") || slices.Contains(got, "--application") {
		t.Errorf("args = %q", got)
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

func TestParseDeviceReadsTheImplicitMarker(t *testing.T) {
	t.Parallel()
	a, err := ParseDevice([]byte(matchAnswer), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a != (Answer{Rule: "lab-rule-i1", Action: "allow", Implicit: true}) {
		t.Errorf("answer = %+v", a)
	}
	explicit := strings.Replace(matchAnswer, "(implicit)", "", 1)
	if a, err := ParseDevice([]byte(explicit), nil); err != nil || a.Implicit {
		t.Errorf("explicit answer = %+v, %v", a, err)
	}
	// The older answer gives the rule as text.
	old := `<response status="success"><result><rules><entry>lab-rule-p1; index: 3<action>deny</action></entry></rules></result></response>`
	if a, err := ParseDevice([]byte(old), nil); err != nil || a.Rule != "lab-rule-p1" || a.Action != "deny" {
		t.Errorf("text answer = %+v, %v", a, err)
	}
	if _, err := ParseDevice([]byte(`<response status="success"><result><rules><entry name="r"/></rules></result></response>`), nil); err == nil {
		t.Error("an answer without an action gave no error")
	}
}

func TestParseDeviceNoRule(t *testing.T) {
	t.Parallel()
	for _, b := range []string{
		`<response status="success"><result/></response>`,
		`<response status="success"><result><rules/></result></response>`,
	} {
		a, err := ParseDevice([]byte(b), nil)
		if err != nil || a != (Answer{}) {
			t.Errorf("%s: answer = %+v, %v", b, a, err)
		}
	}
}

func TestParseDeviceRefused(t *testing.T) {
	t.Parallel()
	refusal := `<response status="error"><msg><line>Server error : Unrecognized application Error parsing arguments</line></msg></response>`
	a, err := ParseDevice([]byte(refusal), nil)
	if err != nil || !a.Refused {
		t.Errorf("answer = %+v, %v", a, err)
	}
	// The refusal can arrive as the call's error, with an HTTP error status.
	if a, err := ParseDevice(nil, errors.New("HTTP 400: Unrecognized application")); err != nil || !a.Refused {
		t.Errorf("answer = %+v, %v", a, err)
	}
	// Another error is an error, not a refusal.
	other := `<response status="error"><msg><line>invalid zone</line></msg></response>`
	if _, err := ParseDevice([]byte(other), nil); err == nil || !strings.Contains(err.Error(), "invalid zone") {
		t.Errorf("other error: %v", err)
	}
	if _, err := ParseDevice(nil, errors.New("connection reset")); err == nil {
		t.Error("a transport error gave no error")
	}
	if _, err := ParseDevice([]byte("not xml"), nil); err == nil {
		t.Error("a broken answer gave no error")
	}
}

func TestParseProteus(t *testing.T) {
	t.Parallel()
	rule := `{"results":[{"verdict":"pass","rule":"lab-rule-i1","default":"","default_action":"",
		"first_match":{"name":"lab-rule-i1","action":"allow"},"implicit":{"app":"ssl","via":["airdroid"]}}]}`
	a, decided, err := ParseProteus([]byte(rule), 0)
	if err != nil || !decided || a != (Answer{Rule: "lab-rule-i1", Action: "allow", Implicit: true}) {
		t.Errorf("rule: %+v %v %v", a, decided, err)
	}
	def := `{"results":[{"verdict":"stop","rule":"interzone-default","default":"interzone-default","default_action":"deny","first_match":null}]}`
	a, decided, err = ParseProteus([]byte(def), 0)
	if err != nil || !decided || a != (Answer{Rule: "interzone-default", Action: "deny", Default: true}) {
		t.Errorf("default: %+v %v %v", a, decided, err)
	}
	und := `{"results":[{"verdict":"undecided","rule":"","first_match":{"name":"x","action":"allow"}}]}`
	if a, decided, err = ParseProteus([]byte(und), 0); err != nil || decided || a != (Answer{}) {
		t.Errorf("undecided: %+v %v %v", a, decided, err)
	}
	// Exit 3 is an incomplete answer, an undecided one too, on stdout.
	if a, decided, err = ParseProteus([]byte(und), 3); err != nil || decided || a != (Answer{}) {
		t.Errorf("undecided, exit 3: %+v %v %v", a, decided, err)
	}
	if a, decided, err = ParseProteus([]byte(rule), 3); err != nil || !decided || a.Rule != "lab-rule-i1" {
		t.Errorf("rule, exit 3: %+v %v %v", a, decided, err)
	}
	refused := "noise\n" + `{"format":2,"exit":2,"error":"--application giphy: giphy is an application container; name one of its functions: giphy-base","log":"/tmp/x"}` + "\n"
	if a, decided, err = ParseProteus([]byte(refused), 2); err != nil || !decided || !a.Refused {
		t.Errorf("refused: %+v %v %v", a, decided, err)
	}
	for name, c := range map[string]struct {
		b    string
		exit int
	}{
		"other usage error":  {`{"format":2,"exit":2,"error":"--port \"x\": want 443 or tcp/443"}`, 2},
		"usage without json": {"proteus: bad\n", 2},
		"failure":            {`{"format":2,"exit":1,"error":"boom"}`, 1},
		"no result":          {`{"results":[]}`, 0},
		"broken json":        {`{`, 0},
		"no first match":     {`{"results":[{"verdict":"pass","rule":"r","first_match":null}]}`, 0},
	} {
		if _, _, err := ParseProteus([]byte(c.b), c.exit); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()
	allow := Answer{Rule: "lab-rule-s1", Action: "allow"}
	def := Answer{Rule: "interzone-default", Action: "deny", Default: true}
	refused := Answer{Refused: true}
	for _, c := range []struct {
		name            string
		expect          string
		device, proteus Answer
		decided, ok     bool
	}{
		{"same rule", "", allow, allow, true, true},
		{"other rule", "", allow, Answer{Rule: "lab-rule-s2", Action: "allow"}, true, false},
		{"other action", "", allow, Answer{Rule: "lab-rule-s1", Action: "deny"}, true, false},
		{"implicit marker", "", Answer{Rule: "lab-rule-s1", Action: "allow", Implicit: true}, allow, true, false},
		{"marker both", "", Answer{Rule: "r", Action: "allow", Implicit: true}, Answer{Rule: "r", Action: "allow", Implicit: true}, true, true},
		{"no rule and a default rule", "", Answer{}, def, true, true},
		{"no rule and a rule", "", Answer{}, allow, true, false},
		{"a rule and a default rule", "", allow, def, true, false},
		{"refused both, marked", "refused", refused, refused, true, true},
		{"refused both, not marked", "", refused, refused, true, false},
		{"refused by the device only", "refused", refused, def, true, false},
		{"refused by proteus only", "refused", Answer{}, refused, true, false},
		{"marked refused, none refuses", "refused", allow, allow, true, false},
		{"undecided, marked doubt", "doubt", allow, Answer{}, false, true},
		{"undecided, not marked", "", allow, Answer{}, false, false},
		{"decided, marked doubt", "doubt", allow, allow, true, false},
	} {
		err := Compare(Flow{Case: "c", Expect: c.expect}, c.device, c.proteus, c.decided)
		if (err == nil) != c.ok {
			t.Errorf("%s: Compare = %v, want ok %v", c.name, err, c.ok)
		}
	}
}

func TestAnswerString(t *testing.T) {
	t.Parallel()
	for a, want := range map[Answer]string{
		{}:                           "no rule",
		{Refused: true}:              "refused",
		{Rule: "r", Action: "allow"}: "r (allow)",
		{Rule: "r", Action: "allow", Implicit: true}:               "r (allow, implicit)",
		{Rule: "interzone-default", Action: "deny", Default: true}: "interzone-default (deny, default rule)",
	} {
		if got := a.String(); got != want {
			t.Errorf("%+v: %q, want %q", a, got, want)
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
	d := newDevice(strings.TrimPrefix(srv.URL, "https://"), true, 0, "X-PAN-KEY", "dummy-key")

	for _, cmd := range []string{
		"<show><system><info/></system></show>",
		"<test><security-policy-match><from>a</from><to>b</to></security-policy-match></test>",
	} {
		if _, err := d.op(context.Background(), cmd); err != nil {
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
		if _, err := d.op(context.Background(), cmd); err == nil {
			t.Errorf("%q: the guard let it pass", cmd)
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
	d := newDevice(strings.TrimPrefix(srv.URL, "https://"), true, 0, "X-PAN-KEY", "dummy-key")
	_, err := d.op(context.Background(), "<show><system><info/></system></show>")
	if !errors.Is(err, errForbidden) || strings.Contains(err.Error(), "dummy-key") {
		t.Errorf("err = %v", err)
	}

	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<response status="error"><msg>Unrecognized application</msg></response>`)
	}))
	defer bad.Close()
	d = newDevice(strings.TrimPrefix(bad.URL, "https://"), true, 0, "X-PAN-KEY", "dummy-key")
	b, err := d.op(context.Background(), "<show><system><info/></system></show>")
	if err == nil || errors.Is(err, errForbidden) || !bytes.Contains(b, []byte("Unrecognized")) {
		t.Errorf("400: %q, %v", b, err)
	}

	// A device that does not answer is a transport error, without the key.
	d = newDevice("127.0.0.1:1", true, 0, "X-PAN-KEY", "dummy-key")
	if _, err := d.op(context.Background(), "<show/>"); err == nil || strings.Contains(err.Error(), "dummy-key") {
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
		filepath.Join(dir, "config.xml"):     "<config/>",
		filepath.Join(dir, "predefined.xml"): "<predefined/>",
		filepath.Join(dir, "meta.json"):      `{"device":"fw-test","id":"` + id + `","app_version":"8000-1000","documents":[]}`,
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
	ver, err := copySnapshot(st, "fw-test", dst)
	if err != nil || ver != "8000-1000" {
		t.Fatalf("copySnapshot = %q, %v", ver, err)
	}
	for name, want := range map[string]string{"config.xml": "<config/>", "predefined.xml": "<predefined/>", "apps.xml.gz": "gz"} {
		b, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil || string(b) != want {
			t.Errorf("%s: %q, %v", name, b, err)
		}
	}
	if _, err := copySnapshot(fakeSnapshot(t, false), "fw-test", t.TempDir()); err == nil || !strings.Contains(err.Error(), "content") {
		t.Errorf("no content file: %v", err)
	}
	if _, err := copySnapshot(t.TempDir(), "fw-test", t.TempDir()); err == nil {
		t.Error("an empty store gave no error")
	}
}

// fakeDevice answers each command from a map keyed by the flow's source.
type fakeDevice struct {
	answers map[string]string
	err     error
}

func (f fakeDevice) op(_ context.Context, cmd string) ([]byte, error) {
	if err := checkOp(cmd); err != nil {
		return nil, err
	}
	if f.err != nil {
		return nil, f.err
	}
	for src, b := range f.answers {
		if strings.Contains(cmd, "<source>"+src+"</source>") {
			return []byte(b), nil
		}
	}
	return []byte(`<response status="success"><result/></response>`), nil
}

func TestCheckFlows(t *testing.T) {
	t.Parallel()
	flows := []Flow{
		{Case: "same", Fact: "S1", From: "a", To: "b", Source: "s1", Destination: "d", Protocol: "6", Port: 443, Application: "ssl"},
		{Case: "differs", Fact: "S2", From: "a", To: "b", Source: "s2", Destination: "d", Protocol: "6", Port: 443, Application: "ssl"},
		{Case: "refused", Fact: "P10", From: "a", To: "b", Source: "s3", Destination: "d", Protocol: "6", Port: 443, Application: "giphy", Expect: "refused"},
		{Case: "doubt", Fact: "§4.1", From: "a", To: "b", Source: "s4", Destination: "d", Protocol: "6", Port: 80, Expect: "doubt"},
	}
	dev := fakeDevice{answers: map[string]string{
		"s1": `<response status="success"><result><rules><entry name="r1"><action>allow</action></entry></rules></result></response>`,
		"s3": `<response status="error"><msg><line>Unrecognized application</line></msg></response>`,
	}}
	run := func(_ context.Context, args []string) ([]byte, []byte, int, error) {
		switch args[2] {
		case "s1":
			return []byte(`{"results":[{"verdict":"pass","rule":"r1","first_match":{"name":"r1","action":"allow"}}]}`), nil, 0, nil
		case "s3":
			return nil, []byte(`{"format":2,"exit":2,"error":"--application giphy: a container"}`), 2, nil
		case "s4":
			// An undecided answer exits 3, with the answer on stdout.
			return []byte(`{"results":[{"verdict":"undecided","rule":""}]}`), []byte(`{"format":2,"exit":3}`), 3, nil
		}
		return []byte(`{"results":[{"verdict":"pass","rule":"r9","first_match":{"name":"r9","action":"allow"}}]}`), nil, 0, nil
	}
	out := t.TempDir()
	var w bytes.Buffer
	diffs, err := checkFlows(context.Background(), &w, out, dev, run, flows, "config.xml", "vsys1")
	if err != nil {
		t.Fatal(err)
	}
	if diffs != 1 {
		t.Errorf("diffs = %d\n%s", diffs, w.String())
	}
	lines := strings.Split(strings.TrimSpace(w.String()), "\n")
	if len(lines) != 4 || !strings.HasSuffix(lines[0], " ok") || !strings.Contains(lines[1], "DIFF") ||
		!strings.HasSuffix(lines[2], " ok") || !strings.HasSuffix(lines[3], " ok") || !strings.Contains(lines[3], "undecided") {
		t.Errorf("output:\n%s", w.String())
	}
	for _, name := range []string{"same.device.xml", "same.proteus.json", "refused.proteus.json"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// A 403 stops the run.
	_, err = checkFlows(context.Background(), io.Discard, t.TempDir(), fakeDevice{err: errForbidden}, run, flows, "c", "vsys1")
	if !errors.Is(err, errForbidden) {
		t.Errorf("403: %v", err)
	}
	// Another device error counts as a difference and the run goes on.
	diffs, err = checkFlows(context.Background(), io.Discard, t.TempDir(), fakeDevice{err: errors.New("reset")}, run, flows[:1], "c", "vsys1")
	if err != nil || diffs != 1 {
		t.Errorf("device error: %d, %v", diffs, err)
	}
	// proteus that cannot start stops the run.
	broken := func(context.Context, []string) ([]byte, []byte, int, error) {
		return nil, nil, 0, errors.New("no binary")
	}
	if _, err := checkFlows(context.Background(), io.Discard, t.TempDir(), dev, broken, flows[:1], "c", "vsys1"); err == nil {
		t.Error("a proteus that cannot start gave no error")
	}
	// A cancelled run stops.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := checkFlows(ctx, io.Discard, t.TempDir(), dev, run, flows, "c", "vsys1"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// labFile reads one file of docs/lab.
func labFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, "docs", "lab", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// setEntry is one line of the set file.
type setEntry struct {
	xpath, kind, name string
	elem              node
}

// node is a parsed XML element.
type node struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Text    string     `xml:",chardata"`
	Nodes   []node     `xml:",any"`
}

func (n node) child(name string) *node {
	for i := range n.Nodes {
		if n.Nodes[i].XMLName.Local == name {
			return &n.Nodes[i]
		}
	}
	return nil
}

func (n *node) members() []string {
	if n == nil {
		return nil
	}
	var out []string
	for _, c := range n.Nodes {
		if c.XMLName.Local == "member" {
			out = append(out, c.Text)
		}
	}
	return out
}

// walk calls fn for every element below n, n too.
func (n node) walk(fn func(node)) {
	fn(n)
	for _, c := range n.Nodes {
		c.walk(fn)
	}
}

func readSetFile(t *testing.T) []setEntry {
	t.Helper()
	var out []setEntry
	for i, line := range strings.Split(labFile(t, "app-id-lab-set.tsv"), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		xpath, elem, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("set line %d has no tab", i+1)
		}
		kind, ok := strings.CutPrefix(xpath, vsysXPath+"/")
		if !ok {
			t.Fatalf("set line %d: xpath %s is not below %s", i+1, xpath, vsysXPath)
		}
		var n node
		if err := xml.Unmarshal([]byte(elem), &n); err != nil {
			t.Fatalf("set line %d: %v", i+1, err)
		}
		e := setEntry{xpath: xpath, kind: kind, elem: n}
		for _, a := range n.Attrs {
			if a.Name.Local == "name" {
				e.name = a.Value
			}
		}
		if n.XMLName.Local != "entry" || len(n.Attrs) != 1 || e.name == "" {
			t.Fatalf("set line %d: the element is not one named entry", i+1)
		}
		out = append(out, e)
	}
	return out
}

var srcPlaceholder = regexp.MustCompile(`^\$\{SRC_[0-9]+\}$`)

// The lab configuration touches only its own objects (spec 2026-10-16 §9.3).
func TestLabConfigIsIsolated(t *testing.T) {
	t.Parallel()
	entries := readSetFile(t)
	kinds := map[string]bool{
		"zone": true, "tag": true, "application": true, "application-tag": true, "application-filter": true,
		"application-group": true, "service": true, "service-group": true, "rulebase/security/rules": true,
	}
	defined := map[string]bool{}
	sourceOf := map[string]string{} // source placeholder -> the rule that used it last
	var lastSource string
	rules := 0
	for i, e := range entries {
		if !kinds[e.kind] {
			t.Errorf("%s: kind %s is not a lab kind", e.name, e.kind)
		}
		if !strings.HasPrefix(e.name, "lab-") {
			t.Errorf("%s: the name does not start with lab-", e.name)
		}
		// Every lab- name an entry names is an entry the file set before.
		e.elem.walk(func(n node) {
			if n.XMLName.Local == "member" && strings.HasPrefix(n.Text, "lab-") && !defined[n.Text] {
				t.Errorf("%s names %s before the file sets it", e.name, n.Text)
			}
		})
		defined[e.name] = true
		switch e.kind {
		case "zone":
			if i > 1 {
				t.Errorf("zone %s: the zones come first", e.name)
			}
			l3 := e.elem.child("network")
			if l3 == nil || l3.child("layer3") == nil || len(l3.child("layer3").Nodes) != 0 {
				t.Errorf("zone %s: want layer3 without interfaces", e.name)
			}
		case "rulebase/security/rules":
			rules++
			if got := e.elem.child("from").members(); !slices.Equal(got, []string{"lab-zone-in"}) {
				t.Errorf("rule %s: from %v", e.name, got)
			}
			if got := e.elem.child("to").members(); !slices.Equal(got, []string{"lab-zone-out"}) {
				t.Errorf("rule %s: to %v", e.name, got)
			}
			src := e.elem.child("source").members()
			if len(src) != 1 || !srcPlaceholder.MatchString(src[0]) {
				t.Errorf("rule %s: source %v, want one ${SRC_n}", e.name, src)
				continue
			}
			// Rules that share a source are one case group, next to each other.
			if prev, seen := sourceOf[src[0]]; seen && lastSource != src[0] {
				t.Errorf("rule %s shares %s with %s, but not next to it", e.name, src[0], prev)
			}
			sourceOf[src[0]], lastSource = e.name, src[0]
		default:
			if rules > 0 {
				t.Errorf("%s: the rules come last", e.name)
			}
		}
	}
	if rules == 0 {
		t.Fatal("the set file holds no rule")
	}

	// The delete file removes every entry, in the reverse order.
	var want []string
	for _, e := range slices.Backward(entries) {
		want = append(want, e.xpath+"/entry[@name='"+e.name+"']")
	}
	var got []string
	for _, line := range strings.Split(labFile(t, "app-id-lab-delete.tsv"), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			got = append(got, line)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("the delete file is not the set file's entries in reverse:\ngot  %q\nwant %q", got, want)
	}
}

// labFlows reads the flow list with each placeholder filled by itself.
func labFlows(t *testing.T) []Flow {
	t.Helper()
	text := labFile(t, "app-id-flows.tsv")
	vars := map[string]string{}
	for _, m := range placeholder.FindAllStringSubmatch(text, -1) {
		vars[m[1]] = m[0]
	}
	flows, err := ReadFlows(strings.NewReader(text), vars)
	if err != nil {
		t.Fatal(err)
	}
	return flows
}

// The flow list covers every fact of spec 2026-10-16 §1.2-§1.4 and the
// objects §9.1 names.
func TestFlowListCoversTheFacts(t *testing.T) {
	t.Parallel()
	flows := labFlows(t)
	facts := map[string]bool{}
	for _, f := range flows {
		for _, fact := range strings.Split(f.Fact, ",") {
			facts[fact] = true
		}
	}
	for _, set := range []struct {
		prefix string
		n      int
	}{{"S", 15}, {"I", 8}, {"P", 15}} {
		for i := 1; i <= set.n; i++ {
			if fact := fmt.Sprintf("%s%d", set.prefix, i); !facts[fact] {
				t.Errorf("no flow for %s", fact)
			}
		}
	}

	// What the rules of each source name, from the set file.
	entries := readSetFile(t)
	names := map[string][]string{} // source -> application and service members
	customDefault := map[string]bool{}
	for _, e := range entries {
		switch e.kind {
		case "application":
			customDefault[strings.ToLower(e.name)] = e.elem.child("default") != nil
		case "rulebase/security/rules":
			src := e.elem.child("source").members()[0]
			names[src] = append(names[src], e.elem.child("application").members()...)
			names[src] = append(names[src], e.elem.child("service").members()...)
		}
	}
	covered := map[string]bool{}
	for _, f := range flows {
		if names[f.Source] == nil && f.Expect != "refused" {
			t.Errorf("%s: no lab rule names source %s", f.Case, f.Source)
		}
		for _, n := range names[f.Source] {
			switch {
			case strings.HasPrefix(n, "lab-svcgrp-"):
				covered["service group"] = true
			case strings.HasPrefix(n, "lab-svc-"):
				covered["custom service"] = true
			}
		}
		if def, custom := customDefault[strings.ToLower(f.Application)]; custom {
			covered[map[bool]string{true: "custom application with default", false: "custom application without default"}[def]] = true
		}
		if portless(f.Protocol) {
			covered["protocol without ports"] = true
			if f.Port != 1 {
				t.Errorf("%s: protocol %s has port %d, want 1 (P9)", f.Case, f.Protocol, f.Port)
			}
		}
		if f.Expect == "refused" {
			covered["refused"] = true
		}
	}
	for _, want := range []string{
		"custom service", "service group", "custom application with default",
		"custom application without default", "protocol without ports", "refused",
	} {
		if !covered[want] {
			t.Errorf("no flow covers a %s", want)
		}
	}
}

// labDataFiles are the tracked lab files.
var labDataFiles = []string{"app-id-lab.md", "app-id-lab-set.tsv", "app-id-lab-delete.tsv", "app-id-flows.tsv"}

// The documentation ranges: RFC 5737 and RFC 2544.
var exampleNets = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
}

var (
	ipv4   = regexp.MustCompile(`\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b`)
	serial = regexp.MustCompile(`\b[0-9]{12,}\b`)
)

// labDataIn returns what in a file's text looks like lab data: an address
// outside the documentation ranges, or a serial number.
func labDataIn(text string) []string {
	var out []string
	for _, s := range ipv4.FindAllString(text, -1) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if !slices.ContainsFunc(exampleNets, func(p netip.Prefix) bool { return p.Contains(a) }) {
			out = append(out, "address "+s)
		}
	}
	for _, s := range serial.FindAllString(text, -1) {
		out = append(out, "serial "+s)
	}
	return out
}

func TestLabDataInCatchesLabData(t *testing.T) {
	t.Parallel()
	got := labDataIn("src 198.18.0.1 and 192.0.2.7, not 10.1.2.3 or 012345678901")
	if !slices.Equal(got, []string{"address 10.1.2.3", "serial 012345678901"}) {
		t.Errorf("labDataIn = %q", got)
	}
}

// The lab files hold placeholders, never a lab address or serial
// (spec 2026-10-16 §9.2), and the variables file stays out of git.
func TestLabFilesHoldNoLabData(t *testing.T) {
	t.Parallel()
	for _, name := range labDataFiles {
		for _, bad := range labDataIn(labFile(t, name)) {
			t.Errorf("docs/lab/%s holds %s", name, bad)
		}
	}
	gi, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(strings.Split(string(gi), "\n"), "/"+VarsFile) {
		t.Errorf(".gitignore does not name /%s", VarsFile)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git, so the tracked-file check cannot run")
	}
	out, err := exec.CommandContext(context.Background(), git, "-C", root, "ls-files", "--", VarsFile).Output()
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(out)) > 0 {
		t.Errorf("git tracks %s", VarsFile)
	}
}
