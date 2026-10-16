package fetch

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/fakepanos"
	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/runlog"
)

const (
	testUser = "reader"
	testPass = "not-a-real-password"
	testKey  = "not-a-real-key"
)

func device() *fakepanos.Device {
	return &fakepanos.Device{
		User: testUser, Password: testPass, Key: testKey,
		Ops: map[string]string{
			"<show><system><info/></system></show>": fakepanos.Success("<system><hostname>lab</hostname><app-version>8000-1000</app-version></system>"),
		},
		Config: `<config version="11.2.0"><devices/></config>`,
	}
}

func target(host string) inventory.Target {
	return inventory.Target{
		Name: "lab", Host: host, Username: testUser, Password: testPass,
		InsecureTLS: true, Timeout: 5 * time.Second,
	}
}

func loggedIn(t *testing.T, d *fakepanos.Device) *Client {
	t.Helper()
	c := NewClient(target(d.Start(t)), nil)
	if err := c.Keygen(context.Background(), testUser, testPass); err != nil {
		t.Fatalf("Keygen: %v", err)
	}
	return c
}

// Source: PAN-OS XML API, "Get Your API Key". The password goes in a POST body and
// the key in a header, so neither is ever part of a URL.
func TestKeygenKeepsSecretsOutOfURLs(t *testing.T) {
	t.Parallel()
	d := device()
	c := loggedIn(t, d)
	if _, err := c.Op(context.Background(), "<show><system><info/></system></show>"); err != nil {
		t.Fatal(err)
	}
	reqs := d.Requests()
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want keygen then op", len(reqs))
	}
	for _, r := range reqs {
		if r.Method != "POST" || strings.Contains(r.RawQuery, testPass) || strings.Contains(r.RawQuery, testKey) {
			t.Errorf("a secret reached the URL, or the method was not POST: %+v", r)
		}
	}
	if reqs[1].Key != testKey {
		t.Errorf("the key must travel in X-PAN-KEY, got %q", reqs[1].Key)
	}
}

func TestKeygenRefusalIsAnAPIErrorAndIsNotRetried(t *testing.T) {
	t.Parallel()
	d := device()
	c := NewClient(target(d.Start(t)), nil)
	err := c.Keygen(context.Background(), testUser, "wrong")
	var api *APIError
	if !errors.As(err, &api) || api.HTTPStatus != 403 || !strings.Contains(api.Message, "Invalid Credential") {
		t.Fatalf("want a 403 APIError naming the refusal, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Error("an error must never quote the password")
	}
	if n := len(d.Requests()); n != 1 {
		t.Errorf("a refusal was sent %d times; a 4xx is never retried", n)
	}
}

func TestKeygenNeedsAKeyInTheAnswer(t *testing.T) {
	t.Parallel()
	d := device()
	d.Key = ""
	c := NewClient(target(d.Start(t)), nil)
	if err := c.Keygen(context.Background(), testUser, testPass); err == nil {
		t.Error("a success without a key must be an error")
	}
}

func TestOpReturnsTheResponseVerbatim(t *testing.T) {
	t.Parallel()
	c := loggedIn(t, device())
	b, err := c.Op(context.Background(), "<show><system><info/></system></show>")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "<hostname>lab</hostname>") || !strings.HasPrefix(string(b), "<response") {
		t.Errorf("body = %s", b)
	}
}

// A device that answers status="error" with HTTP 200 has still refused.
func TestOpRefusalIsAnAPIError(t *testing.T) {
	t.Parallel()
	c := loggedIn(t, device())
	_, err := c.Op(context.Background(), "<show><nothing/></show>")
	var api *APIError
	if !errors.As(err, &api) || api.Code != "17" || !strings.Contains(api.Message, "invalid syntax") {
		t.Errorf("want code 17 invalid syntax, got %v", err)
	}
	if !strings.Contains(err.Error(), "code 17") {
		t.Errorf("the error must carry the code: %v", err)
	}
}

func TestAPIErrorWithoutCodeOrMessage(t *testing.T) {
	t.Parallel()
	e := &APIError{HTTPStatus: 502}
	if got := e.Error(); got != "device refused (HTTP 502): no message" {
		t.Errorf("Error() = %q", got)
	}
}

func TestExportConfigAcceptsABareConfig(t *testing.T) {
	t.Parallel()
	c := loggedIn(t, device())
	b, err := c.ExportConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "<config") {
		t.Errorf("body = %s", b)
	}
}

func TestCallsNeedAKey(t *testing.T) {
	t.Parallel()
	c := NewClient(target(device().Start(t)), nil)
	if _, err := c.ExportConfig(context.Background()); err == nil {
		t.Error("a call before Keygen must fail")
	}
}

// A dropped connection is retried once; a second drop is the answer.
func TestOneRetryOnATransportError(t *testing.T) {
	t.Parallel()
	d := device()
	d.DropFirst = 1
	c := quick(NewClient(target(d.Start(t)), nil))
	if err := c.Keygen(context.Background(), testUser, testPass); err != nil {
		t.Fatalf("one drop must be survived: %v", err)
	}
	d2 := device()
	d2.DropFirst = 2
	c2 := quick(NewClient(target(d2.Start(t)), nil))
	if err := c2.Keygen(context.Background(), testUser, testPass); err == nil {
		t.Error("two drops must fail")
	}
	if n := len(d2.Requests()); n != 2 {
		t.Errorf("got %d attempts, want 2", n)
	}
}

// A cancelled run stops at once rather than retrying.
func TestACancelledContextIsNotRetried(t *testing.T) {
	t.Parallel()
	d := device()
	d.DropFirst = 1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewClient(target(d.Start(t)), nil).Keygen(ctx, testUser, testPass); err == nil {
		t.Error("a cancelled context must fail")
	}
	if n := len(d.Requests()); n != 0 {
		t.Errorf("a cancelled context reached the device %d times", n)
	}
}

// With verification on, the fake device's self-signed certificate is rejected. That
// proves insecure_tls: false really verifies.
func TestVerificationRejectsAnUntrustedCertificate(t *testing.T) {
	t.Parallel()
	tg := target(device().Start(t))
	tg.InsecureTLS = false
	err := NewClient(tg, nil).Keygen(context.Background(), testUser, testPass)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("want a certificate error, got %v", err)
	}
}

// R2. The client reads: it can ask for a key, run show commands and export the
// configuration, and nothing else reaches the device. The unexported opStream
// keeps the same guard.
func TestOnlyReadCalls(t *testing.T) {
	t.Parallel()
	d := device()
	c := loggedIn(t, d)
	for _, cmd := range []string{
		"<request><restart><system/></restart></request>",
		"<clear><session><all/></session></clear>",
		"<test><security-policy-match/></test>",
		" <show><system><info/></system></show>",
		"<set><cli/></set>",
	} {
		if _, err := c.Op(context.Background(), cmd); err == nil {
			t.Errorf("Op(%q) was allowed", cmd)
		}
		err := c.opStream(context.Background(), cmd, func(io.Reader) error {
			t.Errorf("opStream(%q) read an answer", cmd)
			return nil
		})
		if err == nil {
			t.Errorf("opStream(%q) was allowed", cmd)
		}
	}
	if n := len(d.Requests()); n != 1 {
		t.Errorf("a refused command reached the device: %d requests", n)
	}
	var methods []string
	ty := reflect.TypeFor[*Client]()
	for method := range ty.Methods() {
		methods = append(methods, method.Name)
	}
	if got := strings.Join(methods, ","); got != "ExportConfig,Keygen,Op" {
		t.Errorf("Client methods = %s; a new one needs R2 review", got)
	}
}

// A body cut off mid-read is a transport failure: retried once.
func TestATruncatedBodyIsRetried(t *testing.T) {
	t.Parallel()
	d := device()
	d.TruncateFirst = 1
	if err := quick(NewClient(target(d.Start(t)), nil)).Keygen(context.Background(), testUser, testPass); err != nil {
		t.Errorf("one truncated body must be survived: %v", err)
	}
	d2 := device()
	d2.TruncateFirst = 2
	if err := quick(NewClient(target(d2.Start(t)), nil)).Keygen(context.Background(), testUser, testPass); err == nil {
		t.Error("two truncated bodies must fail")
	}
}

func TestABadHostFailsBeforeSending(t *testing.T) {
	t.Parallel()
	if err := NewClient(target("bad host\x7f"), nil).Keygen(context.Background(), testUser, testPass); err == nil {
		t.Error("an unparseable host must fail")
	}
}

// quick shortens the pause before a retry, so the retry tests stay fast.
func quick(c *Client) *Client {
	c.retryWait = time.Millisecond
	return c
}

// A certificate that fails verification fails the same way twice, so the client
// does not try again.
func TestACertificateErrorIsNotRetried(t *testing.T) {
	t.Parallel()
	tg := target(device().Start(t))
	tg.InsecureTLS = false
	l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "fetch", Level: runlog.Debug})
	if err != nil {
		t.Fatal(err)
	}
	if err := quick(NewClient(tg, l)).Keygen(context.Background(), testUser, testPass); err == nil {
		t.Fatal("want a certificate error")
	}
	_ = l.Close()
	b, _ := os.ReadFile(l.Path())
	if strings.Count(string(b), ": attempt ") != 1 {
		t.Errorf("want one attempt, log:\n%s", b)
	}
}

// A run cancelled while the client waits to retry stops at once.
func TestACancelDuringTheRetryPauseStops(t *testing.T) {
	t.Parallel()
	d := device()
	d.DropFirst = 1
	c := NewClient(target(d.Start(t)), nil)
	c.retryWait = time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.Keygen(ctx, testUser, testPass)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Errorf("err = %v after %s", err, time.Since(start))
	}
}

// PAN-OS writes a refusal three ways, and an export answers with a bare <config>.
func TestCheckResponse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		refused bool
		code    string
		message string
	}{
		{"success", 200, `<response status="success"><result/></response>`, false, "", ""},
		{"a bare export", 200, `<config version="11.2.0"/>`, false, "", ""},
		{"an error with lines", 200, `<response status="error" code="17"><msg><line>invalid</line><line>syntax</line></msg></response>`, true, "17", "invalid syntax"},
		{"an error with text", 200, `<response status="error" code="12"><msg>no such node</msg></response>`, true, "12", "no such node"},
		{"a keygen refusal", 403, `<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>`, true, "403", "Invalid Credential"},
		{"an HTTP error without XML", 502, `Bad Gateway`, true, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkResponse(tc.status, []byte(tc.body))
			api, ok := errors.AsType[*APIError](err)
			if ok != tc.refused || (ok && (api.Code != tc.code || api.Message != tc.message || api.HTTPStatus != tc.status)) {
				t.Errorf("checkResponse = %#v", err)
			}
		})
	}
}
