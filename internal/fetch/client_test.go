package fetch

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/fakepanos"
	"github.com/okaiser/proteus/internal/inventory"
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
			"<show><system><info/></system></show>": fakepanos.Success("<system><hostname>lab</hostname></system>"),
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
	d := device()
	d.Key = ""
	c := NewClient(target(d.Start(t)), nil)
	if err := c.Keygen(context.Background(), testUser, testPass); err == nil {
		t.Error("a success without a key must be an error")
	}
}

func TestOpReturnsTheResponseVerbatim(t *testing.T) {
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
	e := &APIError{HTTPStatus: 502}
	if got := e.Error(); got != "device refused (HTTP 502): no message" {
		t.Errorf("Error() = %q", got)
	}
}

func TestExportConfigAcceptsABareConfig(t *testing.T) {
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
	c := NewClient(target(device().Start(t)), nil)
	if _, err := c.ExportConfig(context.Background()); err == nil {
		t.Error("a call before Keygen must fail")
	}
}

// A dropped connection is retried once; a second drop is the answer.
func TestOneRetryOnATransportError(t *testing.T) {
	d := device()
	d.DropFirst = 1
	c := NewClient(target(d.Start(t)), nil)
	if err := c.Keygen(context.Background(), testUser, testPass); err != nil {
		t.Fatalf("one drop must be survived: %v", err)
	}
	d2 := device()
	d2.DropFirst = 2
	c2 := NewClient(target(d2.Start(t)), nil)
	if err := c2.Keygen(context.Background(), testUser, testPass); err == nil {
		t.Error("two drops must fail")
	}
	if n := len(d2.Requests()); n != 2 {
		t.Errorf("got %d attempts, want 2", n)
	}
}

// A cancelled run stops at once rather than retrying.
func TestACancelledContextIsNotRetried(t *testing.T) {
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
	tg := target(device().Start(t))
	tg.InsecureTLS = false
	err := NewClient(tg, nil).Keygen(context.Background(), testUser, testPass)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("want a certificate error, got %v", err)
	}
}

// R2. The client reads: it can ask for a key, run show commands and export the
// configuration, and nothing else reaches the device.
func TestOnlyReadCalls(t *testing.T) {
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
	}
	if n := len(d.Requests()); n != 1 {
		t.Errorf("a refused command reached the device: %d requests", n)
	}
	var methods []string
	ty := reflect.TypeOf(c)
	for i := range ty.NumMethod() {
		methods = append(methods, ty.Method(i).Name)
	}
	if got := strings.Join(methods, ","); got != "ExportConfig,Keygen,Op" {
		t.Errorf("Client methods = %s; a new one needs R2 review", got)
	}
}

// A body cut off mid-read is a transport failure: retried once.
func TestATruncatedBodyIsRetried(t *testing.T) {
	d := device()
	d.TruncateFirst = 1
	if err := NewClient(target(d.Start(t)), nil).Keygen(context.Background(), testUser, testPass); err != nil {
		t.Errorf("one truncated body must be survived: %v", err)
	}
	d2 := device()
	d2.TruncateFirst = 2
	if err := NewClient(target(d2.Start(t)), nil).Keygen(context.Background(), testUser, testPass); err == nil {
		t.Error("two truncated bodies must fail")
	}
}

func TestABadHostFailsBeforeSending(t *testing.T) {
	if err := NewClient(target("bad host\x7f"), nil).Keygen(context.Background(), testUser, testPass); err == nil {
		t.Error("an unparseable host must fail")
	}
}
