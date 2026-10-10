package mcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
)

// testToken is a dummy bearer token of 32 bytes.
const testToken = "0123456789abcdef0123456789abcdef"

// httpLab serves the path lab over HTTP on a loopback listener until the
// test ends, and returns its URL, the audit and a stop that ends the
// server and returns ServeHTTP's error.
func httpLab(t *testing.T, o Options) (string, *recorder, func() error) {
	t.Helper()
	return httpLabOn(t, o, nil)
}

// httpLabOn is httpLab with the listener passed through wrap first, when set.
func httpLabOn(t *testing.T, o Options, wrap func(net.Listener) net.Listener) (string, *recorder, func() error) {
	t.Helper()
	rec := &recorder{}
	if o.Env.Inventory == nil {
		o.Env = labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	}
	if o.Audit == nil {
		o.Audit = rec
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if wrap != nil {
		ln = wrap(ln)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeHTTP(ctx, o, HTTPOptions{Token: testToken, AllowedHosts: []string{"127.0.0.1", "Proteus.Example.Org"}}, ln)
	}()
	var once sync.Once
	var served error
	stop := func() error {
		once.Do(func() { cancel(); served = <-done })
		return served
	}
	t.Cleanup(func() { _ = stop() })
	return "http://" + ln.Addr().String() + "/", rec, stop
}

// headers adds fixed headers to each request.
type headers struct {
	set  map[string]string
	next http.RoundTripper
}

func (h headers) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.set {
		r.Header.Set(k, v)
	}
	return h.next.RoundTrip(r)
}

// httpClient connects an SDK client to url with the token and extra headers.
func httpClient(t *testing.T, url string, extra map[string]string) *sdk.ClientSession {
	t.Helper()
	set := map[string]string{"Authorization": "Bearer " + testToken}
	for k, v := range extra {
		set[k] = v
	}
	tr := &sdk.StreamableClientTransport{
		Endpoint: url, DisableStandaloneSSE: true, MaxRetries: -1,
		HTTPClient: &http.Client{Transport: headers{set: set, next: http.DefaultTransport}},
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "client", Version: "test"}, nil).Connect(context.Background(), tr, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// A call over HTTP answers like one over any transport, and its audit record
// carries the identity the header claims.
func TestServeHTTPAnswersACall(t *testing.T) {
	t.Parallel()
	o := Options{Identify: HeaderIdentity("X-User-Claims", []string{"sub", "email"})}
	url, rec, stop := httpLab(t, o)
	cs := httpClient(t, url, map[string]string{"X-User-Claims": `{"sub":"alice","email":"alice@example.test","role":"admin"}`})
	res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
		Name:      "simulate_routing",
		Arguments: map[string]any{"source": pathlab.Source, "destination": pathlab.Destination, "port": 443},
	})
	if err != nil || res.IsError {
		t.Fatalf("call: %v %+v", err, res)
	}
	c := rec.last(t)
	want := Identity{Auth: AuthToken, Source: SourceHeader, Claims: map[string]string{"sub": "alice", "email": "alice@example.test"}}
	if c.Status != StatusOK || c.Tool != "simulate_routing" || fmt.Sprint(c.Identity) != fmt.Sprint(want) {
		t.Errorf("audit %+v", c)
	}
	if err := stop(); !errors.Is(err, context.Canceled) {
		t.Errorf("ServeHTTP returned %v", err)
	}
}

// The Host check comes first (403), then the token (401); /healthz needs
// neither. Every refusal is audited.
func TestTheGuard(t *testing.T) {
	t.Parallel()
	url, rec, _ := httpLab(t, Options{})
	post := func(host, auth string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if host != "" {
			req.Host = host
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		return res.StatusCode, res.Header.Get("WWW-Authenticate")
	}
	for _, tc := range []struct {
		name, host, auth string
		want             int
	}{
		{"other host", "evil.example.test", "Bearer " + testToken, http.StatusForbidden},
		{"other host without a token", "evil.example.test:8765", "", http.StatusForbidden},
		{"no token", "", "", http.StatusUnauthorized},
		{"wrong token", "", "Bearer " + strings.Repeat("x", 32), http.StatusUnauthorized},
		{"token prefix", "", "Bearer " + testToken[:31], http.StatusUnauthorized},
		{"other scheme", "", "Basic " + testToken, http.StatusUnauthorized},
		{"empty bearer", "", "Bearer ", http.StatusUnauthorized},
		{"allowed host with a port", "proteus.example.org:443", "Bearer " + testToken, http.StatusOK},
		{"loopback host", "", "bearer " + testToken, http.StatusOK},
	} {
		if code, challenge := post(tc.host, tc.auth); code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, code, tc.want)
		} else if tc.want == http.StatusUnauthorized && challenge != "Bearer" {
			t.Errorf("%s: WWW-Authenticate %q", tc.name, challenge)
		}
	}
	rec.mu.Lock()
	var codes []int
	for _, c := range rec.calls {
		if c.Status != StatusUnauthorised || c.Remote != "127.0.0.1" || c.Identity.Auth != AuthToken {
			t.Errorf("refusal audited as %+v", c)
		}
		codes = append(codes, c.HTTPStatus)
	}
	rec.mu.Unlock()
	if want := []int{403, 403, 401, 401, 401, 401, 401}; !slices.Equal(codes, want) {
		t.Errorf("audited %v, want %v", codes, want)
	}

	// /healthz: no Host check, no token, 200 and no body.
	req, _ := http.NewRequest(http.MethodGet, url+"healthz", nil)
	req.Host = "anything.example.test"
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || len(body) != 0 {
		t.Errorf("healthz: %d %q", res.StatusCode, body)
	}
}

// The token check compares digests in constant time. Not parallel: it
// counts the uses of the package's compare.
//
//nolint:paralleltest // it replaces the package's compare
func TestTheTokenCompareIsConstantTime(t *testing.T) {
	var n int
	old := equal
	equal = func(a, b []byte) int {
		n++
		if len(a) != 32 || len(b) != 32 {
			t.Errorf("compared %d and %d bytes, want two SHA-256 digests", len(a), len(b))
		}
		return old(a, b)
	}
	defer func() { equal = old }()
	g := &guard{}
	g.digest = sha256.Sum256([]byte(testToken))
	for _, h := range []string{"Bearer " + testToken, "Bearer short", "", "Basic x"} {
		g.authorised(h)
	}
	if n != 4 {
		t.Errorf("the constant-time compare ran %d times for 4 checks", n)
	}
	if !g.authorised("Bearer "+testToken) || g.authorised("Bearer "+testToken+"x") {
		t.Error("the compare decides wrongly")
	}
}

// A body above 1 MiB gives 413; headers above 16 KiB give 431.
func TestHTTPLimits(t *testing.T) {
	t.Parallel()
	url, _, _ := httpLab(t, Options{})
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("x", maxBody) + `"}}`
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+testToken)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("a big body: %d", res.StatusCode)
	}

	// net/http answers 431 itself; it allows 4 KiB above MaxHeaderBytes.
	conn, err := net.Dial("tcp", strings.TrimSuffix(strings.TrimPrefix(url, "http://"), "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: %s\r\n\r\n", strings.Repeat("y", maxHeader+8<<10))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("big headers: %d", resp.StatusCode)
	}
}

// Without allowed hosts the guard accepts every Host, and still wants the
// token (spec 2026-10-10 F6).
func TestTheGuardWithoutHosts(t *testing.T) {
	t.Parallel()
	env := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)})
	s, lim, err := build(Options{Env: env}, true)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	srv := newHTTPServer(s, Options{Audit: rec}, HTTPOptions{Token: testToken}, lim)
	for _, tc := range []struct {
		name, host, auth string
		want             int
	}{
		{"any host", "evil.example.test", "Bearer " + testToken, http.StatusOK},
		{"any host with a port", "anything.example.test:8443", "Bearer " + testToken, http.StatusOK},
		{"no token", "proteus.example.org", "", http.StatusUnauthorized},
		{"wrong token", "proteus.example.org", "Bearer " + strings.Repeat("x", 32), http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Host = tc.host
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, w.Code, tc.want)
		}
	}
}

// The server's timeouts and the SDK's options are those of spec §4.4.
func TestTheHTTPServerSettings(t *testing.T) {
	t.Parallel()
	env := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)})
	s, lim, err := build(Options{Env: env, Limits: Limits{CallTimeout: 30 * time.Second, MaxWait: 5 * time.Second}}, true)
	if err != nil {
		t.Fatal(err)
	}
	srv := newHTTPServer(s, Options{}, HTTPOptions{Token: testToken, AllowedHosts: []string{"a"}}, lim)
	if srv.ReadHeaderTimeout != 10*time.Second || srv.MaxHeaderBytes != 16<<10 || srv.IdleTimeout != 120*time.Second ||
		srv.WriteTimeout != 45*time.Second {
		t.Errorf("server %+v", srv)
	}
	// ServeHTTP refuses to serve without a token.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ServeHTTP(context.Background(), Options{Env: env}, HTTPOptions{AllowedHosts: []string{"a"}}, ln); err == nil {
		t.Error("served without a token")
	}
	if _, err := ln.Accept(); err == nil {
		t.Error("the listener stays open")
	}
	// Nor without a device to answer for.
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ServeHTTP(context.Background(), Options{}, HTTPOptions{Token: testToken, AllowedHosts: []string{"a"}}, ln); err == nil {
		t.Error("served without an inventory")
	}
}

// A listener that fails ends ServeHTTP with its error.
func TestServeHTTPEndsWithItsListener(t *testing.T) {
	t.Parallel()
	env := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- ServeHTTP(context.Background(), Options{Env: env}, HTTPOptions{Token: testToken, AllowedHosts: []string{"a"}}, ln)
	}()
	time.Sleep(20 * time.Millisecond)
	_ = ln.Close()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			t.Errorf("ServeHTTP returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeHTTP did not return")
	}
}

// Shutdown waits for the running call to answer over HTTP before the server
// closes, and refuses new calls meanwhile.
func TestServeHTTPDrainsOnShutdown(t *testing.T) {
	t.Parallel()
	env := labEnv(t, snap{pathlab.FW01, pathlab.ConfigFile(pathlab.FW01)}, snap{pathlab.FW02, pathlab.ConfigFile(pathlab.FW02)})
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	env.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		once.Do(func() { close(started) })
		<-release
		return []netip.Addr{netip.MustParseAddr(pathlab.Destination)}, nil
	}
	url, _, stop := httpLab(t, Options{Env: env})
	cs := httpClient(t, url, nil)
	type answer struct {
		res *sdk.CallToolResult
		err error
	}
	answered := make(chan answer, 1)
	go func() {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
			Name:      "simulate_routing",
			Arguments: map[string]any{"source": pathlab.Source, "destination": "slow.example.test", "port": 443},
		})
		answered <- answer{res, err}
	}()
	<-started
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	// While the running call holds its slot, a new call is busy.
	eventually(t, "new calls are refused", func() bool {
		res, err := cs.CallTool(context.Background(), &sdk.CallToolParams{
			Name: "search", Arguments: map[string]any{"value": "dc01"},
		})
		return err == nil && res.IsError && strings.Contains(fmt.Sprint(res.StructuredContent), "call.busy")
	})
	close(release)
	// The call in flight at the stop gets its whole answer.
	if a := <-answered; a.err != nil || a.res.IsError || !strings.Contains(fmt.Sprint(a.res.StructuredContent), "envelope:map[") {
		t.Errorf("the running call: %v %+v", a.err, a.res)
	}
	if err := <-stopped; !errors.Is(err, context.Canceled) {
		t.Errorf("ServeHTTP returned %v", err)
	}
}

// A request still open when the shutdown deadline (the call timeout) passes
// is cut: the server closes its connection and ServeHTTP returns.
func TestServeHTTPClosesWhatOutlivesTheShutdown(t *testing.T) {
	t.Parallel()
	waiting := make(chan struct{})
	url, _, stop := httpLabOn(t, Options{Limits: Limits{CallTimeout: 100 * time.Millisecond}}, func(ln net.Listener) net.Listener {
		return &secondRead{Listener: ln, waiting: waiting}
	})
	conn, err := net.Dial("tcp", strings.TrimSuffix(strings.TrimPrefix(url, "http://"), "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A body that never arrives in full keeps the request active.
	if _, err := fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer %s\r\n"+
		"Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: 1000\r\n\r\n{", testToken); err != nil {
		t.Fatal(err)
	}
	// The handler reads the body: the request is active, not new.
	select {
	case <-waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("the server never read the body")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("ServeHTTP returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the open request held the shutdown")
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	// Closed: the read ends at once, with EOF or a reset, not the deadline.
	if _, err := io.ReadAll(conn); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("the connection was not closed: %v", err)
	}
}

// secondRead closes waiting when the first connection it accepts is read a
// second time: the first read takes the headers and the body's first byte,
// the second waits for the rest of the body.
type secondRead struct {
	net.Listener
	waiting chan struct{}
	once    sync.Once
}

func (l *secondRead) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &readCount{Conn: c, l: l}, nil
}

type readCount struct {
	net.Conn
	l     *secondRead
	reads atomic.Int32
}

func (c *readCount) Read(b []byte) (int, error) {
	if c.reads.Add(1) == 2 {
		c.l.once.Do(func() { close(c.l.waiting) })
	}
	return c.Conn.Read(b)
}

// Refusals are audited at most 10 per minute per address; a summary line
// counts the rest when the window ends.
func TestRefusalsAreRateLimited(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	rec := &recorder{}
	r := &refusals{audit: rec, now: func() time.Time { return now }, by: map[string]*refusalCount{}}
	for range 15 {
		r.refuse("198.18.0.1", http.StatusUnauthorized)
	}
	r.refuse("198.18.0.2", http.StatusForbidden)
	count := func() (lines, summaries, refused int) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		for _, c := range rec.calls {
			lines++
			if c.Refused > 0 {
				summaries++
				refused += c.Refused
			}
		}
		return
	}
	if l, s, _ := count(); l != 11 || s != 0 {
		t.Fatalf("%d lines, %d summaries; want 11 and 0", l, s)
	}
	r.flush(false)
	if l, _, _ := count(); l != 11 {
		t.Fatalf("a flush inside the window wrote %d lines", l-11)
	}
	now = now.Add(refusalWindow)
	r.flush(false)
	if l, s, n := count(); l != 12 || s != 1 || n != 5 {
		t.Fatalf("after the window: %d lines, %d summaries of %d", l, s, n)
	}
	sum := rec.last(t)
	if sum.Remote != "198.18.0.1" || sum.HTTPStatus != http.StatusUnauthorized || sum.Status != StatusUnauthorised {
		t.Errorf("summary %+v", sum)
	}
	// A new window audits again.
	r.refuse("198.18.0.1", http.StatusUnauthorized)
	if l, _, _ := count(); l != 13 {
		t.Errorf("the new window audits: %d lines", l)
	}
	// Past maxRefusers addresses, the rest count as one.
	for i := range maxRefusers + 3 {
		r.refuse(fmt.Sprintf("198.19.%d.%d", i/256, i%256), http.StatusUnauthorized)
	}
	r.mu.Lock()
	n, other := len(r.by), r.by["other"]
	r.mu.Unlock()
	if n > maxRefusers+1 || other == nil {
		t.Errorf("%d addresses kept, other %+v", n, other)
	}
	r.flush(true)
	r.mu.Lock()
	if len(r.by) != 0 {
		t.Errorf("a final flush keeps %d", len(r.by))
	}
	r.mu.Unlock()
	// A refusal past its address's window writes that address's summary
	// first; another address's window waits for the ticker's flush.
	rec2 := &recorder{}
	r2 := &refusals{audit: rec2, now: func() time.Time { return now }, by: map[string]*refusalCount{}}
	for range refusalLimit + 2 {
		r2.refuse("198.18.0.1", http.StatusUnauthorized)
		r2.refuse("198.18.0.2", http.StatusForbidden)
	}
	now = now.Add(refusalWindow)
	r2.refuse("198.18.0.1", http.StatusUnauthorized)
	rec2.mu.Lock()
	got := rec2.calls[2*refusalLimit:]
	rec2.mu.Unlock()
	if len(got) != 2 || got[0].Remote != "198.18.0.1" || got[0].Refused != 2 || got[1].Refused != 0 {
		t.Errorf("after the window: %+v", got)
	}
	r2.mu.Lock()
	if n := r2.by["198.18.0.2"]; n == nil || n.dropped != 2 {
		t.Errorf("the other address's window: %+v", n)
	}
	r2.mu.Unlock()
	// Without an audit, nothing is counted.
	quiet := &refusals{now: time.Now, by: map[string]*refusalCount{}}
	quiet.refuse("198.18.0.1", http.StatusUnauthorized)
	quiet.flush(true)
	if len(quiet.by) != 0 {
		t.Error("counted without an audit")
	}
}

func TestHostOf(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"Proteus.Example.Org": "proteus.example.org", "proteus.example.org:8765": "proteus.example.org",
		"[::1]:8765": "::1", "[::1]": "::1", "127.0.0.1": "127.0.0.1",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "pipe"
	if remoteOf(r) != "pipe" {
		t.Errorf("remoteOf without a port: %q", remoteOf(r))
	}
}

// The identity header is read as JSON; each claim is cut to 256 bytes; a
// missing or broken header is the identity unknown.
func TestHeaderIdentity(t *testing.T) {
	t.Parallel()
	id := HeaderIdentity("X-User-Claims", []string{"sub", "groups", "name", "absent"})
	long := strings.Repeat("é", 200) // 400 bytes
	h := http.Header{}
	h.Set("X-User-Claims", `{"sub":"alice","groups":["a","b"],"name":"`+long+`","other":"x"}`)
	got := id(h)
	if got.Auth != AuthToken || got.Source != SourceHeader || got.Claims["sub"] != "alice" || got.Claims["groups"] != `["a","b"]` {
		t.Errorf("identity %+v", got)
	}
	if n := got.Claims["name"]; len(n) != 256 || n != long[:256] {
		t.Errorf("cut claim: %d bytes", len(n))
	}
	if _, ok := got.Claims["other"]; ok {
		t.Error("an unaudited claim is kept")
	}
	if _, ok := got.Claims["absent"]; ok {
		t.Error("an absent claim is set")
	}
	for _, v := range []string{"", "not json", `["a"]`, "null"} {
		h := http.Header{}
		if v != "" {
			h.Set("X-User-Claims", v)
		}
		if got := id(h); got.Source != SourceNone || got.Claims != nil || got.Auth != AuthToken {
			t.Errorf("%q: identity %+v", v, got)
		}
	}
	// A JSON object with none of the audited claims: unknown, from the header.
	h = http.Header{}
	h.Set("X-User-Claims", `{"email":"bob@example.test"}`)
	if got := id(h); got.Source != SourceHeader || got.Claims != nil {
		t.Errorf("no audited claim: %+v", got)
	}
	if l := lineOf(Call{Identity: id(h)}); l.Identity != "unknown" || l.IdentitySource != SourceHeader {
		t.Errorf("no audited claim, line %+v", l)
	}
	if got := HeaderIdentity("", nil)(nil); got.Source != SourceNone {
		t.Errorf("no header name: %+v", got)
	}
	if got := StdioIdentity("operator")(nil); got.Auth != AuthStdio || got.Source != SourceOS || got.Claims["user"] != "operator" {
		t.Errorf("stdio identity %+v", got)
	}
	// A cut keeps whole characters.
	if got := cut("aé", 2); got != "a" {
		t.Errorf("cut = %q", got)
	}
}

// Each call is one JSON line with the fields of spec §4.9, appended to a
// file of mode 0600; concurrent writers keep their lines whole.
func TestTheAuditLog(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// An existing file others can read is made 0600.
	if err := os.WriteFile(path, []byte(`{"earlier":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAudit(path, Rotation{})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 10, 10, 9, 0, 0, 0, time.FixedZone("x", 3600))
	a.Audit(Call{
		Time: when, Tool: "search", Input: json.RawMessage(`{"value":"dc01"}`), Status: StatusOK,
		Answers: []string{"found"}, Codes: []reason.Code{"note.stale"}, Snapshots: []string{"fw01@1"},
		Duration: 1500 * time.Millisecond, Identity: Identity{Auth: AuthToken, Source: SourceHeader, Claims: map[string]string{"sub": "alice"}},
	})
	a.Audit(Call{Time: when, Status: StatusUnauthorised, Remote: "198.18.0.1", HTTPStatus: 401, Identity: Identity{Auth: AuthToken, Source: SourceNone}})
	a.Audit(Call{Time: when, Tool: "lookup", Input: json.RawMessage(`{broken`), Status: StatusUsage, Code: "call.usage"})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() { a.Audit(Call{Time: when, Tool: fmt.Sprintf("t%d", i), Status: StatusOK}) })
	}
	wg.Wait()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 54 || lines[0] != `{"earlier":true}` {
		t.Fatalf("%d lines, first %q", len(lines), lines[0])
	}
	for _, l := range lines {
		if !json.Valid([]byte(l)) {
			t.Errorf("not a JSON line: %q", l)
		}
	}
	want := `{"time":"2026-10-10T08:00:00Z","auth":"token","identity_source":"header","identity":{"sub":"alice"},"tool":"search",` +
		`"input":{"value":"dc01"},"verdict":["found"],"codes":["note.stale"],"snapshots":["fw01@1"],"duration_ms":1500,"status":"ok"}`
	if lines[1] != want {
		t.Errorf("line\n%s\nwant\n%s", lines[1], want)
	}
	want = `{"time":"2026-10-10T08:00:00Z","auth":"token","identity_source":"none","identity":"unknown","remote":"198.18.0.1","tool":"",` +
		`"input":null,"verdict":[],"codes":[],"snapshots":[],"duration_ms":0,"status":"unauthorised","http_status":401}`
	if lines[2] != want {
		t.Errorf("line\n%s\nwant\n%s", lines[2], want)
	}
	if !strings.Contains(lines[3], `"input":"{broken"`) || !strings.Contains(lines[3], `"code":"call.usage"`) {
		t.Errorf("line %s", lines[3])
	}

	// A write that fails reaches OnError.
	var got error
	a.OnError = func(err error) { got = err }
	a.Audit(Call{})
	if got == nil {
		t.Error("a failed write was not reported")
	}
	a.OnError = nil
	a.Audit(Call{}) // dropped without a handler
	if _, err := OpenAudit(filepath.Join(t.TempDir(), "no", "such", "dir", "audit.jsonl"), Rotation{}); err == nil {
		t.Error("opened an audit file in a missing directory")
	}
}
