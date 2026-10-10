package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPOptions configure the Streamable HTTP server (spec §4.4).
type HTTPOptions struct {
	// Token is the bearer token every request but /healthz must carry.
	Token string
	// AllowedHosts are the Host header values the server answers, without a
	// port; any other gives 403. None turns the Host check off: the token
	// makes DNS rebinding useless, so the check is defence in depth
	// (spec 2026-10-10 F6).
	AllowedHosts []string
}

// The HTTP limits of spec §4.4.
const (
	maxBody           = 1 << 20  // MiB; more gives 413 (S6)
	maxHeader         = 16 << 10 // KiB; more gives 431
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	// writeSlack is added to the call timeout and the maximum wait: a call's
	// answer is written within their sum and this.
	writeSlack = 10 * time.Second
)

// ServeHTTP answers MCP calls over Streamable HTTP on ln, in plain text
// behind a reverse proxy that terminates TLS, until ctx ends (spec §4.4).
// Every request but /healthz must carry the token (401) and, when allowed
// hosts are set, name one of them (403); refusals are audited, rate-limited
// per address. When ctx ends
// (SIGTERM), new calls answer call.busy, the running calls get up to the
// call timeout to answer, the server shuts down, and ServeHTTP returns.
func ServeHTTP(ctx context.Context, o Options, h HTTPOptions, ln net.Listener) error {
	if h.Token == "" {
		_ = ln.Close()
		return errors.New("mcp: --http needs a token")
	}
	s, lim, err := build(o, testing.Testing())
	if err != nil {
		_ = ln.Close()
		return err
	}
	srv := newHTTPServer(s, o, h, lim)
	ref := srv.Handler.(*guard).refusals
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	tick := time.NewTicker(refusalWindow / 2)
	defer tick.Stop()
	for stopping := false; !stopping; {
		select {
		case err := <-served:
			// The listener failed. Close ends the connections it left.
			lim.stop()
			_ = srv.Close()
			ref.flush(true)
			return err
		case <-tick.C:
			ref.flush(false)
		case <-ctx.Done():
			stopping = true
		}
	}
	lim.stop()
	// Shutdown waits for every response in flight to be written, then closes
	// the connections: no timed grace as over stdio. The call timeout bounds
	// the wait for a call that stop gave up on.
	sctx, cancel := context.WithTimeout(context.Background(), lim.timeout)
	defer cancel()
	if srv.Shutdown(sctx) != nil {
		// The deadline passed: close the connections still open.
		_ = srv.Close()
	}
	<-served
	ref.flush(true)
	return ctx.Err()
}

// newHTTPServer is the http.Server of spec §4.4 over s: the guard, then the
// SDK's stateless handler.
func newHTTPServer(s *sdk.Server, o Options, h HTTPOptions, lim *limiter) *http.Server {
	sdkHandler := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{
		Stateless:           true,
		MaxRequestBodyBytes: maxBody,
		// The guard checks the Host against allowed_hosts instead: behind a
		// proxy the loopback-only check refuses every request (S5).
		DisableLocalhostProtection: true,
		// The handler ends when the client goes, for clients of protocol
		// 2026-07-28 on; for older ones the call timeout is the bound (S4).
		PropagateRequestCancellation: true,
	})
	now := o.Now
	if now == nil {
		now = time.Now
	}
	g := &guard{
		next: sdkHandler, digest: sha256.Sum256([]byte(h.Token)),
		hosts:    map[string]bool{},
		refusals: &refusals{audit: o.Audit, now: now, by: map[string]*refusalCount{}},
	}
	for _, host := range h.AllowedHosts {
		g.hosts[strings.ToLower(host)] = true
	}
	return &http.Server{
		Handler:           g,
		ReadHeaderTimeout: readHeaderTimeout,
		MaxHeaderBytes:    maxHeader,
		WriteTimeout:      lim.timeout + lim.maxWait + writeSlack,
		IdleTimeout:       idleTimeout,
	}
}

// equal compares two token digests in constant time; a test counts its uses.
var equal = subtle.ConstantTimeCompare

// guard checks each request before the SDK sees it: the Host, then the
// bearer token. /healthz needs neither.
type guard struct {
	next   http.Handler
	digest [32]byte // SHA-256 of the token
	// hosts are the allowed Host values; empty accepts every Host.
	hosts    map[string]bool
	refusals *refusals
}

func (g *guard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if len(g.hosts) > 0 && !g.hosts[hostOf(r.Host)] {
		g.refusals.refuse(remoteOf(r), http.StatusForbidden)
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	if !g.authorised(r.Header.Get("Authorization")) {
		g.refusals.refuse(remoteOf(r), http.StatusUnauthorized)
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorised", http.StatusUnauthorized)
		return
	}
	g.next.ServeHTTP(w, r)
}

// authorised reports whether an Authorization value carries the token. It
// compares SHA-256 digests in constant time, so neither the token's length
// nor its content shows in the time the check takes.
func (g *guard) authorised(header string) bool {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		token = ""
	}
	d := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return equal(d[:], g.digest[:]) == 1 && token != ""
}

// hostOf is a Host header value without its port, in lower case.
func hostOf(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
}

// remoteOf is the client's address without its port: behind the proxy, the
// proxy's.
func remoteOf(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// The audit bound for refused requests (spec §4.9): at most refusalLimit
// lines per address in each refusalWindow; a summary line counts the rest.
const (
	refusalLimit  = 10
	refusalWindow = time.Minute
	// maxRefusers bounds the addresses counted apart; the refusals of any
	// further address count under "other".
	maxRefusers = 4096
)

// refusals audits refused requests, rate-limited per address.
type refusals struct {
	audit Auditor
	now   func() time.Time

	mu sync.Mutex
	by map[string]*refusalCount
}

// refusalCount is one address's refusals in its current window.
type refusalCount struct {
	start    time.Time
	audited  int
	dropped  int
	lastCode int
}

// refuse audits a refused request from remote with its HTTP status, unless
// the address passed its limit in this window.
func (r *refusals) refuse(remote string, code int) {
	if r.audit == nil {
		return
	}
	now := r.now()
	var summary *Call
	r.mu.Lock()
	n := r.by[remote]
	if n == nil && len(r.by) >= maxRefusers {
		remote = "other"
		n = r.by[remote]
	}
	if n != nil && now.Sub(n.start) >= refusalWindow {
		// This address's window is over: its summary, then a new window. The
		// ticker ends the windows of the addresses that went quiet.
		summary = n.summary(remote, now)
		n = nil
		delete(r.by, remote)
	}
	if n == nil {
		n = &refusalCount{start: now}
		r.by[remote] = n
	}
	n.lastCode = code
	audit := n.audited < refusalLimit
	if audit {
		n.audited++
	} else {
		n.dropped++
	}
	r.mu.Unlock()
	if summary != nil {
		r.audit.Audit(*summary)
	}
	if !audit {
		return
	}
	r.audit.Audit(Call{
		Time: now, Identity: Identity{Auth: AuthToken, Source: SourceNone}, Remote: remote,
		Status: StatusUnauthorised, HTTPStatus: code,
	})
}

// flush ends the windows that are over, all of them when all is set, and
// writes a summary line for each address that had refusals not audited.
func (r *refusals) flush(all bool) {
	if r.audit == nil {
		return
	}
	now := r.now()
	var lines []Call
	r.mu.Lock()
	for remote, n := range r.by {
		if !all && now.Sub(n.start) < refusalWindow {
			continue
		}
		delete(r.by, remote)
		if c := n.summary(remote, now); c != nil {
			lines = append(lines, *c)
		}
	}
	r.mu.Unlock()
	for _, c := range lines {
		r.audit.Audit(c)
	}
}

// summary is the line that counts the refusals of remote not audited in
// this window; nil when there were none.
func (n *refusalCount) summary(remote string, now time.Time) *Call {
	if n.dropped == 0 {
		return nil
	}
	return &Call{
		Time: now, Identity: Identity{Auth: AuthToken, Source: SourceNone}, Remote: remote,
		Status: StatusUnauthorised, HTTPStatus: n.lastCode, Refused: n.dropped,
	}
}
