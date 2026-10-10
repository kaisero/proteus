package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/runlog"
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
// hosts are set, name one of them (403). Refusals are not audited: the
// process log counts them by status once a minute. When ctx ends (SIGTERM),
// new calls answer call.busy, the running calls get up to the call timeout
// to answer, the server shuts down, and ServeHTTP returns.
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
	// The ticker checks often; flush writes once a minute has passed.
	tick := time.NewTicker(refusalWindow / 6)
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
		// Behind a proxy the loopback-only check refuses every request (S5).
		// The guard checks the Host instead, when allowed_hosts is set.
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
		refusals: &refusals{log: o.Log, now: now, by: map[int]int{}},
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
		g.refusals.refuse(http.StatusForbidden)
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	if !g.authorised(r.Header.Get("Authorization")) {
		g.refusals.refuse(http.StatusUnauthorized)
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

// refusalWindow is how often, at most, the process log counts the refused
// requests (spec 2026-10-10 F5).
const refusalWindow = time.Minute

// refusals counts refused requests by HTTP status. They are not audited one
// by one: behind the proxy every request has the proxy's address, the
// gateway logs its users and the proxy logs direct scans. A count shows a
// token or Host fault (spec 2026-10-10 F5).
type refusals struct {
	log *runlog.Logger
	now func() time.Time

	mu    sync.Mutex
	start time.Time   // the first refusal not yet logged
	by    map[int]int // HTTP status -> refusals
}

// refuse counts a refused request with its HTTP status.
func (r *refusals) refuse(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.by) == 0 {
		r.start = r.now()
	}
	r.by[code]++
}

// flush writes one warn line with the counts by status since the last such
// line, once a minute has passed since the first refusal it counts, or at
// once when all is set; then it counts from zero. Without a refusal it
// writes nothing.
func (r *refusals) flush(all bool) {
	r.mu.Lock()
	if len(r.by) == 0 || !all && r.now().Sub(r.start) < refusalWindow {
		r.mu.Unlock()
		return
	}
	codes := slices.Sorted(maps.Keys(r.by))
	parts := make([]string, 0, len(codes))
	for _, code := range codes {
		parts = append(parts, fmt.Sprintf("%d ×%d", code, r.by[code]))
	}
	clear(r.by)
	r.mu.Unlock()
	r.log.Warnf(runlog.TagRun, "mcp: refused since the last report: %s", strings.Join(parts, ", "))
}
