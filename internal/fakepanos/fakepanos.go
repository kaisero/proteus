// Package fakepanos is a stand-in PAN-OS XML API for tests. It answers keygen, a
// fixed set of show commands and a configuration export over TLS on 127.0.0.1, and
// records every request so a test can check what was sent and what was not.
package fakepanos

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Device is one fake firewall.
type Device struct {
	User, Password, Key string
	// Ops maps a show command to the full response body the device returns for it.
	// A command not listed gets the device's syntax-error refusal.
	Ops map[string]string
	// Config is the body of a configuration export.
	Config string
	// DropFirst closes the connection without an answer on the first N requests,
	// which a client sees as a transport error.
	DropFirst int
	// TruncateFirst promises a longer body than it sends on the first N
	// requests, then closes the connection, which a client sees while reading.
	TruncateFirst int
	// Stall names a request type, such as "export", that the device never answers:
	// it waits until the client gives up, as a hung device does.
	Stall string

	mu       sync.Mutex
	requests []Request
}

// Request is one request as the device received it.
type Request struct {
	Method, Type, Cmd, Key, RawQuery, Body string
}

// Success wraps a result the way PAN-OS does.
func Success(inner string) string {
	return `<response status="success"><result>` + inner + `</result></response>`
}

// Refusal is a PAN-OS error response.
func Refusal(code, msg string) string {
	return fmt.Sprintf(`<response status="error" code="%s"><msg><line>%s</line></msg></response>`, code, msg)
}

// Start serves the device until the test ends and returns its host:port.
func (d *Device) Start(tb testing.TB) string {
	tb.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(d.serve))
	tb.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

// Requests returns every request received so far.
func (d *Device) Requests() []Request {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Request{}, d.requests...)
}

func (d *Device) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	_ = r.ParseForm()

	d.mu.Lock()
	d.requests = append(d.requests, Request{
		Method: r.Method, Type: r.Form.Get("type"), Cmd: r.Form.Get("cmd"),
		Key: r.Header.Get("X-PAN-KEY"), RawQuery: r.URL.RawQuery, Body: string(body),
	})
	drop := d.DropFirst > 0
	if drop {
		d.DropFirst--
	}
	truncate := !drop && d.TruncateFirst > 0
	if truncate {
		d.TruncateFirst--
	}
	d.mu.Unlock()

	if d.Stall != "" && r.Form.Get("type") == d.Stall {
		<-r.Context().Done()
		return
	}

	if truncate {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, buf, err := hj.Hijack(); err == nil {
				_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n<response")
				_ = buf.Flush()
				_ = conn.Close()
				return
			}
		}
	}

	if drop {
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
	}

	if r.Form.Get("type") == "keygen" {
		if r.Form.Get("user") != d.User || r.Form.Get("password") != d.Password {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>`)
			return
		}
		_, _ = io.WriteString(w, Success("<key>"+d.Key+"</key>"))
		return
	}
	if r.Header.Get("X-PAN-KEY") != d.Key {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, Refusal("403", "Invalid credentials."))
		return
	}
	switch r.Form.Get("type") {
	case "op":
		resp, ok := d.Ops[r.Form.Get("cmd")]
		if !ok {
			_, _ = io.WriteString(w, Refusal("17", "show -> invalid syntax"))
			return
		}
		_, _ = io.WriteString(w, resp)
	case "export":
		if r.Form.Get("category") != "configuration" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, Refusal("400", "unsupported export"))
			return
		}
		_, _ = io.WriteString(w, d.Config)
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, Refusal("400", "unsupported type"))
	}
}
