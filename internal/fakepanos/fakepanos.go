// Package fakepanos is a stand-in PAN-OS XML API for tests. It answers keygen, a
// fixed set of show commands, the running configuration, the pushed template,
// the predefined services, the App-ID data and a configuration export over TLS
// on 127.0.0.1, and records every request so a test can check what was sent
// and what was not.
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
	// Config is the configuration: the body of an export, and the config
	// element of the answer to RunningConfigCmd, unless Ops names the command.
	Config string
	// Template is the template element of the answer to PushedTemplateCmd,
	// unless Ops names the command. Empty answers NoTemplate, as a device
	// without a template does.
	Template string
	// DropFirst closes the connection without an answer on the first N requests,
	// which a client sees as a transport error.
	DropFirst int
	// DropCmd maps an op command to the number of its requests to drop without
	// an answer, which a client sees as a transport error.
	DropCmd map[string]int
	// TruncateFirst promises a longer body than it sends on the first N
	// requests, then closes the connection, which a client sees while reading.
	TruncateFirst int
	// Stall names a request type, such as "export", or an op command that the
	// device never answers: it waits until the client gives up, as a hung
	// device does.
	Stall string

	mu       sync.Mutex
	requests []Request
}

// Request is one request as the device received it.
type Request struct {
	Method, Type, Cmd, Key, RawQuery, Body string
}

// PredefinedCmd asks a device for its predefined services.
const PredefinedCmd = "<show><predefined><xpath>/predefined/service</xpath></predefined></show>"

// PredefinedServices is a device's answer to PredefinedCmd, as fw02 gave it on
// PAN-OS 12.2.3 (L4). Every fake device answers it unless Ops names the command.
const PredefinedServices = `<response status="success"><result><service>` +
	`<entry name="service-http"><protocol><tcp><port>80,8080</port></tcp></protocol></entry>` +
	`<entry name="service-https"><protocol><tcp><port>443</port></tcp></protocol></entry>` +
	`</service></result></response>`

// ApplicationsCmd and ContainersCmd ask a device for its App-ID data (spec
// 2026-10-16 F1).
const (
	ApplicationsCmd = "<show><predefined><xpath>/predefined/application</xpath></predefined></show>"
	ContainersCmd   = "<show><predefined><xpath>/predefined/application-container</xpath></predefined></show>"
)

// Applications is a dummy answer to ApplicationsCmd in the shape of spec
// 2026-10-16 F1 and F7: two applications and the two functions of one
// container. The ids and versions are dummy values. Every fake device answers
// it unless Ops names the command.
const Applications = `<response status="success"><result><application>` +
	`<entry id="10001" name="ssl" minver="1.0.0"><category>networking</category><risk>4</risk>` +
	`<icon>ZHVtbXk=</icon><default><port><member>tcp/443</member></port></default></entry>` +
	`<entry id="10002" name="web-browsing" minver="1.0.0"><category>general-internet</category><risk>4</risk>` +
	`<default><port><member>tcp/80</member></port></default></entry>` +
	`<entry id="10003" name="office-docs" minver="1.0.0"><category>business-systems</category><risk>2</risk>` +
	`<application-container>office-suite</application-container></entry>` +
	`<entry id="10004" name="office-mail" minver="1.0.0"><category>business-systems</category><risk>2</risk>` +
	`<application-container>office-suite</application-container></entry>` +
	`</application></result></response>`

// Containers is a dummy answer to ContainersCmd (F1, F7). Every fake device
// answers it unless Ops names the command.
const Containers = `<response status="success"><result><application-container>` +
	`<entry id="90001" name="office-suite" minver="1.0.0"><functions>` +
	`<member>office-docs</member><member>office-mail</member></functions></entry>` +
	`</application-container></result></response>`

// RunningConfigCmd and PushedTemplateCmd ask a device for its running
// configuration and for the template that Panorama pushed to it (spec
// 2026-10-17 C9, C12).
const (
	RunningConfigCmd  = "<show><config><running/></config></show>"
	PushedTemplateCmd = "<show><config><pushed-template/></config></show>"
)

// NoTemplate is the answer to PushedTemplateCmd of a device without a
// template, as fw02 gave it on PAN-OS 12.2.3 (spec 2026-10-17 C7).
const NoTemplate = `<response status="success"><result>No template pushed to device</result></response>`

// defaults are the answers every fake device gives unless Ops names the
// command.
var defaults = map[string]string{
	PredefinedCmd:   PredefinedServices,
	ApplicationsCmd: Applications,
	ContainersCmd:   Containers,
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
	cmd := r.Form.Get("cmd")
	drop := d.DropFirst > 0
	if drop {
		d.DropFirst--
	} else if d.DropCmd[cmd] > 0 {
		d.DropCmd[cmd]--
		drop = true
	}
	truncate := !drop && d.TruncateFirst > 0
	if truncate {
		d.TruncateFirst--
	}
	d.mu.Unlock()

	if d.Stall != "" && (r.Form.Get("type") == d.Stall || cmd == d.Stall) {
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
		resp, ok := d.Ops[cmd]
		if !ok {
			resp, ok = d.answer(cmd)
		}
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

// answer is the device's own answer to an op command that Ops does not name:
// the running configuration, the pushed template, or a default.
func (d *Device) answer(cmd string) (string, bool) {
	switch cmd {
	case RunningConfigCmd:
		return Success(d.Config), true
	case PushedTemplateCmd:
		if d.Template == "" {
			return NoTemplate, true
		}
		return Success(d.Template), true
	}
	resp, ok := defaults[cmd]
	return resp, ok
}
