// Package fetch reads documents from a firewall's XML API: it logs in with a
// username and password, and fetches the running configuration and operational
// state. It reads and never writes. See AGENTS.md R2.
package fetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/runlog"
)

// Client talks to one firewall's XML API.
type Client struct {
	base string // https://<host>/api/
	http *http.Client
	key  string
	log  *runlog.Logger
	name string // the device, for log lines
	// retryWait is the pause before the one retry of a transport error.
	retryWait time.Duration
}

// defaultRetryWait gives a device that dropped a connection a moment to recover.
const defaultRetryWait = 500 * time.Millisecond

// NewClient returns a client for one device. It verifies the device's TLS
// certificate unless the inventory turned that off (spec S8).
//
// log receives one API line per call at debug level, and registers the password
// and the API key as secrets the moment each exists. A nil log discards.
func NewClient(t inventory.Target, log *runlog.Logger) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	//nolint:gosec // G402: skipping verification is the inventory's documented,
	// per-device opt-out for self-signed lab certificates (spec S8).
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.InsecureTLS}
	log.AddSecret(t.Password)
	return &Client{
		base: "https://" + t.Host + "/api/",
		http: &http.Client{Transport: tr, Timeout: t.Timeout},
		log:  log,
		name: t.Name,

		retryWait: defaultRetryWait,
	}
}

// APIError is a refusal from the device: an HTTP error status, or a response whose
// status is not success.
type APIError struct {
	HTTPStatus int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = "no message"
	}
	if e.Code != "" {
		return fmt.Sprintf("device refused (HTTP %d, code %s): %s", e.HTTPStatus, e.Code, msg)
	}
	return fmt.Sprintf("device refused (HTTP %d): %s", e.HTTPStatus, msg)
}

// Keygen exchanges a username and password for an API key and keeps the key for
// the calls that follow. The password travels in a POST body, never in a URL, so it
// stays out of access logs and error messages.
//
// Source: PAN-OS XML API, "Get Your API Key" and "Structure of a PAN-OS XML API
// Request", https://docs.paloaltonetworks.com/ngfw/api/getting-started/structure-of-a-pan-os-xml-api-request
func (c *Client) Keygen(ctx context.Context, user, password string) error {
	c.log.AddSecret(password)
	body, err := c.do(ctx, url.Values{"type": {"keygen"}, "user": {user}, "password": {password}}, false)
	if err != nil {
		return fmt.Errorf("keygen for %s: %w", user, err)
	}
	var r struct {
		Key string `xml:"result>key"`
	}
	if err := xml.Unmarshal(body, &r); err != nil || r.Key == "" {
		return fmt.Errorf("keygen for %s: the response held no key", user)
	}
	c.key = r.Key
	c.log.AddSecret(r.Key)
	c.log.Infof(runlog.TagAPI, "%s: logged in as %s", c.name, user)
	return nil
}

// Op runs one show command and returns the device's response verbatim.
//
// It refuses anything but a show command. An op command can also clear, test,
// request or restart, and this library never changes a device (AGENTS.md R2).
func (c *Client) Op(ctx context.Context, cmd string) ([]byte, error) {
	if err := showOnly(cmd); err != nil {
		return nil, err
	}
	return c.do(ctx, url.Values{"type": {"op"}, "cmd": {cmd}}, true)
}

// opStream runs one show command and hands its answer to read as a stream, so
// a large answer is never held whole. It keeps the guard of Op: it refuses
// anything but a show command before a request is sent (AGENTS.md R2). It is
// unexported, so the exported method set stays the one R2 reviewed.
//
// An HTTP error status gives an *APIError, and read never runs. read can run
// twice: send retries a body that breaks off, so read must first reset what it
// wrote before.
func (c *Client) opStream(ctx context.Context, cmd string, read func(io.Reader) error) error {
	if err := showOnly(cmd); err != nil {
		return err
	}
	return c.send(ctx, url.Values{"type": {"op"}, "cmd": {cmd}}, true, func(status int, body io.Reader) error {
		if status >= 300 {
			// send retries a body that breaks off whatever this returns, so
			// the read error itself is of no use here.
			b, _ := io.ReadAll(io.LimitReader(body, errorBodyLimit))
			return checkResponse(status, b)
		}
		return read(body)
	})
}

// errorBodyLimit bounds how much of an error answer opStream reads: enough for
// the PAN-OS error envelope.
const errorBodyLimit = 64 << 10

// showOnly refuses a command that is not a show command.
func showOnly(cmd string) error {
	if !strings.HasPrefix(cmd, "<show>") {
		return fmt.Errorf("fetch: refusing op command %q: only <show> commands are read-only", cmd)
	}
	return nil
}

// ExportConfig returns the running configuration as
// type=export&category=configuration returns it: a bare <config> element.
func (c *Client) ExportConfig(ctx context.Context) ([]byte, error) {
	return c.do(ctx, url.Values{"type": {"export"}, "category": {"configuration"}}, true)
}

// do sends one request and returns its whole body. A refusal returns the body
// with an *APIError.
func (c *Client) do(ctx context.Context, form url.Values, needKey bool) ([]byte, error) {
	var body []byte
	err := c.send(ctx, form, needKey, func(status int, r io.Reader) error {
		b, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		body = b
		return checkResponse(status, b)
	})
	return body, err
}

// send sends one request and gives the answer to read. It is the one retry loop
// of the client: do and opStream call it.
//
// A transport error is retried once, after a short pause, and so is a body that
// breaks off while read reads it. A refusal and a certificate error are not
// retried, because a second attempt fails the same way. An error that read
// returns while the body reads well goes back at once, unchanged. Every request
// is a POST: the XML API accepts it for these types, and it keeps arguments out
// of the URL.
func (c *Client) send(ctx context.Context, form url.Values, needKey bool, read func(status int, body io.Reader) error) error {
	if needKey && c.key == "" {
		return errors.New("fetch: no API key; call Keygen first")
	}
	what := form.Get("type")
	if cmd := form.Get("cmd"); cmd != "" {
		what += " " + cmd
	}
	var lastErr error
	for attempt := range 2 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("fetch: %s: %w", c.base, ctx.Err())
			case <-time.After(c.retryWait):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base, strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if needKey {
			req.Header.Set("X-PAN-KEY", c.key)
		}
		start := time.Now()
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			lastErr = err
			c.log.Debugf(runlog.TagAPI, "%s: %s: attempt %d: %v", c.name, what, attempt+1, err)
			if isCertificateError(err) {
				break
			}
			continue
		}
		body := &bodyReader{r: resp.Body}
		err = read(resp.StatusCode, body)
		_ = resp.Body.Close()
		if body.err != nil {
			lastErr = body.err
			c.log.Debugf(runlog.TagAPI, "%s: %s: attempt %d: reading the body: %v", c.name, what, attempt+1, body.err)
			continue
		}
		c.log.Debugf(runlog.TagAPI, "%s: %s -> HTTP %d, %d bytes, %s", c.name, what, resp.StatusCode, body.n, time.Since(start).Round(time.Millisecond))
		if err != nil {
			// The caller decides what a refusal means and logs it at warn.
			c.log.Debugf(runlog.TagAPI, "%s: %s: refused: %v", c.name, what, err)
		}
		return err
	}
	return fmt.Errorf("fetch: %s: %w", c.base, lastErr)
}

// bodyReader reads the body of an answer and keeps its own read error, so send
// can tell a connection that broke off from an error of the caller's read.
type bodyReader struct {
	r   io.Reader
	n   int
	err error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += n
	if err != nil && !errors.Is(err, io.EOF) {
		b.err = err
	}
	return n, err
}

// isCertificateError reports whether a transport error is the device's certificate
// failing verification. Retrying cannot change that answer. The TLS client wraps
// every x509 failure in a CertificateVerificationError.
func isCertificateError(err error) bool {
	_, ok := errors.AsType[*tls.CertificateVerificationError](err)
	return ok
}

// checkResponse turns an HTTP error or a PAN-OS error envelope into an APIError. A
// body whose root element is not <response>, such as an export's bare <config>, is
// accepted as it stands when the HTTP status is a success.
func checkResponse(status int, body []byte) error {
	// PAN-OS writes an error message three ways: <msg>text</msg>,
	// <msg><line>text</line></msg>, and <result><msg>text</msg></result> (keygen).
	type msg struct {
		Text  string   `xml:",chardata"`
		Lines []string `xml:"line"`
	}
	var env struct {
		XMLName xml.Name
		Status  string `xml:"status,attr"`
		Code    string `xml:"code,attr"`
		Msg     msg    `xml:"msg"`
		Result  msg    `xml:"result>msg"`
	}
	parseErr := xml.NewDecoder(bytes.NewReader(body)).Decode(&env)
	isResponse := parseErr == nil && env.XMLName.Local == "response"
	if status < 300 && (!isResponse || env.Status == "success") {
		return nil
	}
	parts := append([]string{env.Msg.Text}, env.Msg.Lines...)
	parts = append(append(parts, env.Result.Text), env.Result.Lines...)
	return &APIError{
		HTTPStatus: status, Code: env.Code,
		Message: strings.Join(strings.Fields(strings.Join(parts, " ")), " "),
	}
}
