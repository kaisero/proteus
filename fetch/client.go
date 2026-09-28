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

	"github.com/okaiser/panos-analyst/inventory"
)

// Client talks to one firewall's XML API.
type Client struct {
	base string // https://<host>/api/
	http *http.Client
	key  string
}

// NewClient returns a client for one device. It verifies the device's TLS
// certificate unless the inventory turned that off (spec S8).
func NewClient(t inventory.Target) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	//nolint:gosec // G402: skipping verification is the inventory's documented,
	// per-device opt-out for self-signed lab certificates (spec S8).
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: t.InsecureTLS}
	return &Client{
		base: "https://" + t.Host + "/api/",
		http: &http.Client{Transport: tr, Timeout: t.Timeout},
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
	return nil
}

// Op runs one show command and returns the device's response verbatim.
//
// It refuses anything but a show command. An op command can also clear, test,
// request or restart, and this library never changes a device (AGENTS.md R2).
func (c *Client) Op(ctx context.Context, cmd string) ([]byte, error) {
	if !strings.HasPrefix(cmd, "<show>") {
		return nil, fmt.Errorf("fetch: refusing op command %q: only <show> commands are read-only", cmd)
	}
	return c.do(ctx, url.Values{"type": {"op"}, "cmd": {cmd}}, true)
}

// ExportConfig returns the running configuration as
// type=export&category=configuration returns it: a bare <config> element.
func (c *Client) ExportConfig(ctx context.Context) ([]byte, error) {
	return c.do(ctx, url.Values{"type": {"export"}, "category": {"configuration"}}, true)
}

// do sends one request, retrying once on a transport error and never on a refusal.
// Every request is a POST: the XML API accepts it for these types, and it keeps
// arguments out of the URL.
func (c *Client) do(ctx context.Context, form url.Values, needKey bool) ([]byte, error) {
	if needKey && c.key == "" {
		return nil, errors.New("fetch: no API key; call Keygen first")
	}
	var lastErr error
	for range 2 {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if needKey {
			req.Header.Set("X-PAN-KEY", c.key)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return body, checkResponse(resp.StatusCode, body)
	}
	return nil, fmt.Errorf("fetch: %s: %w", c.base, lastErr)
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
