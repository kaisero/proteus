package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/okaiser/proteus/internal/reason"
)

// The auth modes and identity sources of an audit line (spec §4.9).
const (
	AuthToken = "token"
	AuthStdio = "stdio"

	// SourceHeader is an identity the gateway claimed in the identity header.
	SourceHeader = "header"
	// SourceNone is no identity: no header, or one that is not a JSON object.
	SourceNone = "none"
	// SourceOS is the operating system user that runs a stdio server.
	SourceOS = "os"
)

// StatusUnauthorised is a request the HTTP server refused before any call:
// a Host it does not serve, or no or a wrong token (spec §4.4, §4.9).
const StatusUnauthorised = "unauthorised"

// Identity is who a call claims to come from.
type Identity struct {
	Auth   string // AuthToken or AuthStdio
	Source string // SourceHeader, SourceNone or SourceOS
	// Claims are the audited claims; nil is the identity "unknown".
	Claims map[string]string
}

// maxClaim is how many bytes of each claim value the audit keeps (spec §4.4).
const maxClaim = 256

// HeaderIdentity reads a call's identity from the header name, as the gateway
// sets it: a JSON object of claims, of which claims are kept, each value cut
// to 256 bytes. A missing header or one that is not a JSON object is the
// identity "unknown" from source none; an object with none of claims is the
// identity "unknown" from source header. The call goes on. A token holder can forge the header:
// the audit line records the identity as the gateway claimed it.
func HeaderIdentity(name string, claims []string) func(http.Header) Identity {
	return func(h http.Header) Identity {
		id := Identity{Auth: AuthToken, Source: SourceNone}
		v := h.Get(name)
		if name == "" || v == "" {
			return id
		}
		var all map[string]json.RawMessage
		if err := json.Unmarshal([]byte(v), &all); err != nil || all == nil {
			return id
		}
		id.Source, id.Claims = SourceHeader, map[string]string{}
		for _, c := range claims {
			raw, ok := all[c]
			if !ok {
				continue
			}
			var s string
			if json.Unmarshal(raw, &s) != nil {
				s = string(raw) // a number, a list or an object: its JSON text
			}
			id.Claims[c] = cut(s, maxClaim)
		}
		if len(id.Claims) == 0 {
			// The gateway sent claims, none of those audited: the identity
			// is unknown, and the line says the header was there.
			id.Claims = nil
		}
		return id
	}
}

// StdioIdentity is the identity of every call of a stdio server: the
// operating system user that runs it.
func StdioIdentity(user string) func(http.Header) Identity {
	return func(http.Header) Identity {
		return Identity{Auth: AuthStdio, Source: SourceOS, Claims: map[string]string{"user": cut(user, maxClaim)}}
	}
}

// cut is s in at most n bytes, cut at a character boundary.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// AuditLog writes each call as one JSON line to a file opened append-only,
// mode 0600 (spec §4.9). The file holds addresses and identities: treat it
// as sensitive. It is safe for concurrent use.
type AuditLog struct {
	mu sync.Mutex
	f  *os.File
	// OnError receives a line that could not be written; nil drops it.
	OnError func(error)
}

// OpenAudit opens the audit file at path for appending, creating it with
// mode 0600. An existing file others could read is made 0600 too.
func OpenAudit(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return &AuditLog{f: f}, nil
}

// auditLine is one line of the audit file (spec §4.9).
type auditLine struct {
	Time           time.Time       `json:"time"`
	Auth           string          `json:"auth"`
	IdentitySource string          `json:"identity_source"`
	Identity       any             `json:"identity"`
	Remote         string          `json:"remote,omitempty"`
	Tool           string          `json:"tool"`
	Input          json.RawMessage `json:"input"`
	Verdict        []string        `json:"verdict"`
	Codes          []reason.Code   `json:"codes"`
	Snapshots      []string        `json:"snapshots"`
	DurationMS     int64           `json:"duration_ms"`
	Status         string          `json:"status"`
	Code           reason.Code     `json:"code,omitempty"`
	HTTPStatus     int             `json:"http_status,omitempty"`
	Refused        int             `json:"refused,omitempty"`
}

// lineOf is c as an audit line. Lists are never null.
func lineOf(c Call) auditLine {
	l := auditLine{
		Time: c.Time.UTC(), Auth: c.Identity.Auth, IdentitySource: c.Identity.Source, Identity: "unknown",
		Remote: c.Remote, Tool: c.Tool, Input: c.Input,
		Verdict: c.Answers, Codes: c.Codes, Snapshots: c.Snapshots,
		DurationMS: c.Duration.Milliseconds(), Status: c.Status, Code: c.Code,
		HTTPStatus: c.HTTPStatus, Refused: c.Refused,
	}
	if c.Identity.Claims != nil {
		l.Identity = c.Identity.Claims
	}
	if l.Input != nil && !json.Valid(l.Input) {
		// The SDK parsed it, so this does not happen; a line stays JSON.
		l.Input, _ = json.Marshal(string(c.Input))
	}
	if l.Verdict == nil {
		l.Verdict = []string{}
	}
	if l.Codes == nil {
		l.Codes = []reason.Code{}
	}
	if l.Snapshots == nil {
		l.Snapshots = []string{}
	}
	return l
}

// Audit writes c as one line. One write per line keeps lines whole between
// writers that share the file.
func (a *AuditLog) Audit(c Call) {
	b, err := json.Marshal(lineOf(c))
	if err == nil {
		a.mu.Lock()
		_, err = a.f.Write(append(b, '\n'))
		a.mu.Unlock()
	}
	if err != nil && a.OnError != nil {
		a.OnError(fmt.Errorf("audit log: %w", err))
	}
}

// Close closes the file.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.f.Close()
}
