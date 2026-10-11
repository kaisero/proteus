package mcp

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
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

// AuditLog writes each call as one JSON line (spec §4.9): to a file opened
// append-only, mode 0600, which it rotates by size and count (spec 2026-10-10
// F3), or to a stream such as standard output, which the container platform
// collects. The lines hold identities, and the addresses in the inputs:
// treat them as sensitive.
// It is safe for concurrent use. One process writes a file: two servers that
// share one would each rotate it.
type AuditLog struct {
	// mu covers every write and rotation, so a line is never split across
	// two files, nor two lines interleaved.
	mu sync.Mutex
	w  io.Writer // the file, or the stream
	// The file's state; f is nil for a stream, and after a rotation whose
	// new file did not open (the next line tries again).
	f      *os.File
	path   string
	size   int64 // bytes in f
	rot    Rotation
	closed bool
	// openFile opens the file; nil is os.OpenFile. A test makes it fail.
	openFile func(string, int, os.FileMode) (*os.File, error)
	// OnError receives a line that could not be written, or a rotation that
	// failed; nil drops it.
	OnError func(error)
}

// Rotation bounds the audit file: before a line would take it past MaxBytes,
// it is renamed to <name>.<UTC time>-<seq> and a new file starts; the newest Keep
// renamed files stay. A zero field takes its default.
type Rotation struct {
	MaxBytes int64
	Keep     int
	// Now names the renamed files; nil uses time.Now.
	Now func() time.Time
}

// The defaults of audit_max_mb and audit_keep (spec 2026-10-10 F3).
const (
	DefaultAuditMaxMB = 100
	DefaultAuditKeep  = 10
)

// rotatedLayout is the time in a renamed file's name, UTC.
const rotatedLayout = "2006-01-02T15-04-05.000000000Z"

// OpenAudit opens the audit file at path for appending, creating it with
// mode 0600, rotated as r says. An existing file others could read is made
// 0600 too.
func OpenAudit(path string, r Rotation) (*AuditLog, error) {
	r.MaxBytes = cmp.Or(r.MaxBytes, DefaultAuditMaxMB<<20)
	r.Keep = cmp.Or(r.Keep, DefaultAuditKeep)
	if r.Now == nil {
		r.Now = time.Now
	}
	a := &AuditLog{path: path, rot: r}
	if err := a.open(); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return a, nil
}

// AuditTo writes the audit lines to w, unrotated. Close does not close w.
func AuditTo(w io.Writer) *AuditLog { return &AuditLog{w: w} }

// open opens the file at a.path for appending, mode 0600, and takes its size.
func (a *AuditLog) open() error {
	open := a.openFile
	if open == nil {
		open = os.OpenFile
	}
	f, err := open(a.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err != nil {
		_ = f.Close()
		return err
	}
	a.f, a.w, a.size = f, f, fi.Size()
	return nil
}

// auditLine is one line of the audit file (spec §4.9).
type auditLine struct {
	Time           time.Time       `json:"time"`
	Auth           string          `json:"auth"`
	IdentitySource string          `json:"identity_source"`
	Identity       any             `json:"identity"`
	Tool           string          `json:"tool"`
	Input          json.RawMessage `json:"input"`
	Verdict        []string        `json:"verdict"`       // the summary line and the first 20 result lines
	VerdictCount   int             `json:"verdict_count"` // the answer lines the client received; with limit, the cut answer's
	Codes          []reason.Code   `json:"codes"`
	Snapshots      []string        `json:"snapshots"`
	DurationMS     int64           `json:"duration_ms"`
	Status         string          `json:"status"`
	Code           reason.Code     `json:"code,omitempty"`
}

// lineOf is c as an audit line. Lists are never null.
func lineOf(c Call) auditLine {
	l := auditLine{
		Time: c.Time.UTC(), Auth: c.Identity.Auth, IdentitySource: c.Identity.Source, Identity: "unknown",
		Tool: c.Tool, Input: c.Input,
		Verdict: c.Answers, VerdictCount: c.AnswerCount, Codes: c.Codes, Snapshots: c.Snapshots,
		DurationMS: c.Duration.Milliseconds(), Status: c.Status, Code: c.Code,
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

// Audit writes c as one line. One write per line, under the lock that also
// covers the rotation, keeps lines whole between the calls that share the
// log.
func (a *AuditLog) Audit(c Call) {
	b, err := json.Marshal(lineOf(c))
	if err == nil {
		a.mu.Lock()
		err = a.write(append(b, '\n'))
		a.mu.Unlock()
	}
	if err != nil {
		a.fail(err)
	}
}

// fail hands err to OnError, if set.
func (a *AuditLog) fail(err error) {
	if a.OnError != nil {
		a.OnError(fmt.Errorf("audit log: %w", err))
	}
}

// write writes line, rotating the file first when the line would take it
// past its limit. A failed rotation keeps writing to the file it has; a file
// that did not open loses the line. It returns what failed, one error per
// line; a.mu is held.
func (a *AuditLog) write(line []byte) error {
	var rotated error
	switch {
	case a.path == "" || a.closed:
	case a.f == nil:
		// The new file did not open after a rotation renamed the old one:
		// try again, and prune as that rotation could not.
		if err := a.open(); err != nil {
			return err
		}
		rotated = a.prune()
	case a.size > 0 && a.size+int64(len(line)) > a.rot.MaxBytes:
		// A line longer than the limit still goes to a new file whole.
		rotated = a.rotate()
	}
	if a.w == nil {
		return cmp.Or(rotated, os.ErrClosed)
	}
	n, err := a.w.Write(line)
	if err != nil && n > 0 && n < len(line) {
		// A short write, as on a full disk, leaves a fragment that would
		// run into the next line. The file has one writer and appends, so
		// cut it back; a stream gets the line ended instead.
		err = errors.Join(err, a.repair())
		if a.f != nil {
			n = 0
		}
	}
	a.size += int64(n)
	return errors.Join(rotated, err)
}

// repair undoes a short write: the file is cut back to its size before it,
// a stream gets the fragment ended with a newline. a.mu is held.
func (a *AuditLog) repair() error {
	if a.f != nil {
		return a.f.Truncate(a.size)
	}
	_, err := a.w.Write([]byte{'\n'})
	return err
}

// rotate renames the file to <name>.<UTC time>-<seq>, opens a new one, and removes
// the oldest renamed files past Keep. When the rename fails the file stays
// as it is. a.mu is held.
func (a *AuditLog) rotate() error {
	to := a.rotatedName()
	f := a.f
	a.f, a.w = nil, nil
	closed := f.Close()
	renamed := os.Rename(a.path, to)
	// Open the file at a.path again: a new one after the rename, or the same
	// one when the rename failed. When this fails the next line tries again.
	if err := a.open(); err != nil {
		return errors.Join(closed, renamed, err)
	}
	if renamed != nil {
		return errors.Join(closed, renamed)
	}
	return errors.Join(closed, a.prune())
}

// rotatedName is a free name for the file rotated now:
// <name>.<UTC time>-<seq>. The sequence is one above the highest of the
// rotated files, so prune keeps the newest even when the clock went back.
func (a *AuditLog) rotatedName() string {
	files, _ := a.rotated() // unreadable: start at 1, and Rename reports it
	seq := 1
	if len(files) > 0 {
		seq = files[len(files)-1].seq + 1
	}
	stamp := a.rot.Now().UTC().Format(rotatedLayout)
	for {
		name := fmt.Sprintf("%s.%s-%06d", a.path, stamp, seq)
		// Only a name that exists moves on; any other error is Rename's to
		// report, so the loop cannot spin under the lock.
		if _, err := os.Lstat(name); err != nil {
			return name
		}
		seq++
	}
}

// rotatedFile is a rotated audit file and its sequence number.
type rotatedFile struct {
	name string
	seq  int
}

// rotatedSuffix matches the suffix of a rotated file: the UTC time and the
// sequence number.
var rotatedSuffix = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{9}Z)-(\d+)$`)

// rotated are the rotated files beside the audit file, oldest first by
// sequence number. Other files beside it do not count.
func (a *AuditLog) rotated() ([]rotatedFile, error) {
	dir, base := filepath.Split(a.path)
	entries, err := os.ReadDir(cmp.Or(dir, "."))
	if err != nil {
		return nil, err
	}
	var files []rotatedFile
	for _, e := range entries {
		suffix, ok := strings.CutPrefix(e.Name(), base+".")
		m := rotatedSuffix.FindStringSubmatch(suffix)
		if !ok || m == nil || !e.Type().IsRegular() {
			continue
		}
		seq, err := strconv.Atoi(m[2])
		if err != nil {
			continue // past the int range: not a name this log wrote
		}
		files = append(files, rotatedFile{filepath.Join(dir, e.Name()), seq})
	}
	slices.SortFunc(files, func(x, y rotatedFile) int { return cmp.Compare(x.seq, y.seq) })
	return files, nil
}

// prune removes the oldest rotated files past Keep.
func (a *AuditLog) prune() error {
	files, err := a.rotated()
	if err != nil {
		return err
	}
	var errs []error
	for _, f := range files[:max(0, len(files)-a.rot.Keep)] {
		errs = append(errs, os.Remove(f.name))
	}
	return errors.Join(errs...)
}

// Close closes the file; a stream stays open. A line after Close fails.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	f := a.f
	a.f, a.w = nil, nil
	if f == nil {
		return nil
	}
	return f.Close()
}
