package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// rotatedFiles are the names in dir that start with base and a dot, sorted.
func rotatedFiles(t *testing.T, dir, base string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base+".") {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out
}

// jsonLines are the lines of the files, each checked to be one JSON object.
func jsonLines(t *testing.T, paths ...string) []string {
	t.Helper()
	var out []string
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for l := range strings.Lines(string(b)) {
			if !strings.HasSuffix(l, "\n") || !json.Valid([]byte(l)) {
				t.Errorf("%s: not a whole JSON line: %q", filepath.Base(p), l)
			}
			out = append(out, strings.TrimSuffix(l, "\n"))
		}
	}
	return out
}

// The audit file rotates before a line would take it past its size: the
// old file gets a sortable UTC name, the new one mode 0600, and only the
// newest Keep rotated files stay. Other files beside it stay too.
func TestTheAuditRotates(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	other := filepath.Join(dir, "audit.jsonl.bak")
	if err := os.WriteFile(other, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Every rotation in one clock tick: the names still differ and sort.
	now := time.Date(2026, 10, 10, 8, 0, 0, 0, time.FixedZone("x", 7200))
	line, err := json.Marshal(lineOf(Call{Time: now, Tool: "search", Status: StatusOK}))
	if err != nil {
		t.Fatal(err)
	}
	size := int64(len(line) + 1)
	a, err := OpenAudit(path, Rotation{MaxBytes: 3 * size, Keep: 2, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		a.Audit(Call{Time: now, Tool: "search", Status: StatusOK})
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// 10 lines, 3 per file: 3 rotations, the newest 2 kept, 1 line current.
	rotated := rotatedFiles(t, dir, "audit.jsonl")
	if len(rotated) != 3 || rotated[0] != "audit.jsonl.2026-10-10T06-00-00.000000000Z-000002" ||
		rotated[1] != "audit.jsonl.2026-10-10T06-00-00.000000000Z-000003" || rotated[2] != "audit.jsonl.bak" {
		t.Fatalf("rotated %v", rotated)
	}
	for _, name := range append(rotated[:2], "audit.jsonl") {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() > 3*size {
			t.Errorf("%s: %v %v", name, fi, err)
		}
	}
	if n := len(jsonLines(t, filepath.Join(dir, rotated[0]), filepath.Join(dir, rotated[1]), path)); n != 7 {
		t.Errorf("%d lines kept, want 7", n)
	}
	if b, _ := os.ReadFile(other); string(b) != "keep me\n" {
		t.Errorf("the other file: %q", b)
	}
}

// A file that starts past its limit rotates at the first line; a line
// longer than the limit is written whole to a new file.
func TestTheAuditRotatesAnOldFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(path, []byte(`{"earlier":true}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := OpenAudit(path, Rotation{MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	a.Audit(Call{Tool: "search"})
	a.Audit(Call{Tool: "lookup"})
	_ = a.Close()
	rotated := rotatedFiles(t, dir, "audit.jsonl")
	if len(rotated) != 2 {
		t.Fatalf("rotated %v", rotated)
	}
	if got := jsonLines(t, filepath.Join(dir, rotated[0])); len(got) != 1 || got[0] != `{"earlier":true}` {
		t.Errorf("first rotated %v", got)
	}
	if got := jsonLines(t, path); len(got) != 1 || !strings.Contains(got[0], `"tool":"lookup"`) {
		t.Errorf("current %v", got)
	}
}

// Parallel calls lose no line and split none across a rotation.
func TestTheAuditRotatesUnderParallelWrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	a, err := OpenAudit(path, Rotation{MaxBytes: 2000, Keep: 1000})
	if err != nil {
		t.Fatal(err)
	}
	const writers, each = 16, 50
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			for i := range each {
				a.Audit(Call{Tool: fmt.Sprintf("t%d-%d", w, i), Status: StatusOK})
			}
		})
	}
	wg.Wait()
	_ = a.Close()
	paths := []string{path}
	for _, name := range rotatedFiles(t, dir, "audit.jsonl") {
		paths = append(paths, filepath.Join(dir, name))
	}
	if len(paths) < 10 {
		t.Errorf("%d files: the test did not rotate much", len(paths))
	}
	seen := map[string]bool{}
	for _, l := range jsonLines(t, paths...) {
		var v struct{ Tool string }
		_ = json.Unmarshal([]byte(l), &v)
		seen[v.Tool] = true
	}
	if len(seen) != writers*each {
		t.Errorf("%d distinct lines, want %d", len(seen), writers*each)
	}
}

// A rotation that cannot rename the file reports it and keeps writing to
// the file it has; no line is lost.
func TestAFailedRotationKeepsTheLine(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("root renames in a read-only directory")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	a, err := OpenAudit(path, Rotation{MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	var errs []error
	a.OnError = func(err error) { errs = append(errs, err) }
	a.Audit(Call{Tool: "one"})
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	a.Audit(Call{Tool: "two"})
	_ = a.Close()
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "audit log") {
		t.Errorf("errors %v", errs)
	}
	if got := jsonLines(t, path); len(got) != 2 {
		t.Errorf("lines %v", got)
	}
	if rotated := rotatedFiles(t, dir, "audit.jsonl"); len(rotated) != 0 {
		t.Errorf("rotated %v", rotated)
	}
}

// When the new file cannot open after a rename, the line is reported lost,
// and the next line opens the file again.
func TestTheAuditReopensAfterAFailedOpen(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// Two older rotated files; the reopen prunes to the newest one, which
	// the failed rotation wrote.
	for _, old := range []string{"2026-10-10T06-00-00.000000000Z-000001", "2026-10-10T06-00-00.000000000Z-000002"} {
		if err := os.WriteFile(path+"."+old, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, err := OpenAudit(path, Rotation{MaxBytes: 10, Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	var errs []error
	a.OnError = func(err error) { errs = append(errs, err) }
	a.Audit(Call{Tool: "one"})
	a.mu.Lock()
	a.openFile = func(string, int, os.FileMode) (*os.File, error) { return nil, os.ErrPermission }
	a.mu.Unlock()
	a.Audit(Call{Tool: "two"}) // rotates, then cannot open: lost
	a.Audit(Call{Tool: "two"}) // cannot open again: lost
	if len(errs) != 2 {
		t.Fatalf("errors %v", errs)
	}
	a.mu.Lock()
	a.openFile = nil
	a.mu.Unlock()
	a.Audit(Call{Tool: "three"})
	_ = a.Close()
	if got := jsonLines(t, path); len(got) != 1 || !strings.Contains(got[0], `"tool":"three"`) {
		t.Errorf("after the reopen %v", got)
	}
	if rotated := rotatedFiles(t, dir, "audit.jsonl"); len(rotated) != 1 || !strings.HasSuffix(rotated[0], "-000003") {
		t.Errorf("rotated %v", rotated)
	}
}

// A clock that went back does not make prune remove the newest rotated
// file: the sequence orders them, not the time.
func TestTheAuditPrunesBySequence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	now := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	a, err := OpenAudit(path, Rotation{MaxBytes: 10, Keep: 2, Now: func() time.Time { now = now.Add(-time.Hour); return now }})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"one", "two", "three", "four"} {
		a.Audit(Call{Tool: tool})
	}
	_ = a.Close()
	rotated := rotatedFiles(t, dir, "audit.jsonl")
	if len(rotated) != 2 {
		t.Fatalf("rotated %v", rotated)
	}
	for i, tool := range []string{"two", "three"} {
		var got []string
		for _, f := range rotated {
			if strings.HasSuffix(f, fmt.Sprintf("-%06d", i+2)) {
				got = jsonLines(t, filepath.Join(dir, f))
			}
		}
		if len(got) != 1 || !strings.Contains(got[0], `"tool":"`+tool+`"`) {
			t.Errorf("rotated %d: %v (files %v)", i+2, got, rotated)
		}
	}
}

// A rotated name the file system refuses (too long) is reported by the
// rename and does not stop the log: the name check does not loop on an
// error other than "exists".
func TestTheAuditSurvivesARefusedName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, strings.Repeat("a", 240)) // the rotated name passes 255 bytes
	a, err := OpenAudit(path, Rotation{MaxBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	var errs []error
	a.OnError = func(err error) { errs = append(errs, err) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Audit(Call{Tool: "one"})
		a.Audit(Call{Tool: "two"})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the rotation does not return")
	}
	_ = a.Close()
	if len(errs) != 1 {
		t.Errorf("errors %v", errs)
	}
	if got := jsonLines(t, path); len(got) != 2 {
		t.Errorf("lines %v", got)
	}
}

// shortWriter writes half of each write longer than a byte to w and fails,
// as a disk that fills up mid-line.
type shortWriter struct{ w io.Writer }

func (s shortWriter) Write(p []byte) (int, error) {
	if len(p) == 1 {
		return s.w.Write(p)
	}
	n, _ := s.w.Write(p[:len(p)/2])
	return n, errors.New("disk full")
}

// A short write leaves no fragment in the file to run into the next line;
// a stream gets the fragment ended.
func TestAShortWriteIsUndone(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := OpenAudit(path, Rotation{})
	if err != nil {
		t.Fatal(err)
	}
	var errs []error
	a.OnError = func(err error) { errs = append(errs, err) }
	a.Audit(Call{Tool: "one"})
	a.mu.Lock()
	a.w = shortWriter{a.f}
	a.mu.Unlock()
	a.Audit(Call{Tool: "lost"})
	a.mu.Lock()
	a.w = a.f
	a.mu.Unlock()
	a.Audit(Call{Tool: "three"})
	_ = a.Close()
	got := jsonLines(t, path)
	if len(errs) != 1 || len(got) != 2 || !strings.Contains(got[1], `"tool":"three"`) {
		t.Errorf("errors %v, lines %v", errs, got)
	}
	var buf bytes.Buffer
	s := AuditTo(shortWriter{&buf})
	s.Audit(Call{Tool: "cut"})
	if b := buf.String(); !strings.HasSuffix(b, "\n") || strings.Count(b, "\n") != 1 {
		t.Errorf("stream %q", b)
	}
}

// AuditTo writes the lines to a stream and leaves it open; a line after
// Close is an error.
func TestAuditTo(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	a := AuditTo(&buf)
	a.Audit(Call{Tool: "search", Status: StatusOK})
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	var got error
	a.OnError = func(err error) { got = err }
	a.Audit(Call{Tool: "late"})
	if got == nil {
		t.Error("a line after Close was not reported")
	}
	if l := buf.String(); strings.Count(l, "\n") != 1 || !strings.Contains(l, `"tool":"search"`) {
		t.Errorf("stream %q", l)
	}
}

// A name that is taken moves the sequence on; a directory or a sequence
// past the int range beside the file is not a rotated file.
func TestTheAuditSkipsTakenAndForeignNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	const stamp = "2026-10-10T08-00-00.000000000Z"
	if err := os.Mkdir(path+"."+stamp+"-000001", 0o700); err != nil {
		t.Fatal(err)
	}
	huge := path + "." + stamp + "-" + strings.Repeat("9", 30)
	if err := os.WriteFile(huge, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	a, err := OpenAudit(path, Rotation{MaxBytes: 10, Keep: 1, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	a.Audit(Call{Tool: "one"})
	a.Audit(Call{Tool: "two"})
	_ = a.Close()
	if _, err := os.Stat(path + "." + stamp + "-000002"); err != nil {
		t.Errorf("the next free name: %v (files %v)", err, rotatedFiles(t, dir, "audit.jsonl"))
	}
	if _, err := os.Stat(huge); err != nil {
		t.Errorf("a foreign file was pruned: %v", err)
	}
}

// A directory that cannot be read fails prune, and the rotated name starts
// at sequence 1 for the rename to report.
func TestTheAuditWithoutItsDirectory(t *testing.T) {
	t.Parallel()
	a := &AuditLog{path: filepath.Join(t.TempDir(), "gone", "audit.jsonl"), rot: Rotation{Keep: 1, Now: time.Now}}
	if err := a.prune(); err == nil {
		t.Error("pruned a missing directory")
	}
	if name := a.rotatedName(); !strings.HasSuffix(name, "-000001") {
		t.Errorf("name %s", name)
	}
}
