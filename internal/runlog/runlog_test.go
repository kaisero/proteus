package runlog

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func clock() func() time.Time {
	t := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	return func() time.Time { t = t.Add(time.Second); return t }
}

func open(t *testing.T, o Options) *Logger {
	t.Helper()
	if o.Dir == "" {
		o.Dir = t.TempDir()
	}
	if o.Now == nil {
		o.Now = clock()
	}
	l, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func content(t *testing.T, l *Logger) string {
	t.Helper()
	b, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLevelsFilter(t *testing.T) {
	t.Parallel()
	l := open(t, Options{Command: "search", Level: Info})
	l.Debugf(TagFind, "hidden detail")
	l.Infof(TagRun, "shown")
	l.Warnf(TagSnap, "a warning")
	l.Errorf(TagRun, "an error")
	got := content(t, l)
	if strings.Contains(got, "hidden detail") {
		t.Error("a debug line was written at info")
	}
	for _, want := range []string{"[INFO] [RUN] shown", "[WARN] [SNAP] a warning", "[ERROR] [RUN] an error"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if !l.Enabled(Info) || l.Enabled(Debug) {
		t.Error("Enabled must follow the level")
	}
}

func TestSecretsAreRedacted(t *testing.T) {
	t.Parallel()
	l := open(t, Options{Command: "fetch", Level: Debug})
	l.Infof(TagAPI, "before: secret-password")
	l.AddSecret("secret-password")
	l.AddSecret("secret")
	l.AddSecret("")
	l.Infof(TagAPI, "after: secret-password and secret")
	got := content(t, l)
	if !strings.Contains(got, "after: *** and ***") {
		t.Errorf("secrets must be redacted, longest first:\n%s", got)
	}
}

func TestFileIsPrivate(t *testing.T) {
	t.Parallel()
	l := open(t, Options{Command: "simulate policy"})
	fi, err := os.Stat(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	if !strings.HasPrefix(filepath.Base(l.Path()), "simulate_policy-") {
		t.Errorf("name = %s", l.Path())
	}
}

func TestRotationKeepsTheNewest(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := clock()
	for _, cmd := range []string{"a", "b", "c", "d"} {
		l, err := Open(Options{Dir: dir, Command: cmd, Keep: 2, Now: now})
		if err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name()[:1])
	}
	if strings.Join(names, ",") != "c,d" {
		t.Errorf("kept %v, want the newest two whatever the command", names)
	}
}

func TestEchoAndNil(t *testing.T) {
	t.Parallel()
	var echo bytes.Buffer
	l := open(t, Options{Command: "x", Level: Info, Echo: &echo})
	l.Infof(TagRun, "hello")
	if !strings.Contains(echo.String(), "[INFO] [RUN] hello") {
		t.Errorf("echo = %q", echo.String())
	}
	none := Discard()
	none.Infof(TagRun, "nothing")
	none.AddSecret("x")
	if none.Path() != "" || none.Enabled(Error) || none.Close() != nil {
		t.Error("a nil logger discards")
	}
	if err := l.Close(); err != nil || l.Close() != nil {
		t.Error("Close is idempotent")
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   string
		want Level
	}{{"error", Error}, {"WARN", Warn}, {"Info", Info}, {"debug", Debug}} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got, err := ParseLevel(tc.in); err != nil || got != tc.want {
				t.Errorf("ParseLevel(%s) = %v, %v", tc.in, got, err)
			}
		})
	}
	t.Run("trace", func(t *testing.T) {
		t.Parallel()
		if _, err := ParseLevel("trace"); err == nil {
			t.Error("an unknown level must be an error")
		}
	})
	if Level(9).String() != "Level(9)" || Debug.String() != "DEBUG" {
		t.Error("String")
	}
}

func TestOpenFails(t *testing.T) {
	t.Parallel()
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: filepath.Join(f, "sub"), Command: "x"}); err == nil {
		t.Error("a directory under a file must fail")
	}
}

// Runs that open in the same millisecond each get their own file, and their
// rotations, which race, warn of nothing (spec 2026-10-09 §4.9, §12 C14).
func TestParallelOpensInOneMillisecond(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	at := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	const n = 32
	paths := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			l, err := Open(Options{Dir: dir, Command: "mcp search", Keep: 4, Level: Warn, Now: func() time.Time { return at }})
			if err != nil {
				errs[i] = err
				return
			}
			paths[i] = l.Path()
			errs[i] = l.Close()
		})
	}
	wg.Wait()
	seen := map[string]bool{}
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("open %d: %v", i, errs[i])
		}
		if seen[paths[i]] {
			t.Fatalf("two runs share %s", paths[i])
		}
		seen[paths[i]] = true
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "rotation failed") {
			t.Errorf("%s: %s", e.Name(), b)
		}
	}
}

func TestSequenceNumbersCountUp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	at := func() time.Time { return time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC) }
	last := 0
	for range 3 {
		l := open(t, Options{Dir: dir, Command: "simulate policy", Now: at})
		m := logName.FindStringSubmatch(filepath.Base(l.Path()))
		if m == nil || !strings.HasPrefix(filepath.Base(l.Path()), "simulate_policy-20260929T100000.000Z-") || len(m[2]) < 3 {
			t.Fatalf("name = %s", l.Path())
		}
		seq, _ := strconv.Atoi(m[2])
		if seq <= last {
			t.Errorf("sequence %d after %d", seq, last)
		}
		last = seq
	}
}

// A name another process holds is skipped; when every try is taken, Open fails.
func TestCreateSkipsATakenName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x-001.log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var n uint64
	f, path, err := create(dir, "x", func(d uint64) uint64 { n += d; return n })
	if err != nil || filepath.Base(path) != "x-002.log" {
		t.Fatalf("create = %s, %v", path, err)
	}
	_ = f.Close()
	if _, _, err := create(dir, "x", func(uint64) uint64 { return 1 }); err == nil {
		t.Error("every try is taken: want an error")
	}
}

// Rotation orders by timestamp, then sequence number; a name from before the
// sequence number counts as the first of its millisecond. Other files stay.
func TestRotationReadsTheSequenceNumber(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{
		"b-20260929T100000.000Z-010.log",
		"a-20260929T100000.000Z-002.log",
		"c-20260929T100000.000Z.log",
		"z-20260929T090000.000Z-001.log",
		"notes.log", "other-name.log",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := rotate(dir, 2); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"a-20260929T100000.000Z-002.log", "b-20260929T100000.000Z-010.log", "notes.log", "other-name.log"}
	if !slices.Equal(names, want) {
		t.Errorf("kept %v, want %v", names, want)
	}
}

func TestRemoveGone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := removeGone(filepath.Join(dir, "gone.log")); err != nil {
		t.Errorf("a file already gone: %v", err)
	}
	full := filepath.Join(dir, "full")
	if err := os.MkdirAll(filepath.Join(full, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := removeGone(full); err == nil {
		t.Error("a directory that is not empty must fail")
	}
	if err := rotate(filepath.Join(dir, "absent"), 1); err == nil {
		t.Error("an absent directory must fail")
	}
}

// Rotations that run at once over the same files all succeed: each tolerates
// a file another one removed first, and one file is left.
func TestConcurrentRotationsSucceed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for i := range 50 {
		name := fmt.Sprintf("simulate_policy-20260929T100000.000Z-%03d.log", i+1)
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() { errs <- rotate(dir, 1) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("rotate: %v", err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 || entries[0].Name() != "simulate_policy-20260929T100000.000Z-050.log" {
		t.Errorf("left %v", entries)
	}
}
