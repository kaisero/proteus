package runlog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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
	for in, want := range map[string]Level{"error": Error, "WARN": Warn, "Info": Info, "debug": Debug} {
		if got, err := ParseLevel(in); err != nil || got != want {
			t.Errorf("ParseLevel(%s) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseLevel("trace"); err == nil {
		t.Error("an unknown level must be an error")
	}
	if Level(9).String() != "Level(9)" || Debug.String() != "DEBUG" {
		t.Error("String")
	}
}

func TestOpenFails(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{Dir: filepath.Join(f, "sub"), Command: "x"}); err == nil {
		t.Error("a directory under a file must fail")
	}
}
