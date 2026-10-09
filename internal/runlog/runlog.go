// Package runlog writes one log file per run of proteus, so an answer nobody
// can explain can be traced afterwards: which snapshot was read, which API calls
// were made, and what each simulation stage kept and dropped.
//
// It follows panos-doctor's run log: one file per run, grep-friendly lines, every
// registered secret redacted before a line is written, rotation by count, and an
// optional echo to the terminal. Unlike panos-doctor it has a level, so a run can
// record every detail when something needs explaining and stay short otherwise.
//
// A nil *Logger discards everything, so a library caller that passes none pays
// nothing.
package runlog

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level is how much a run records. Each level includes the ones above it.
type Level int

// The levels, most severe first.
const (
	Error Level = iota
	Warn
	Info
	Debug
)

var levelNames = []string{"ERROR", "WARN", "INFO", "DEBUG"}

func (lv Level) String() string {
	if lv < Error || lv > Debug {
		return fmt.Sprintf("Level(%d)", int(lv))
	}
	return levelNames[lv]
}

// ParseLevel reads error, warn, info or debug, in any case.
func ParseLevel(s string) (Level, error) {
	for i, n := range levelNames {
		if strings.EqualFold(s, n) {
			return Level(i), nil
		}
	}
	return Info, fmt.Errorf("log level %q: want error, warn, info or debug", s)
}

// Tag says what a line is about. Find a simulation stage with
// grep '\[STEP\]', an API call with grep '\[API\]'.
type Tag string

// The tags.
const (
	TagRun  Tag = "RUN"  // the command, its settings, its exit
	TagAPI  Tag = "API"  // a call to a device
	TagSnap Tag = "SNAP" // which snapshot a device resolved to
	TagFind Tag = "FIND" // search findings
	TagStep Tag = "STEP" // a simulation stage
)

const redactMarker = "***"

// Options configure a run log.
type Options struct {
	Dir     string // created 0700 when absent
	Command string // part of the file name
	Keep    int    // files kept; 20 when zero
	Level   Level
	Echo    io.Writer // receives every line as well; nil for none
	Now     func() time.Time
}

// Logger writes one run's log. It is safe for concurrent use.
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	echo    io.Writer
	level   Level
	secrets []string
	path    string
	now     func() time.Time
}

// maxTries bounds the names Open tries before it gives up.
const maxTries = 999

// seqs numbers the logs this process opens. It is the package's one mutable
// value and is atomic: a server opens a log per call, concurrently, and a
// sequence number that never repeats in a process keeps two calls in one
// millisecond apart even while a rotation removes older files.
var seqs atomic.Uint64

// logName matches a run log's name: the command, the UTC timestamp and, since
// the sequence number came in, the sequence number.
var logName = regexp.MustCompile(`-(\d{8}T\d{6}\.\d{3}Z)(?:-(\d+))?\.log$`)

// Open creates the run's log file, <Dir>/<Command>-<UTC timestamp>-<seq>.log,
// mode 0600, and removes the oldest files beyond Keep. The sequence number
// counts the logs this process opened; when another process holds the name,
// Open takes the next number. So runs that open in the same millisecond each get
// their own file (spec 2026-10-09 §4.9).
func Open(o Options) (*Logger, error) {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("runlog: %w", err)
	}
	base := fileSafe(o.Command) + "-" + now().UTC().Format("20060102T150405.000Z")
	f, path, err := create(o.Dir, base, seqs.Add)
	if err != nil {
		return nil, fmt.Errorf("runlog: %w", err)
	}
	l := &Logger{file: f, echo: o.Echo, level: o.Level, path: path, now: now}
	keep := o.Keep
	if keep <= 0 {
		keep = 20
	}
	if err := rotate(o.Dir, keep); err != nil {
		l.Warnf(TagRun, "log rotation failed: %v", err)
	}
	return l, nil
}

// Discard returns a logger that writes nothing.
func Discard() *Logger { return nil }

// Path is the file this run logs to; empty for a discarding logger.
func (l *Logger) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Enabled reports whether a line at this level would be written, so a caller can
// skip building an expensive debug message.
func (l *Logger) Enabled(lv Level) bool { return l != nil && lv <= l.level }

// AddSecret registers a value to redact from every later line: a password, an API
// key. Longer secrets are replaced first, so an overlapping shorter one never
// leaves the tail of a longer one in the clear.
func (l *Logger) AddSecret(s string) {
	if l == nil || s == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secrets = append(l.secrets, s)
	slices.SortFunc(l.secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
}

// Errorf logs at ERROR.
func (l *Logger) Errorf(tag Tag, format string, args ...any) { l.write(Error, tag, format, args) }

// Warnf logs at WARN.
func (l *Logger) Warnf(tag Tag, format string, args ...any) { l.write(Warn, tag, format, args) }

// Infof logs at INFO.
func (l *Logger) Infof(tag Tag, format string, args ...any) { l.write(Info, tag, format, args) }

// Debugf logs at DEBUG.
func (l *Logger) Debugf(tag Tag, format string, args ...any) { l.write(Debug, tag, format, args) }

func (l *Logger) write(lv Level, tag Tag, format string, args []any) {
	if !l.Enabled(lv) {
		return
	}
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.secrets {
		msg = strings.ReplaceAll(msg, s, redactMarker)
	}
	line := fmt.Sprintf("%s [%s] [%s] %s\n", l.now().UTC().Format(time.RFC3339Nano), lv, tag, msg)
	if l.file != nil {
		_, _ = io.WriteString(l.file, line)
	}
	if l.echo != nil {
		_, _ = io.WriteString(l.echo, line)
	}
}

// Close closes the file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// create makes <dir>/<base>-<seq>.log with the first free number next gives.
func create(dir, base string, next func(uint64) uint64) (*os.File, string, error) {
	for try := 1; ; try++ {
		path := filepath.Join(dir, fmt.Sprintf("%s-%03d.log", base, next(1)))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err == nil {
			return f, path, nil
		}
		if !errors.Is(err, fs.ErrExist) || try == maxTries {
			return nil, "", err
		}
	}
}

// rotate keeps the newest keep log files. The names embed a sortable timestamp
// and a sequence number after the command, so the files are sorted by those,
// not by name. A file another run removed first is not an error: two runs that
// open at once both rotate.
func rotate(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type file struct {
		name, stamp string
		seq         int
	}
	var logs []file
	for _, e := range entries {
		m := logName.FindStringSubmatch(e.Name())
		if e.IsDir() || m == nil {
			continue
		}
		seq, _ := strconv.Atoi(m[2]) // a name from before the sequence number sorts first
		logs = append(logs, file{e.Name(), m[1], seq})
	}
	if len(logs) <= keep {
		return nil
	}
	slices.SortFunc(logs, func(a, b file) int {
		return cmp.Or(cmp.Compare(a.stamp, b.stamp), cmp.Compare(a.seq, b.seq))
	})
	for _, f := range logs[:len(logs)-keep] {
		if err := removeGone(filepath.Join(dir, f.name)); err != nil {
			return err
		}
	}
	return nil
}

// removeGone removes a file; one that is already gone is not an error.
func removeGone(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// fileSafe turns a command such as "simulate policy" into "simulate_policy".
func fileSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.':
			return r
		}
		return '_'
	}, s)
}
