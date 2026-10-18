package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kaisero/proteus/internal/query"
)

// name returns a completion value's command name, without its tab-separated
// description.
func name(v string) string {
	n, _, _ := strings.Cut(v, "\t")
	return n
}

func TestHelpCompletionOffersSubcommands(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	var got []string
	for _, v := range c.complete("help", "") {
		got = append(got, name(v))
	}
	if !slices.Contains(got, "snapshot") {
		t.Errorf("help <TAB>: got %v, want it to contain snapshot", got)
	}
	got = nil
	for _, v := range c.complete("help", "snapshot", "") {
		got = append(got, name(v))
	}
	for _, want := range []string{"list", "show", "diff"} {
		if !slices.Contains(got, want) {
			t.Errorf("help snapshot <TAB>: got %v, want it to contain %s", got, want)
		}
	}
}

func TestUnknownCommandsAreUsageErrors(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"bogus"}, {"snapshot", "bogus"}, {"simulate", "bogus"}, {"inventory", "bogus"}, {"help", "bogus"}} {
		c := newCLI(t)
		if _, errOut, code := c.run(args...); code != exitUsage {
			t.Errorf("%v: exit %d, want 2; stderr %q", args, code, errOut)
		}
	}
	c := newCLI(t)
	if out := c.want(0, "snapshot"); out == "" {
		t.Error("a bare group still prints its help")
	}
	if out := c.want(0, "help", "snapshot"); out == "" {
		t.Error("help on a known topic prints it")
	}
	if out := c.want(0, "help", "snapshot", "list"); out == "" {
		t.Error("help on a known subcommand prints it")
	}
	if _, errOut, code := c.run("help", "snapshot", "bogus"); code != exitUsage {
		t.Errorf("help snapshot bogus: exit %d, want 2; stderr %q", code, errOut)
	}
}

// effectiveColor mirrors effectiveFormat, used by errors that print before --color is
// resolved. It has no test of its own in the plan's Task 14 brief, so this one covers
// it directly rather than leave it untested until the later task that calls it.
func TestEffectiveColorBeforeAndAfterTheHook(t *testing.T) {
	t.Parallel()
	a := newApp(&bytes.Buffer{}, &bytes.Buffer{}, func(string) string { return "" }, time.Now)
	a.argv = []string{"search", "--color", "never"}
	if got := a.effectiveColor(); got != colorNever {
		t.Errorf("before the hook: %q, want %q", got, colorNever)
	}
	a.argv = []string{"search", "--color", "bogus"}
	if got := a.effectiveColor(); got != colorAuto {
		t.Errorf("an unparsable value falls back to %q, got %q", colorAuto, got)
	}
	a.hookRan, a.color = true, colorAlways
	if got := a.effectiveColor(); got != colorAlways {
		t.Errorf("after the hook, the resolved value wins: got %q, want %q", got, colorAlways)
	}
}

func TestLastFlag(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		argv []string
		want string
	}{
		{[]string{"search", "--output", "json"}, "json"},
		{[]string{"search", "--output=yaml", "--output", "json"}, "json"},
		{[]string{"search", "--", "--output", "json"}, ""},
		{[]string{"search", "--output"}, ""},
	} {
		if got := lastFlag(tc.argv, "output"); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.argv, got, tc.want)
		}
	}
}

func TestEarlyErrorsFollowTheFormat(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"search", "--bogus", "--output", "json"},
		{"bogus", "--output", "json"},
		{"search", "--output", "json"},
	} {
		c := newCLI(t)
		out, errOut, code := c.run(args...)
		var line struct {
			Format int    `json:"format"`
			Exit   int    `json:"exit"`
			Error  string `json:"error"`
			Log    string `json:"log"`
		}
		if code != exitUsage || out != "" || json.Unmarshal([]byte(strings.TrimSpace(errOut)), &line) != nil ||
			line.Exit != 2 || line.Error == "" || line.Log != "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out, errOut)
		}
	}
}

// An early error of proteus mcp does not read the inventory with
// credentials: its output: json does not apply, a flag does.
func TestAnEarlyMCPErrorReadsNoInventory(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory("version: 1\ndefaults:\n  output: json\ndevices: []\n")
	if _, errOut, code := c.run("search", "--bogus"); code != exitUsage || !strings.HasPrefix(errOut, "{") {
		t.Fatalf("search: exit %d, stderr %q", code, errOut)
	}
	if _, errOut, code := c.run("mcp", "--bogus"); code != exitUsage || strings.HasPrefix(errOut, "{") {
		t.Errorf("mcp: exit %d, stderr %q", code, errOut)
	}
	if _, errOut, code := c.run("mcp", "--bogus", "--output", "json"); code != exitUsage || !strings.HasPrefix(errOut, "{") {
		t.Errorf("mcp --output json: exit %d, stderr %q", code, errOut)
	}
}

func TestIncompleteJSONRunsEndWithTheExitLine(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	_, errOut, code := c.run("snapshot", "show", "--output", "json")
	if code != exitIncomplete || !strings.Contains(errOut, `"exit":3`) || strings.Contains(errOut, `"error"`) ||
		!strings.Contains(errOut, `"log":`) {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

// A signal that arrives while a command is running still closes the run log, and
// the log keeps both the signal and the command's own error.
func TestASignalDuringACommandEndsTheRunLog(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	c.inventory(inventoryFor(lab(t).Start(t)))
	c.want(0, "fetch", "fw01")

	var out, errOut bytes.Buffer
	now := c.clock
	a := newApp(&out, &errOut, func(k string) string { return c.env[k] }, func() time.Time { return now })
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(signalCause{os.Interrupt})
	code := a.execute(ctx, []string{"search", "198.18.10.100", "--config", c.cfgPath})
	if code != 130 {
		t.Fatalf("exit %d, want 130\nstdout:\n%s\nstderr:\n%s", code, out.String(), errOut.String())
	}
	if got := errOut.String(); got != "proteus: interrupted\nlog: "+a.log.Path()+"\n" {
		t.Errorf("stderr must show only proteus: interrupted, then the log line, got %q", got)
	}
	logContent, err := os.ReadFile(a.log.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logContent), "interrupted: context canceled") {
		t.Errorf("run log must name what the signal interrupted:\n%s", logContent)
	}
	if !strings.Contains(string(logContent), "exit 130") {
		t.Errorf("run log must record exit 130:\n%s", logContent)
	}
}

// A question the query layer refuses exits 2 with the command line's text.
func TestAQueryUsageErrorExitsTwo(t *testing.T) {
	t.Parallel()
	a := newApp(io.Discard, io.Discard, getenv, time.Now)
	u := &query.UsageError{Code: "call.usage", Text: "--port \"x\": want 443 or tcp/443", ToolText: "port \"x\": want 443 or tcp/443"}
	code, msg := a.exitCode(context.Background(), fmt.Errorf("simulate: %w", u))
	if code != exitUsage || msg == nil || msg.Error() != u.Text {
		t.Errorf("exit %d, %v", code, msg)
	}
}
