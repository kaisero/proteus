package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/inventory"
)

// mcpTokenValue is a dummy bearer token of 32 bytes.
const mcpTokenValue = "0123456789abcdef0123456789abcdef"

// syncBuffer is a buffer a command writes while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// mcpLab is a CLI whose store holds a fetched fw01 and the inventory export,
// with mcp as the export's mcp: section.
func mcpLab(t *testing.T, mcpSection string) *cli {
	t.Helper()
	c := newCLI(t)
	doc := exporting(inventoryFor(lab(t).Start(t)))
	if mcpSection != "" {
		doc += "mcp:\n" + mcpSection
	}
	c.inventory(doc)
	c.want(0, "fetch", "fw01")
	// The server reads the export only: no inventory with credentials.
	if err := os.Remove(c.cfgPath); err != nil {
		t.Fatal(err)
	}
	c.env["PROTEUS_MCP_LOG_DIR"] = filepath.Join(c.dir, "mcp-log")
	return c
}

// serveMCP runs proteus mcp with stdin and ctx, and returns its exit code
// once it ends.
func (c *cli) serveMCP(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args ...string) int {
	a := newApp(stdout, stderr, func(k string) string { return c.env[k] }, func() time.Time { return c.clock })
	a.stdin = stdin
	return a.execute(ctx, append([]string{"mcp"}, args...))
}

// The start checks of spec 2026-10-09 §4.3, and the token file rules.
func TestMCPStartChecks(t *testing.T) {
	t.Parallel()
	c := mcpLab(t, "  allowed_hosts: [proteus.example.org]\n")
	audit := "--audit-log=" + filepath.Join(c.dir, "audit.jsonl")
	tokenFile := func(mode os.FileMode, body string) string {
		p := filepath.Join(t.TempDir(), "token")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		args []string
		code int
		msg  string
	}{
		{"http without a token", nil, []string{"--http", audit}, 2, "--http needs a token"},
		{"short token", map[string]string{"PROTEUS_MCP_TOKEN": "short"}, []string{"--http", audit}, 2, "at least 32"},
		{"short token file", nil, []string{"--http", audit, "--token-file", tokenFile(0o600, "short\n")}, 2, "at least 32"},
		{"an empty allowed host", map[string]string{"PROTEUS_MCP_TOKEN": mcpTokenValue}, []string{"--http", audit, "--allowed-host", ""}, 2, "allowed_hosts"},
		{"no audit log", map[string]string{"PROTEUS_MCP_TOKEN": mcpTokenValue}, []string{"--http"}, 2, "--http needs audit_log"},
		{"token file others write", nil, []string{"--http", audit, "--token-file", tokenFile(0o666, mcpTokenValue)}, 2, "others can write it"},
		{"missing token file", nil, []string{"--http", audit, "--token-file", filepath.Join(c.dir, "none")}, 2, "token file"},
		{"bad variable", map[string]string{"PROTEUS_MCP_MAX_QUEUE": "many"}, nil, 2, "PROTEUS_MCP_MAX_QUEUE"},
		{"bad flag", nil, []string{"--max-wait", "soon"}, 2, "max_wait"},
		{"bad header", map[string]string{"PROTEUS_MCP_IDENTITY_HEADER": "X User"}, nil, 2, "identity_header"},
		{"empty claim", map[string]string{"PROTEUS_MCP_AUDIT_CLAIMS": "sub,"}, nil, 2, "audit_claims"},
		{"bad listen", map[string]string{"PROTEUS_MCP_TOKEN": mcpTokenValue, "PROTEUS_MCP_LISTEN": "256.0.0.1:1"}, []string{"--http", audit}, 1, ""},
		{"an argument", nil, []string{"extra"}, 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := map[string]string{}
			for k, v := range c.env {
				env[k] = v
			}
			for k, v := range tc.env {
				env[k] = v
			}
			cc := *c
			cc.env = env
			var errOut bytes.Buffer
			if code := cc.serveMCP(context.Background(), strings.NewReader(""), io.Discard, &errOut, tc.args...); code != tc.code ||
				!strings.Contains(errOut.String(), tc.msg) {
				t.Errorf("exit %d, want %d; stderr:\n%s", code, tc.code, errOut.String())
			}
		})
	}
}

// --http without allowed_hosts in any source does not start.
func TestMCPNeedsAllowedHosts(t *testing.T) {
	t.Parallel()
	c := mcpLab(t, "")
	c.env["PROTEUS_MCP_TOKEN"] = mcpTokenValue
	var errOut bytes.Buffer
	audit := "--audit-log=" + filepath.Join(c.dir, "audit.jsonl")
	if code := c.serveMCP(context.Background(), strings.NewReader(""), io.Discard, &errOut, "--http", audit); code != 2 ||
		!strings.Contains(errOut.String(), "--http needs allowed_hosts") {
		t.Errorf("exit %d; stderr:\n%s", code, errOut.String())
	}
}

// The export decides what the server answers for: missing, holding
// credentials, without a device, or unreadable.
func TestMCPNeedsTheExport(t *testing.T) {
	t.Parallel()
	c := newCLI(t)
	run := func() (int, string) {
		var errOut bytes.Buffer
		code := c.serveMCP(context.Background(), strings.NewReader(""), io.Discard, &errOut)
		return code, errOut.String()
	}
	if code, msg := run(); code != 2 || !strings.Contains(msg, "run proteus fetch first") {
		t.Errorf("no export: %d %s", code, msg)
	}
	path := inventory.ExportPath(c.env["PROTEUS_STORE"])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(doc string) {
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(inventoryFor("fw01.example.test"))
	if code, msg := run(); code != 2 || !strings.Contains(msg, "holds credentials") {
		t.Errorf("credentials: %d %s", code, msg)
	}
	write("version: 1\ndevices: []\n")
	if code, msg := run(); code != 2 || !strings.Contains(msg, "has no device") {
		t.Errorf("no device: %d %s", code, msg)
	}
	write("version: 2\n")
	if code, _ := run(); code != 2 {
		t.Errorf("a broken export: %d", code)
	}
	write("version: 1\ndevices:\n  - {name: fw01, host: fw01.example.test}\n")
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if code, _ := run(); code != 1 {
		t.Errorf("an unreadable export: %d", code)
	}
}

// Each setting comes from its default, the export's mcp: section, a
// PROTEUS_MCP_* variable and a flag, in rising precedence.
func TestMCPSettingPrecedence(t *testing.T) {
	t.Parallel()
	a := newApp(io.Discard, io.Discard, func(k string) string {
		return map[string]string{
			"XDG_STATE_HOME": "/state", "PROTEUS_MCP_MAX_QUEUE": "7", "PROTEUS_MCP_MAX_WAIT": "3s",
			"PROTEUS_MCP_AUDIT_CLAIMS": "sub, email", "PROTEUS_MCP_ALLOWED_HOSTS": "env.example.org",
		}[k]
	}, time.Now)
	a.logDir = "/state/proteus/log" // the root hook resolves it
	cmd := a.mcpCmd()
	if err := cmd.ParseFlags([]string{"--max-wait", "4s", "--allowed-host", "a.example.org", "--allowed-host", "b.example.org"}); err != nil {
		t.Fatal(err)
	}
	file := &inventory.MCP{MaxQueue: 5, MaxConcurrent: 3, MaxWait: "2s", IdentityHeader: "X-User-Claims", LogKeep: 9}
	m, err := a.mcpSettings(cmd, file)
	if err != nil {
		t.Fatal(err)
	}
	want := inventory.MCP{
		Listen: "127.0.0.1:8765", AllowedHosts: []string{"a.example.org", "b.example.org"}, IdentityHeader: "X-User-Claims",
		AuditClaims: []string{"sub", "email"}, LogDir: "/state/proteus/log/mcp", LogKeep: 9,
		MaxConcurrent: 3, MaxQueue: 7, MaxWait: "4s", CallTimeout: "1m0s", MaxLoads: 2, MaxCache: 2048,
	}
	if b, w := mustJSON(t, m), mustJSON(t, want); b != w {
		t.Errorf("settings\n%s\nwant\n%s", b, w)
	}
	if l := limitsOf(m); l.MaxQueue != 7 || l.MaxWait != 4*time.Second || l.CallTimeout != time.Minute || l.MaxConcurrent != 3 {
		t.Errorf("limits %+v", l)
	}
	// Without a file, the defaults.
	m, err = a.mcpSettings(a.mcpCmd(), nil)
	if err != nil || m.MaxConcurrent != 4 || m.MaxWait != "3s" || m.IdentityHeader != "X-User-Claims" || !slices.Equal(m.AuditClaims, []string{"sub", "email"}) {
		t.Errorf("no file: %+v %v", m, err)
	}
	// The calls' logs default to mcp under the CLI's log directory.
	a.logDir = "/logs/cli"
	if m, err = a.mcpSettings(a.mcpCmd(), nil); err != nil || m.LogDir != "/logs/cli/mcp" {
		t.Errorf("log dir %q, %v", m.LogDir, err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The token: --token-file wins over PROTEUS_MCP_TOKEN, which wins over a
// token_file of the variable or the export. Trailing whitespace goes; a
// read-only file is fine.
func TestMCPToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	flagFile := file("flag", "from-flag \n\n", 0o444)
	exportFile := file("export", "from-export\r\n", 0o400)
	for _, tc := range []struct {
		name, env string
		flag      bool
		m         inventory.MCP
		want      string
	}{
		{"flag wins", "from-env", true, inventory.MCP{TokenFile: flagFile}, "from-flag"},
		{"variable over the file", "from-env\n", false, inventory.MCP{TokenFile: exportFile}, "from-env"},
		{"the file", "", false, inventory.MCP{TokenFile: exportFile}, "from-export"},
		{"none", "", false, inventory.MCP{}, ""},
	} {
		a := newApp(io.Discard, io.Discard, func(k string) string {
			if k == "PROTEUS_MCP_TOKEN" {
				return tc.env
			}
			return ""
		}, time.Now)
		cmd := a.mcpCmd()
		if tc.flag {
			if err := cmd.ParseFlags([]string{"--token-file", flagFile}); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := a.mcpToken(cmd, tc.m); err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	if _, err := readToken(file("group", "x", 0o620)); err != nil {
		t.Errorf("a file its group can write: %v", err)
	}
	unreadable := file("unreadable", "x", 0)
	if os.Geteuid() != 0 {
		if _, err := readToken(unreadable); err == nil {
			t.Error("read an unreadable token file")
		}
	}
}

// Only --http reads the token: a token_file in the export that is missing,
// or that others can write, does not stop a stdio server.
func TestMCPStdioIgnoresTheToken(t *testing.T) {
	t.Parallel()
	writable := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(writable, []byte(mcpTokenValue), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(t.TempDir(), "missing"), writable} {
		c := mcpLab(t, "  token_file: "+path+"\n  allowed_hosts: [proteus.example.org]\n")
		var stderr bytes.Buffer
		if code := c.serveMCP(context.Background(), strings.NewReader(""), io.Discard, &stderr); code != 0 {
			t.Errorf("%s: stdio exit %d: %s", path, code, stderr.String())
		}
		stderr.Reset()
		if code := c.serveMCP(context.Background(), strings.NewReader(""), io.Discard, &stderr, "--http", "--audit-log", filepath.Join(c.dir, "audit.jsonl")); code != 2 || !strings.Contains(stderr.String(), "token file") {
			t.Errorf("%s: http exit %d: %s", path, code, stderr.String())
		}
	}
}

// proteus mcp over stdio: a client initialises, lists the tools and calls
// one; the call is audited as stdio and gets its own run log. The client's
// end of input ends the server with exit 0.
func TestMCPOverStdio(t *testing.T) {
	t.Parallel()
	c := mcpLab(t, "")
	auditPath := filepath.Join(c.dir, "audit.jsonl")
	c.env["PROTEUS_MCP_AUDIT_LOG"] = auditPath
	in, client := io.Pipe()
	out := &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- c.serveMCP(context.Background(), in, out, io.Discard) }()
	send := func(line string) {
		t.Helper()
		if _, err := io.WriteString(client, line+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor := func(id string) map[string]any {
		t.Helper()
		for range 1000 {
			for line := range strings.SplitSeq(out.String(), "\n") {
				var msg map[string]any
				if json.Unmarshal([]byte(line), &msg) == nil && mustJSON(t, msg["id"]) == id {
					return msg
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("no answer %s; stdout:\n%s", id, out.String())
		return nil
	}
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	waitFor("1")
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if tools := mustJSON(t, waitFor("2")); !strings.Contains(tools, `"enum":["fw01"]`) || !strings.Contains(tools, `"simulate_policy"`) {
		t.Errorf("tools/list: %s", tools)
	}
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search","arguments":{"value":"198.18.10.100"}}}`)
	res := waitFor("3")
	if r := mustJSON(t, res["result"]); !strings.Contains(r, `"envelope"`) || strings.Contains(r, `"isError":true`) {
		t.Errorf("tools/call: %s", r)
	}
	_ = client.Close()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit %d after the client went", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not end with its input")
	}
	line := strings.TrimSpace(read(t, auditPath))
	var audited map[string]any
	if err := json.Unmarshal([]byte(line), &audited); err != nil {
		t.Fatalf("audit %q: %v", line, err)
	}
	if audited["auth"] != "stdio" || audited["identity_source"] != "os" || audited["tool"] != "search" || audited["status"] != "ok" {
		t.Errorf("audit %s", line)
	}
	logs, _ := os.ReadDir(c.env["PROTEUS_MCP_LOG_DIR"])
	if len(logs) != 1 || !regexp.MustCompile(`^mcp-search-.*\.log$`).MatchString(logs[0].Name()) {
		t.Errorf("run logs %v", logs)
	}
	// The command's own run log is the CLI's, apart from the calls' logs.
	if l := c.logFile(); !strings.Contains(l, "proteus dev: mcp") || !strings.Contains(l, "[RUN] exit 0") {
		t.Errorf("command log:\n%s", l)
	}
}

// proteus mcp --http: a client with the token gets an answer, one without
// gets 401; SIGTERM ends the server with exit 143, SIGINT with 130. The
// defaults read the identity from X-User-Claims and write each call's run log
// to mcp under the CLI's log directory.
func TestMCPOverHTTP(t *testing.T) {
	t.Parallel()
	for _, sig := range []struct {
		sig  os.Signal
		code int
	}{{syscall.SIGTERM, 143}, {os.Interrupt, 130}} {
		c := mcpLab(t, "  allowed_hosts: [127.0.0.1]\n")
		delete(c.env, "PROTEUS_MCP_LOG_DIR")
		c.env["PROTEUS_MCP_LISTEN"] = freePort(t)
		auditPath := filepath.Join(c.dir, "audit.jsonl")
		c.env["PROTEUS_MCP_TOKEN"] = mcpTokenValue
		ctx, cancel := context.WithCancelCause(context.Background())
		errOut := &syncBuffer{}
		done := make(chan int, 1)
		go func() {
			done <- c.serveMCP(ctx, strings.NewReader(""), io.Discard, errOut, "--http", "--audit-log", auditPath)
		}()
		var url string
		addr := regexp.MustCompile(`serving (http://\S+)`)
		for range 1000 {
			if m := addr.FindStringSubmatch(errOut.String()); m != nil {
				url = m[1] + "/"
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if url == "" {
			t.Fatalf("the server did not start:\n%s", errOut.String())
		}
		post := func(auth string) (int, string) {
			t.Helper()
			req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{"value":"198.18.10.100"}}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("X-User-Claims", `{"sub":"alice"}`)
			if auth != "" {
				req.Header.Set("Authorization", auth)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			var body strings.Builder
			sc := bufio.NewScanner(res.Body)
			sc.Buffer(nil, 1<<22)
			for sc.Scan() {
				body.WriteString(sc.Text() + "\n")
			}
			return res.StatusCode, body.String()
		}
		if code, _ := post(""); code != http.StatusUnauthorized {
			t.Errorf("no token: %d", code)
		}
		if code, body := post("Bearer " + mcpTokenValue); code != http.StatusOK || !strings.Contains(body, `"envelope"`) {
			t.Errorf("with the token: %d\n%s", code, body)
		}
		cancel(signalCause{sig.sig})
		select {
		case code := <-done:
			if code != sig.code {
				t.Errorf("%v: exit %d, want %d", sig.sig, code, sig.code)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the server did not stop")
		}
		lines := strings.Split(strings.TrimSpace(read(t, auditPath)), "\n")
		statuses := []string{}
		for _, l := range lines {
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatal(err)
			}
			statuses = append(statuses, m["status"].(string))
			if m["status"] == "ok" && (m["auth"] != "token" || m["identity_source"] != "header" || mustJSON(t, m["identity"]) != `{"sub":"alice"}`) {
				t.Errorf("audit %s", l)
			}
		}
		if !slices.Equal(statuses, []string{"unauthorised", "ok"}) {
			t.Errorf("audited %v", statuses)
		}
		if fi, err := os.Stat(auditPath); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("audit mode %v %v", fi, err)
		}
		logs, _ := os.ReadDir(filepath.Join(c.env["PROTEUS_LOG_DIR"], "mcp"))
		if len(logs) != 1 || !strings.HasPrefix(logs[0].Name(), "mcp-search-") {
			t.Errorf("call logs %v", logs)
		}
	}
}

// freePort is a loopback address with a port free a moment ago.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// An audit file that cannot open stops the start.
func TestMCPAuditLogMustOpen(t *testing.T) {
	t.Parallel()
	c := mcpLab(t, "")
	c.env["PROTEUS_MCP_AUDIT_LOG"] = filepath.Join(c.dir, "no", "such", "audit.jsonl")
	var errOut bytes.Buffer
	if code := c.serveMCP(context.Background(), strings.NewReader(""), io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "audit log") {
		t.Errorf("exit %d\n%s", code, errOut.String())
	}
}

// The client closing its input ends a stdio server normally.
func TestQuiet(t *testing.T) {
	t.Parallel()
	other := io.ErrClosedPipe
	if quiet(io.EOF) != nil || quiet(nil) != nil || !errors.Is(quiet(other), other) {
		t.Error("quiet")
	}
	if osUser(func(string) string { return "" }) == "" {
		t.Error("no user name")
	}
}
