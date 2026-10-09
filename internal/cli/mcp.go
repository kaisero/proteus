package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/mcp"
	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/runlog"
)

// minToken is the shortest bearer token --http accepts (spec 2026-10-09 §4.3).
const minToken = 32

// mcpCmd is proteus mcp: the questions as MCP tools, over stdio or, with
// --http, over Streamable HTTP (spec 2026-10-09 §4.1).
func (a *app) mcpCmd() *cobra.Command {
	var useHTTP bool
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve the questions to MCP clients, over stdio or with --http over HTTP",
		Long: `Serve the questions to MCP clients from the stored snapshots.

Without --http the server talks MCP over standard input and output. With --http it
serves Streamable HTTP in plain text on --listen, behind a reverse proxy that
terminates TLS; every request needs the bearer token and an allowed Host.

The devices come from <store>/.proteus/inventory.yaml, which proteus fetch writes
with export_inventory: true. The server never reads the inventory with credentials.
Each setting comes from, in rising precedence: its default, the export's mcp:
section, a PROTEUS_MCP_* variable, and a flag. PROTEUS_MCP_TOKEN holds the token
itself; there is no flag for it.`,
		Args: args(cobra.NoArgs),
		RunE: func(c *cobra.Command, _ []string) error { return a.runMCP(c, useHTTP) },
	}
	f := cmd.Flags()
	f.BoolVar(&useHTTP, "http", false, "serve Streamable HTTP on --listen instead of stdio")
	f.String("listen", "", "host:port for --http (default 127.0.0.1:8765)")
	f.String("token-file", "", "the file that holds the bearer token")
	f.StringSlice("allowed-host", nil, "a Host header value --http answers (repeatable)")
	f.String("audit-log", "", "the audit file, one JSON line per call (required with --http)")
	f.Int("max-concurrent", 0, "calls answered at once (default 4)")
	f.Int("max-queue", 0, "calls waiting for a slot (default 16)")
	f.String("max-wait", "", "how long a call waits for a slot (default 10s)")
	f.String("call-timeout", "", "how long a call may run (default 60s)")
	f.Int("max-loads", 0, "snapshot loads at once (default 2)")
	f.Int("max-cache", 0, "cache size in MB (default 2048)")
	return cmd
}

// mcpKey is one mcp: setting: its inventory key, variable and flag ("" for
// none), read and written as text.
type mcpKey struct {
	key, env, flag string
	get            func(*inventory.MCP) string // "" when unset
	set            func(*inventory.MCP, string) error
}

// text is a string setting.
func text(key, flag string, f func(*inventory.MCP) *string) mcpKey {
	return mcpKey{
		key: key, env: envOf(key), flag: flag,
		get: func(m *inventory.MCP) string { return *f(m) },
		set: func(m *inventory.MCP, v string) error { *f(m) = v; return nil },
	}
}

// list is a list setting: comma-separated in a variable.
func list(key, flag string, f func(*inventory.MCP) *[]string) mcpKey {
	return mcpKey{
		key: key, env: envOf(key), flag: flag,
		get: func(m *inventory.MCP) string { return strings.Join(*f(m), ",") },
		set: func(m *inventory.MCP, v string) error {
			var out []string
			for p := range strings.SplitSeq(v, ",") {
				out = append(out, strings.TrimSpace(p))
			}
			*f(m) = out
			return nil
		},
	}
}

// number is a count setting; 0 is unset.
func number(key, flag string, f func(*inventory.MCP) *int) mcpKey {
	return mcpKey{
		key: key, env: envOf(key), flag: flag,
		get: func(m *inventory.MCP) string {
			if *f(m) == 0 {
				return ""
			}
			return strconv.Itoa(*f(m))
		},
		set: func(m *inventory.MCP, v string) error {
			n, err := strconv.Atoi(v)
			if err != nil {
				return errors.New("want a number")
			}
			*f(m) = n
			return nil
		},
	}
}

// envOf is a key's variable: PROTEUS_MCP_ and the key in capitals.
func envOf(key string) string { return "PROTEUS_MCP_" + strings.ToUpper(key) }

// mcpKeys are the mcp: settings of spec 2026-10-09 §4.2.
var mcpKeys = []mcpKey{
	text("listen", "listen", func(m *inventory.MCP) *string { return &m.Listen }),
	text("token_file", "token-file", func(m *inventory.MCP) *string { return &m.TokenFile }),
	list("allowed_hosts", "allowed-host", func(m *inventory.MCP) *[]string { return &m.AllowedHosts }),
	text("identity_header", "", func(m *inventory.MCP) *string { return &m.IdentityHeader }),
	list("audit_claims", "", func(m *inventory.MCP) *[]string { return &m.AuditClaims }),
	text("audit_log", "audit-log", func(m *inventory.MCP) *string { return &m.AuditLog }),
	text("log_dir", "", func(m *inventory.MCP) *string { return &m.LogDir }),
	number("log_keep", "", func(m *inventory.MCP) *int { return &m.LogKeep }),
	number("max_concurrent", "max-concurrent", func(m *inventory.MCP) *int { return &m.MaxConcurrent }),
	number("max_queue", "max-queue", func(m *inventory.MCP) *int { return &m.MaxQueue }),
	text("max_wait", "max-wait", func(m *inventory.MCP) *string { return &m.MaxWait }),
	text("call_timeout", "call-timeout", func(m *inventory.MCP) *string { return &m.CallTimeout }),
	number("max_loads", "max-loads", func(m *inventory.MCP) *int { return &m.MaxLoads }),
	number("max_cache", "max-cache", func(m *inventory.MCP) *int { return &m.MaxCache }),
}

// mcpDefaults are the settings no source sets (spec 2026-10-09 §4.2). The
// calls' run logs go to mcp under the CLI's log directory logDir, which the
// root hook resolved: a directory of their own, so each rotates apart.
func mcpDefaults(logDir string) inventory.MCP {
	l := mcp.DefaultLimits
	return inventory.MCP{
		Listen: "127.0.0.1:8765", IdentityHeader: "X-User-Claims", AuditClaims: []string{"sub"},
		LogDir: filepath.Join(logDir, "mcp"), LogKeep: 200,
		MaxConcurrent: l.MaxConcurrent, MaxQueue: l.MaxQueue, MaxWait: l.MaxWait.String(),
		CallTimeout: l.CallTimeout.String(), MaxLoads: l.MaxLoads, MaxCache: l.MaxCacheMB,
	}
}

// mcpSettings resolves the mcp: settings: default < the export's mcp:
// section < PROTEUS_MCP_* < flag. A value is checked as the file's are.
func (a *app) mcpSettings(c *cobra.Command, file *inventory.MCP) (inventory.MCP, error) {
	m := mcpDefaults(a.logDir)
	for _, k := range mcpKeys {
		if file != nil {
			if v := k.get(file); v != "" {
				_ = k.set(&m, v) // the file's values are typed already
			}
		}
		if v := a.getenv(k.env); v != "" {
			if err := k.set(&m, v); err != nil {
				return m, usageErr("%s %q: %v", k.env, v, err)
			}
		}
		if k.flag == "" || !c.Flags().Changed(k.flag) {
			continue
		}
		v := c.Flags().Lookup(k.flag).Value.String()
		if k.flag == "allowed-host" {
			hosts, _ := c.Flags().GetStringSlice(k.flag)
			v = strings.Join(hosts, ",")
		}
		if err := k.set(&m, v); err != nil {
			return m, usageErr("--%s %q: %v", k.flag, v, err)
		}
	}
	for _, p := range []*string{&m.TokenFile, &m.AuditLog, &m.LogDir} {
		*p = expandHome(*p)
	}
	if err := m.Validate(); err != nil {
		return m, usageErr("%v", err)
	}
	return m, nil
}

// mcpToken is the bearer token: from --token-file, else PROTEUS_MCP_TOKEN,
// else the token_file of the variable or the export. "" when none is set.
func (a *app) mcpToken(c *cobra.Command, m inventory.MCP) (string, error) {
	if !c.Flags().Changed("token-file") {
		if t := a.getenv("PROTEUS_MCP_TOKEN"); t != "" {
			return strings.TrimRightFunc(t, isSpace), nil
		}
	}
	if m.TokenFile == "" {
		return "", nil
	}
	return readToken(m.TokenFile)
}

// readToken reads a token file, trailing whitespace trimmed. It refuses a
// file that others can write: anyone could change the token. A read-only
// secret mount (0444, root) is fine.
func readToken(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", usageErr("token file: %v", err)
	}
	if fi.Mode().Perm()&0o002 != 0 {
		return "", usageErr("token file %s is mode %v: others can write it, so make it 0600 (chmod 600 %s)", path, fi.Mode().Perm(), path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", usageErr("token file: %v", err)
	}
	return strings.TrimRightFunc(string(b), isSpace), nil
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }

// readExport reads the inventory export the server answers for, with the
// start checks of spec 2026-10-09 §4.3: missing, holding credentials, or
// without a device is a usage error; an unreadable store is not.
func readExport(root string) (*inventory.Inventory, error) {
	path := inventory.ExportPath(root)
	inv, err := inventory.ReadExport(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, usageErr("no inventory export at %s: run proteus fetch first, with export_inventory: true", path)
	case errors.Is(err, fs.ErrPermission):
		return nil, err
	case err != nil:
		return nil, &exitErr{code: exitUsage, err: err}
	case len(inv.Devices) == 0:
		return nil, usageErr("the inventory export %s has no device", path)
	}
	return inv, nil
}

// runMCP checks the settings and serves until ctx ends or the client goes.
func (a *app) runMCP(c *cobra.Command, useHTTP bool) error {
	export, err := readExport(a.storeRoot)
	if err != nil {
		return err
	}
	m, err := a.mcpSettings(c, export.MCP)
	if err != nil {
		return err
	}
	// Only --http reads the token: a token_file the export names must not
	// stop a stdio server, which needs none.
	var token string
	if useHTTP {
		if token, err = a.mcpToken(c, m); err != nil {
			return err
		}
		switch {
		case token == "":
			return usageErr("--http needs a token: set token_file, --token-file or PROTEUS_MCP_TOKEN")
		case len(token) < minToken:
			return usageErr("the token is %d bytes; --http needs at least %d", len(token), minToken)
		case len(m.AllowedHosts) == 0:
			return usageErr("--http needs allowed_hosts: set them in the mcp: section, PROTEUS_MCP_ALLOWED_HOSTS or --allowed-host")
		case m.AuditLog == "":
			return usageErr("--http needs audit_log: set it in the mcp: section, PROTEUS_MCP_AUDIT_LOG or --audit-log")
		}
	}
	st, err := a.openStore(a.storeRoot)
	if err != nil {
		return err
	}
	// The export's max_snapshot_age is the file source of --max-age here.
	maxAge := a.maxAge
	for _, s := range a.settingTable() {
		if s.name != "max-age" {
			continue
		}
		v, src, err := a.resolve(s, export.Defaults)
		if err != nil {
			return err
		}
		if maxAge, err = inventory.ParseAge(v); err != nil {
			return usageErr("max-age %q (from %s): %w", v, src, err)
		}
	}
	o := mcp.Options{
		Env: query.Env{
			Store: st, Inventory: export, Now: a.now, MaxAge: maxAge,
			Resolve: a.lookup, CanonicalName: a.canonical, Users: a.userSnapshot,
		},
		Version: a.version, Now: a.now,
		Limits: limitsOf(m),
		Logs:   &runlog.Options{Dir: m.LogDir, Keep: m.LogKeep, Level: a.logLevel, Now: a.now},
	}
	if m.AuditLog != "" {
		audit, err := mcp.OpenAudit(m.AuditLog)
		if err != nil {
			return err
		}
		defer func() { _ = audit.Close() }()
		audit.OnError = func(err error) { fmt.Fprintf(a.stderr, "proteus: warning: %v\n", err) }
		o.Audit = audit
	}
	a.log.Infof(runlog.TagRun, "mcp: %d devices, calls logged in %s", len(export.Devices), m.LogDir)
	ctx := c.Context()
	if !useHTTP {
		o.Identify = mcp.StdioIdentity(osUser(a.getenv))
		return quiet(mcp.Serve(ctx, o, mcp.Streams(a.stdin, a.stdout)))
	}
	o.Identify = mcp.HeaderIdentity(m.IdentityHeader, m.AuditClaims)
	ln, err := net.Listen("tcp", m.Listen)
	if err != nil {
		return err
	}
	a.log.Infof(runlog.TagRun, "mcp: serving http://%s", ln.Addr())
	fmt.Fprintf(a.stderr, "proteus mcp: serving http://%s\n", ln.Addr())
	return mcp.ServeHTTP(ctx, o, mcp.HTTPOptions{Token: token, AllowedHosts: m.AllowedHosts}, ln)
}

// quiet is a stdio server's end: the client closing its input is a normal
// end.
func quiet(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// limitsOf are the server's limits from the settings; the durations were
// checked.
func limitsOf(m inventory.MCP) mcp.Limits {
	wait, _ := time.ParseDuration(m.MaxWait)
	timeout, _ := time.ParseDuration(m.CallTimeout)
	return mcp.Limits{
		MaxConcurrent: m.MaxConcurrent, MaxQueue: m.MaxQueue, MaxWait: wait, CallTimeout: timeout,
		MaxLoads: m.MaxLoads, MaxCacheMB: m.MaxCache,
	}
}

// osUser is the user that runs a stdio server, for its audit lines.
func osUser(getenv func(string) string) string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return getenv("USER")
}
