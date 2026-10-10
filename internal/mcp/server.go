package mcp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/runlog"
)

// Options configure the server.
type Options struct {
	// Env is what every call reads: the store and the exported inventory
	// (inventory.ReadExport), whose devices are the tools' device enum.
	Env query.Env
	// Audit receives one record per tool call; nil audits nothing.
	Audit Auditor
	// Version is the server's version as it introduces itself.
	Version string
	// Now is the audit clock; nil uses time.Now.
	Now func() time.Time
	// Limits bound the loads and the cache; a zero field takes its default.
	Limits Limits
	// Identify gives a call's identity from its HTTP header (nil over
	// stdio): HeaderIdentity or StdioIdentity. Nil records none.
	Identify func(http.Header) Identity
	// Logs is the run log of each tool call, named mcp-<tool>-<time>-<seq>.log
	// in Logs.Dir, Logs.Keep kept (spec §4.9). Command is set per call. The
	// file is written only for a call that ends internal or timeout, or for
	// every call at Logs.Level debug (spec 2026-10-10 F4). Nil writes none.
	Logs *runlog.Options
	// Log is the server process's own log: the counts of refused HTTP
	// requests go there. Nil writes nothing.
	Log *runlog.Logger
}

// Limits bound what the server does at once and keeps (spec §4.2, §4.7).
type Limits struct {
	// MaxConcurrent is how many calls run at once.
	MaxConcurrent int
	// MaxWait is how long a call waits for a free slot.
	MaxWait time.Duration
	// CallTimeout is how long a call may run before it answers call.timeout.
	// Its work keeps the slot until it returns. Stopping waits as long.
	CallTimeout time.Duration
	// MaxLoads is how many configuration loads and index builds run at once.
	MaxLoads int
	// MaxQueue is how many calls may wait for a slot, and how many loads
	// for a load slot.
	MaxQueue int
	// MaxCacheMB is the cache's size limit in MB (spec §4.8).
	MaxCacheMB int
}

// DefaultLimits are the limits of spec §4.2.
var DefaultLimits = Limits{
	MaxConcurrent: 4, MaxWait: 10 * time.Second, CallTimeout: 60 * time.Second,
	MaxLoads: 2, MaxQueue: 16, MaxCacheMB: 2048,
}

// withDefaults is l with each zero field set to its default.
func (l Limits) withDefaults() Limits {
	l.MaxConcurrent = cmp.Or(l.MaxConcurrent, DefaultLimits.MaxConcurrent)
	l.MaxWait = cmp.Or(l.MaxWait, DefaultLimits.MaxWait)
	l.CallTimeout = cmp.Or(l.CallTimeout, DefaultLimits.CallTimeout)
	l.MaxLoads = cmp.Or(l.MaxLoads, DefaultLimits.MaxLoads)
	l.MaxQueue = cmp.Or(l.MaxQueue, DefaultLimits.MaxQueue)
	l.MaxCacheMB = cmp.Or(l.MaxCacheMB, DefaultLimits.MaxCacheMB)
	return l
}

// The audit statuses of a call (spec §4.9).
const (
	StatusOK       = "ok"
	StatusUsage    = "usage"
	StatusChoice   = "choice"
	StatusBusy     = "busy"
	StatusTimeout  = "timeout"
	StatusInternal = "internal"
)

// Call is the audit record of one tool call. The audit writer adds the
// caller's identity and writes it as one JSON line (spec §4.9).
type Call struct {
	Time   time.Time
	Tool   string
	Input  json.RawMessage // the arguments as the client sent them
	Status string          // StatusOK, StatusUsage, ...
	// Code is the error's code; empty when the call answered.
	Code reason.Code
	// Answers are the answer lines, the summary's first.
	Answers []string
	// Codes are the reason codes of the holes, unresolved entries and notes.
	Codes []reason.Code
	// Snapshots are the snapshots read, as device@id.
	Snapshots []string
	Duration  time.Duration
	// Err is the error the SDK returned, such as output that failed its
	// schema (S3) or an input error (S7).
	Err string
	// Stack is a recovered panic's value and stack, for the run log; the
	// audit line does not hold it.
	Stack []byte
	// Identity is who the call claims to come from.
	Identity Identity
}

// Auditor records tool calls. Audit runs once per call, after the answer,
// possibly from several calls at once.
type Auditor interface {
	Audit(Call)
}

// callKey keys a call's record in its context.
type callKey struct{}

// callOf is the record of the call ctx carries, or nil.
func callOf(ctx context.Context) *Call {
	c, _ := ctx.Value(callKey{}).(*Call)
	return c
}

// set changes the record; a nil record, outside a served call, takes nothing.
func (c *Call) set(f func(*Call)) {
	if c != nil {
		f(c)
	}
}

// instructions tell the model how to read the answers (spec §4.6).
const instructions = "Report each result's verdict together with its fidelity level. " +
	"Never report an undecided result, or a fidelity of inferred or undermatch, as allowed or denied. " +
	"Ask the user for each input a result's needs list names, and call again with it. " +
	"When a note says a snapshot is stale, state the snapshot's age. " +
	"On the error call.choice, ask the user to pick one of the options and call again with it."

// New is the MCP server: the six tools, the resources and the instructions,
// with the receiving middleware that audits and recovers every call.
func New(o Options) (*sdk.Server, error) {
	return newServer(o, testing.Testing())
}

// newServer is New. strict re-panics a recovered panic, as a test binary
// does: there an unregistered reason code or a bug fails the test instead of
// hiding as call.internal.
func newServer(o Options, strict bool) (*sdk.Server, error) {
	s, _, err := build(o, strict)
	return s, err
}

// build is newServer, with the limiter that Serve stops.
func build(o Options, strict bool) (*sdk.Server, *limiter, error) {
	if o.Env.Inventory == nil || len(o.Env.Inventory.Devices) == 0 {
		return nil, nil, errors.New("mcp: the inventory has no device")
	}
	s := sdk.NewServer(&sdk.Implementation{Name: "proteus", Version: o.Version}, &sdk.ServerOptions{Instructions: instructions})
	lim := o.Limits.withDefaults()
	cache := newCache(int64(lim.MaxCacheMB)<<20, lim.MaxLoads, lim.MaxQueue, strict)
	if err := addTools(s, calls{env: o.Env, cache: cache}, o.Env.Inventory.Names()); err != nil {
		return nil, nil, err
	}
	if err := addResources(s); err != nil {
		return nil, nil, err
	}
	m := middleware{audit: o.Audit, now: o.Now, identify: o.Identify, logs: o.Logs, strict: strict, lim: newLimiter(lim.MaxConcurrent, lim.MaxQueue, lim.MaxWait, lim.CallTimeout)}
	if m.now == nil {
		m.now = time.Now
	}
	s.AddReceivingMiddleware(m.receive)
	return s, m.lim, nil
}

// Serve answers MCP calls over t until ctx ends or the client goes. When ctx
// ends (SIGTERM), new calls answer call.busy, the running calls get up to
// the call timeout to answer over t, and then Serve returns.
func Serve(ctx context.Context, o Options, t sdk.Transport) error {
	s, lim, err := build(o, testing.Testing())
	if err != nil {
		return err
	}
	// The session outlives ctx: the calls that run when it ends still answer.
	ss, err := s.Connect(context.WithoutCancel(ctx), t, nil)
	if err != nil {
		return err
	}
	ended := make(chan error, 1)
	go func() { ended <- ss.Wait() }()
	select {
	case err := <-ended:
		// The client went; the work of its calls still holds their slots.
		lim.stop()
		return err
	case <-ctx.Done():
	}
	begun, answering := lim.begun(), lim.answering()
	lim.stop()
	// The SDK has no drain hook: its Close refuses every answer not yet
	// written (jsonrpc2 refuses writes once Close starts). So Serve waits a
	// moment for the answers of the calls that returned, unless no call ran
	// or arrived since the stop began. ServeHTTP needs no such wait.
	if answering > 0 || lim.begun() != begun {
		time.Sleep(answerGrace)
	}
	_ = ss.Close()
	<-ended
	return ctx.Err()
}

// answerGrace is how long Serve waits, after the last call returned, for its
// answer to be written before it closes the session.
const answerGrace = 100 * time.Millisecond

// Stdio is the transport over standard input and output.
func Stdio() sdk.Transport { return &sdk.StdioTransport{} }

// Streams is the stdio transport over r and w, one JSON-RPC message per
// line. Serve does not close them.
func Streams(r io.Reader, w io.Writer) sdk.Transport {
	return &sdk.IOTransport{Reader: io.NopCloser(r), Writer: nopCloser{w}}
}

// nopCloser is a writer whose Close does nothing.
type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// middleware audits each tool call, bounds the calls and recovers a panic
// (S3, S7, S8, spec §4.7).
type middleware struct {
	audit    Auditor
	now      func() time.Time
	identify func(http.Header) Identity
	logs     *runlog.Options
	strict   bool
	// lim bounds the calls; nil runs each at once with no time limit.
	lim *limiter
}

// internalText is a recovered panic's error text.
const internalText = "the server failed while it answered; the answer is not given"

// receive wraps the SDK's handling of each request.
func (m middleware) receive(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (res sdk.Result, err error) {
		if method != "tools/call" {
			defer func() {
				if p := recover(); p != nil {
					if m.strict {
						panic(p)
					}
					res, err = nil, fmt.Errorf("%s: %s", method, internalText)
				}
			}()
			return next(ctx, method, req)
		}
		c := &Call{Time: m.now()}
		if r, ok := req.(*sdk.CallToolRequest); ok && r.Params != nil {
			c.Tool, c.Input = r.Params.Name, r.Params.Arguments
		}
		if m.identify != nil {
			var h http.Header
			if ex := req.GetExtra(); ex != nil {
				h = ex.Header
			}
			c.Identity = m.identify(h)
		}
		if m.lim != nil {
			// Deferred before the audit, so it runs after it: stop does not
			// see a call answered before its audit line is written.
			m.lim.begin()
			defer m.lim.end()
		}
		var log *runlog.Logger
		defer func() {
			c.Duration = m.now().Sub(c.Time)
			if m.audit != nil {
				m.audit.Audit(*c)
			}
			closeLog(log, c)
		}()
		if m.lim != nil {
			if err := m.lim.enter(ctx); err != nil {
				// Refused before it ran: audited, but no run log.
				return refused(c, err), nil
			}
		}
		log = m.openLog(c)
		ctx = context.WithValue(ctx, logKey{}, log)
		if m.lim == nil {
			return m.handle(ctx, next, method, req, c)
		}
		return m.bounded(ctx, next, method, req, c)
	}
}

// logKey keys a call's run log in its context.
type logKey struct{}

// logOf is the run log of the call ctx carries, or nil.
func logOf(ctx context.Context) *runlog.Logger {
	l, _ := ctx.Value(logKey{}).(*runlog.Logger)
	return l
}

// maxLogTool bounds the tool name in a run log's file name: the client
// names the tool, also one that does not exist.
const maxLogTool = 64

// openLog opens the run log of call c and records its input; nil when the
// server writes none or the log does not open. At debug the file opens now;
// else the log holds its lines in memory until closeLog keeps them.
func (m middleware) openLog(c *Call) *runlog.Logger {
	if m.logs == nil {
		return nil
	}
	o := *m.logs
	o.Command = "mcp-" + cut(c.Tool, maxLogTool)
	var l *runlog.Logger
	if o.Level >= runlog.Debug {
		var err error
		if l, err = runlog.Open(o); err != nil {
			return nil
		}
	} else {
		l = runlog.Buffered(o)
	}
	l.Infof(runlog.TagRun, "call %s: %s", c.Tool, c.Input)
	return l
}

// closeLog records how call c ended in its run log, a panic's stack
// included, and closes the log. A buffered log is written only when the call
// ended internal or timeout: a fault or a slow call keeps its detail, and an
// answer explains itself in its reasons and codes (spec 2026-10-10 F4).
func closeLog(l *runlog.Logger, c *Call) {
	if l == nil {
		return
	}
	if c.Status == StatusInternal || c.Status == StatusTimeout {
		_ = l.Persist() // a log that does not open leaves the call without one
	}
	if c.Err != "" {
		l.Warnf(runlog.TagRun, "%s", c.Err)
	}
	if len(c.Stack) > 0 {
		l.Errorf(runlog.TagRun, "%s", c.Stack)
	}
	l.Infof(runlog.TagRun, "status %s %s after %s", c.Status, c.Code, c.Duration.Round(time.Millisecond))
	_ = l.Close()
}

// refused is a call that did not run, as its result; c gets its status.
func refused(c *Call, err error) *sdk.CallToolResult {
	te := errorOf(err)
	c.Status, c.Code = statuses[te.Code], te.Code
	return &sdk.CallToolResult{
		IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: errorText(te)}},
		StructuredContent: output{Error: te},
	}
}

// outcome is what a call's work returned, with the record it filled and a
// panic a strict server lets go on.
type outcome struct {
	res      sdk.Result
	err      error
	call     Call
	panicked bool
	panic    any
}

// bounded runs a call that holds a slot. Its work runs apart, with the call
// timeout: past it the caller gets call.timeout, and the work keeps the slot
// until it returns. The work fills its own record; the caller's takes it
// when the work answers in time.
func (m middleware) bounded(ctx context.Context, next sdk.MethodHandler, method string, req sdk.Request, c *Call) (sdk.Result, error) {
	work, cancel := context.WithTimeout(ctx, m.lim.timeout)
	done := make(chan outcome, 1)
	left := make(chan struct{})
	o := outcome{call: *c}
	go func() {
		defer m.lim.leave()
		defer cancel()
		func() {
			// Only a strict server's panic gets here: handle recovers the rest.
			defer func() {
				if p := recover(); p != nil {
					o.panicked, o.panic = true, p
				}
			}()
			o.res, o.err = m.handle(work, next, method, req, &o.call)
		}()
		if o.panicked {
			select {
			case <-left:
				// Nobody waits to panic on. Only a strict server, in a test
				// binary, gets here: it crashes the test binary on purpose,
				// so the bug is not lost with the caller that timed out.
				panic(o.panic)
			default:
			}
		}
		done <- o
	}()
	take := func(o outcome) (sdk.Result, error) {
		if o.panicked {
			panic(o.panic)
		}
		*c = o.call
		return o.res, o.err
	}
	select {
	case o := <-done:
		return take(o)
	case <-work.Done():
	}
	select {
	case o := <-done:
		return take(o) // it answered at the deadline
	default:
	}
	close(left)
	return refused(c, work.Err()), nil
}

// handle runs a call's handler with c as its record, recovers a panic into
// call.internal, and audits what the SDK did around the handler.
func (m middleware) handle(ctx context.Context, next sdk.MethodHandler, method string, req sdk.Request, c *Call) (res sdk.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			if m.strict {
				panic(p)
			}
			c.Status, c.Code = StatusInternal, "call.internal"
			// The handler may have filled the record before it failed; the
			// call gave no answer.
			c.Answers, c.Codes, c.Snapshots = nil, nil, nil
			c.Stack = fmt.Appendf(nil, "panic: %v\n\n%s", p, debug.Stack())
			res, err = refused(&Call{}, errInternal), nil
		}
	}()
	res, err = next(context.WithValue(ctx, callKey{}, c), method, req)
	switch r, _ := res.(*sdk.CallToolResult); {
	case err != nil && c.Status == "":
		// The handler did not run: no such tool, or a request the SDK
		// refused.
		c.Status, c.Code, c.Err = StatusUsage, "call.usage", err.Error()
	case err != nil:
		// The handler answered and the SDK refused the answer: output that
		// fails its schema reaches the client as a JSON-RPC error (S3).
		c.Status, c.Code, c.Err = StatusInternal, "call.internal", err.Error()
	case r != nil && r.GetError() != nil:
		// An input the SDK refused before the handler, such as a value
		// outside an enum (S7): handlers never set an error.
		c.Status, c.Code, c.Err = StatusUsage, "call.usage", r.GetError().Error()
	}
	return res, err
}

// errInternal is a recovered panic as an error.
var errInternal = &panicError{value: internalText}
