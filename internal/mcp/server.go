package mcp

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
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
}

// Limits bound what the server does at once and keeps (spec §4.2, §4.7).
type Limits struct {
	// MaxLoads is how many configuration loads and index builds run at once.
	MaxLoads int
	// MaxQueue is how many loads may wait for one of them.
	MaxQueue int
	// MaxCacheMB is the cache's size limit in MB (spec §4.8).
	MaxCacheMB int
}

// DefaultLimits are the limits of spec §4.2.
var DefaultLimits = Limits{MaxLoads: 2, MaxQueue: 16, MaxCacheMB: 2048}

// withDefaults is l with each zero field set to its default.
func (l Limits) withDefaults() Limits {
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
	if o.Env.Inventory == nil || len(o.Env.Inventory.Devices) == 0 {
		return nil, errors.New("mcp: the inventory has no device")
	}
	s := sdk.NewServer(&sdk.Implementation{Name: "proteus", Version: o.Version}, &sdk.ServerOptions{Instructions: instructions})
	lim := o.Limits.withDefaults()
	cache := newCache(int64(lim.MaxCacheMB)<<20, lim.MaxLoads, lim.MaxQueue, strict)
	if err := addTools(s, calls{env: o.Env, cache: cache}, o.Env.Inventory.Names()); err != nil {
		return nil, err
	}
	if err := addResources(s); err != nil {
		return nil, err
	}
	m := middleware{audit: o.Audit, now: o.Now, strict: strict}
	if m.now == nil {
		m.now = time.Now
	}
	s.AddReceivingMiddleware(m.receive)
	return s, nil
}

// Serve answers MCP calls over t until ctx ends or the client goes.
func Serve(ctx context.Context, o Options, t sdk.Transport) error {
	s, err := New(o)
	if err != nil {
		return err
	}
	return s.Run(ctx, t)
}

// Stdio is the transport over standard input and output.
func Stdio() sdk.Transport { return &sdk.StdioTransport{} }

// middleware audits each tool call and recovers a panic (S3, S7, S8).
type middleware struct {
	audit  Auditor
	now    func() time.Time
	strict bool
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
		defer func() {
			if p := recover(); p != nil {
				if m.strict {
					panic(p)
				}
				c.Status, c.Code = StatusInternal, "call.internal"
				// The handler may have filled the record before it failed;
				// the call gave no answer.
				c.Answers, c.Codes, c.Snapshots = nil, nil, nil
				c.Stack = fmt.Appendf(nil, "panic: %v\n\n%s", p, debug.Stack())
				te := newError("call.internal", internalText)
				res, err = &sdk.CallToolResult{
					IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: errorText(te)}},
					StructuredContent: output{Error: te},
				}, nil
			}
			c.Duration = m.now().Sub(c.Time)
			if m.audit != nil {
				m.audit.Audit(*c)
			}
		}()
		res, err = next(context.WithValue(ctx, callKey{}, c), method, req)
		switch r, _ := res.(*sdk.CallToolResult); {
		case err != nil && c.Status == "":
			// The handler did not run: no such tool, or a request the SDK
			// refused.
			c.Status, c.Code, c.Err = StatusUsage, "call.usage", err.Error()
		case err != nil:
			// The handler answered and the SDK refused the answer: output
			// that fails its schema reaches the client as a JSON-RPC error
			// (S3).
			c.Status, c.Code, c.Err = StatusInternal, "call.internal", err.Error()
		case r != nil && r.GetError() != nil:
			// An input the SDK refused before the handler, such as a value
			// outside an enum (S7): handlers never set an error.
			c.Status, c.Code, c.Err = StatusUsage, "call.usage", r.GetError().Error()
		}
		return res, err
	}
}
