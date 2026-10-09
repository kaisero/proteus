package mcp

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/simulate"
)

// The tools' arguments (spec 2026-10-09 §4.5). Each maps onto a query input.
// Each description says what proteus evaluates.

type policyArgs struct {
	Source      string `json:"source" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked"`
	Destination string `json:"destination" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked"`
	Protocol    string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp or sctp; no default: a rule that needs it is held back and needs names it"`
	Port        int    `json:"port,omitempty" jsonschema:"the destination port, a number; the protocol goes in protocol"`
	SourcePort  int    `json:"source_port,omitempty" jsonschema:"the source port, a number"`
	URL         string `json:"url,omitempty" jsonschema:"the URL; it decides the rules that name a URL category the configuration defines"`
	Application string `json:"application,omitempty" jsonschema:"recorded, not evaluated; it does not change the answer"`
	User        string `json:"user,omitempty" jsonschema:"the source user, such as corp\\alice; it decides the rules that name a user or a group of the user snapshot"`
	Device      string `json:"device,omitempty" jsonschema:"the firewall the path starts on; left out, the source places the start"`
	Router      string `json:"router,omitempty" jsonschema:"the start's logical router; needs device"`
	At          string `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; left out, the latest"`
	Detail      string `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return; summary when left out"`
}

type routingArgs struct {
	Source      string `json:"source,omitempty" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked; left out, the path starts on device without a source"`
	Destination string `json:"destination" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is traced"`
	Protocol    string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp or sctp; tcp when left out"`
	Port        int    `json:"port,omitempty" jsonschema:"the destination port, a number; it decides NAT and PBF rules that name a service"`
	Device      string `json:"device,omitempty" jsonschema:"the firewall the path starts on"`
	Router      string `json:"router,omitempty" jsonschema:"the start's logical router; needs device"`
	At          string `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; left out, the latest"`
	Detail      string `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return; summary when left out"`
}

type natArgs struct {
	Source      string `json:"source,omitempty" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked; left out, any source"`
	Destination string `json:"destination" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked"`
	Protocol    string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp or sctp; tcp when left out"`
	Port        int    `json:"port,omitempty" jsonschema:"the destination port, a number"`
	Device      string `json:"device" jsonschema:"the firewall"`
	Router      string `json:"router,omitempty" jsonschema:"its logical router when it has several"`
	At          string `json:"at,omitempty" jsonschema:"read the newest snapshot at or before this time; left out, the latest"`
	Detail      string `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return; summary when left out"`
}

type searchArgs struct {
	Value  string   `json:"value" jsonschema:"the value or name to search for: an address, a prefix, a port or a name"`
	Kind   string   `json:"kind,omitempty" jsonschema:"an object kind to search; left out, every kind"`
	Device []string `json:"device,omitempty" jsonschema:"the devices to search; left out, every device"`
	Label  []string `json:"label,omitempty" jsonschema:"select devices by label, key=value"`
	Vsys   string   `json:"vsys,omitempty" jsonschema:"the vsys to search; left out, every vsys"`
	At     string   `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; left out, the latest"`
	Detail string   `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return; summary when left out"`
}

type lookupArgs struct {
	Name   string   `json:"name" jsonschema:"the rule or object name"`
	Kind   string   `json:"kind,omitempty" jsonschema:"pick one kind when several share the name: security-rule or an object kind"`
	Device []string `json:"device,omitempty" jsonschema:"the devices to read; left out, every device"`
	Vsys   string   `json:"vsys,omitempty" jsonschema:"the vsys to read; left out, every vsys"`
	At     string   `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; left out, the latest"`
	Detail string   `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return; summary when left out"`
}

type diffArgs struct {
	Device string `json:"device" jsonschema:"the device to compare"`
	From   string `json:"from,omitempty" jsonschema:"the older point in time; left out, the snapshot before the newer one"`
	To     string `json:"to,omitempty" jsonschema:"the newer point in time; left out, the latest"`
	Detail string `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return; summary when left out"`
}

// toolError is a call that did not answer (spec §4.5).
type toolError struct {
	Code    reason.Code  `json:"code"`
	Text    string       `json:"text"`
	Options []string     `json:"options"`
	Needs   []query.Need `json:"needs"`
}

// output is a tool's structured output: the envelope, or an error.
type output struct {
	Envelope any        `json:"envelope"`
	Error    *toolError `json:"error"`
}

// port is a tool's port as the query reads it: "" for none. The protocol
// travels apart from it.
func port(p int) string {
	if p == 0 {
		return ""
	}
	return strconv.Itoa(p)
}

// newError is a tool error with empty lists, as the schema wants them.
func newError(code reason.Code, text string) *toolError {
	return &toolError{Code: code, Text: text, Options: []string{}, Needs: []query.Need{}}
}

// choiceNeeds names the input a choice's options fill (C5).
var choiceNeeds = map[string]query.Need{
	simulate.ChoiceDevice: {Code: "input.device", Input: "device", Text: "give device: one of the options"},
	simulate.ChoiceRouter: {Code: "input.router", Input: "router", Text: "give router: one of the options"},
}

// errorOf is a query error as a tool error, in the tool's words: an input
// that is not a valid question is call.usage, a choice only the user can make
// call.choice with its options and the input they fill, a call past its time
// call.timeout, and anything else call.internal.
func errorOf(err error) *toolError {
	if u, ok := errors.AsType[*query.UsageError](err); ok {
		return newError("call.usage", cmp.Or(u.ToolText, u.Text))
	}
	if c, ok := errors.AsType[*simulate.ChoiceError](err); ok {
		need, choice := choiceNeeds[c.Kind]
		if !choice {
			// No choice to offer: the question cannot be taken (C5).
			return newError("call.usage", cmp.Or(c.ToolText, c.Question))
		}
		if c.Starts != nil {
			return tieError(c)
		}
		e := newError("call.choice", cmp.Or(c.ToolText, c.Question))
		e.Options = append(e.Options, c.Options...)
		e.Needs = append(e.Needs, need)
		return e
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError("call.timeout", "the call ran longer than its time limit")
	}
	if errors.Is(err, context.Canceled) {
		// The client cancelled the call, or the server stops: no answer
		// came in time, as at the time limit.
		return newError("call.timeout", "the call was cancelled before it answered")
	}
	return newError("call.internal", err.Error())
}

// tieError is a tie of placement in the tool's inputs. Its options name a
// device and an interface, which the device input does not take: the options
// become the devices, and the text keeps the interfaces. Starts on one device
// are a choice of router when their routers differ; else no input picks one.
func tieError(c *simulate.ChoiceError) *toolError {
	var devices, routers []string
	for _, p := range c.Starts {
		if !slices.Contains(devices, p.Device) {
			devices = append(devices, p.Device)
		}
		if !slices.Contains(routers, p.Router) {
			routers = append(routers, p.Router)
		}
	}
	starts := " (starts: " + strings.Join(c.Options, ", ") + ")"
	switch {
	case len(devices) > 1:
		e := newError("call.choice", cmp.Or(c.ToolText, c.Question)+starts)
		e.Options = devices
		e.Needs = append(e.Needs, choiceNeeds[simulate.ChoiceDevice])
		return e
	case len(routers) > 1:
		e := newError("call.choice", fmt.Sprintf("the source could enter %s through several routers; name device %s and one router%s", devices[0], devices[0], starts))
		e.Options = routers
		e.Needs = append(e.Needs, query.Need{Code: "input.router", Input: "router", Text: fmt.Sprintf("give device %s and router: one of the options", devices[0])})
		return e
	}
	return newError("call.usage", fmt.Sprintf("the source could enter %s at several interfaces of one router, and no input picks one%s; give a source address that only one of them reaches", devices[0], starts))
}

// statuses maps an error code to its audit status (spec §4.9).
var statuses = map[reason.Code]string{
	"call.usage": StatusUsage, "call.choice": StatusChoice, "call.busy": StatusBusy,
	"call.timeout": StatusTimeout, "call.internal": StatusInternal,
}

// answer is a query's answer as a tool's result: its envelope in the detail
// asked (summary when left out) or its error, with the text content, and the
// call's audit record filled. An error sets IsError; the handler never
// returns a Go error, so the SDK keeps the structure (S7).
func answer[In query.Echoer[E], E, R, S any](ctx context.Context, e query.Envelope[In, R], err error, detail string, summary func(R) S) (*sdk.CallToolResult, output, error) {
	c := callOf(ctx)
	if err != nil {
		te := errorOf(err)
		c.set(func(c *Call) { c.Status, c.Code = statuses[te.Code], te.Code })
		return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: errorText(te)}}}, output{Error: te}, nil
	}
	var doc any
	if cmp.Or(detail, query.DetailSummary) == query.DetailSummary {
		doc = query.DocOf(query.Summarize(e, summary))
	} else {
		doc = query.DocOf(e)
	}
	v := viewOf(doc)
	c.set(func(c *Call) {
		c.Status = StatusOK
		c.Answers = v.answers()
		c.Codes = v.codes()
		for _, t := range e.Targets {
			if t.Snapshot != nil {
				c.Snapshots = append(c.Snapshots, t.Device+"@"+t.Snapshot.ID)
			}
		}
	})
	return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: v.text()}}}, output{Envelope: doc}, nil
}

// addTools registers each question as a tool on s, answered by the query
// layer over env, with the generated schemas and devices as the device enum.
func addTools(s *sdk.Server, env query.Env, devices []string) error {
	var errs []error
	add := func(name string, register func(*sdk.Tool)) {
		t, err := toolOf(name, devices)
		if err != nil {
			errs = append(errs, err)
			return
		}
		register(t)
	}
	add("simulate_policy", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a policyArgs) (*sdk.CallToolResult, output, error) {
			e, err := query.Policy(ctx, env, query.PolicyInput{
				Flow: query.FlowInput{
					Source: a.Source, Destination: a.Destination, Protocol: a.Protocol, Port: port(a.Port),
					SourcePort: a.SourcePort, Application: a.Application, User: a.User, URL: a.URL,
				},
				Device: a.Device, Router: a.Router, At: a.At,
			})
			return answer(ctx, e, err, a.Detail, query.PathResult.Summary)
		})
	})
	add("simulate_routing", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a routingArgs) (*sdk.CallToolResult, output, error) {
			e, err := query.Routing(ctx, env, query.RoutingInput{
				Source: a.Source, Destination: a.Destination, Protocol: a.Protocol, Port: port(a.Port),
				Device: a.Device, Router: a.Router, At: a.At,
			})
			return answer(ctx, e, err, a.Detail, query.RoutingResult.Summary)
		})
	})
	add("simulate_nat", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a natArgs) (*sdk.CallToolResult, output, error) {
			// tcp when left out, as on the command line (spec §4.5).
			e, err := query.NAT(ctx, env, query.NATInput{
				Flow:   query.FlowInput{Source: a.Source, Destination: a.Destination, Protocol: cmp.Or(a.Protocol, "tcp"), Port: port(a.Port)},
				Device: a.Device, Router: a.Router, At: a.At,
			})
			return answer(ctx, e, err, a.Detail, query.NATResult.Summary)
		})
	})
	add("search", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a searchArgs) (*sdk.CallToolResult, output, error) {
			in := query.SearchInput{Term: a.Value, Selection: query.Selection{Device: a.Device, Label: a.Label, At: a.At}}
			if a.Kind != "" {
				in.Kinds = []string{a.Kind}
			}
			if a.Vsys != "" {
				in.Selection.Vsys = []string{a.Vsys}
			}
			e, err := query.Search(ctx, env, in)
			return answer(ctx, e, err, a.Detail, query.Finding.Summary)
		})
	})
	add("lookup", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a lookupArgs) (*sdk.CallToolResult, output, error) {
			in := query.LookupInput{Name: a.Name, Kind: a.Kind, Selection: query.Selection{Device: a.Device, At: a.At}}
			if a.Vsys != "" {
				in.Selection.Vsys = []string{a.Vsys}
			}
			e, err := query.Lookup(ctx, env, in)
			return answer(ctx, e, err, a.Detail, query.LookupResult.Summary)
		})
	})
	add("snapshot_diff", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a diffArgs) (*sdk.CallToolResult, output, error) {
			e, err := query.SnapshotDiff(ctx, env, query.DiffInput{Selection: query.Selection{Device: []string{a.Device}}, From: a.From, To: a.To})
			return answer(ctx, e, err, a.Detail, query.DiffResult.Summary)
		})
	})
	return errors.Join(errs...)
}

// toolOf is a tool's definition: its name, a description, and the generated
// input and output schemas, the input's device enum from devices.
func toolOf(name string, devices []string) (*sdk.Tool, error) {
	sh, ok := shapeByTool(name)
	if !ok {
		return nil, errors.New("mcp: no shape for tool " + name)
	}
	in, err := inputSchema(sh.args, devices)
	if err != nil {
		return nil, err
	}
	out, err := outputSchema(sh)
	if err != nil {
		return nil, err
	}
	return &sdk.Tool{Name: sh.tool, Description: toolDescriptions[sh.tool], InputSchema: in, OutputSchema: out}, nil
}

// shapeByTool is the shape a tool answers.
func shapeByTool(tool string) (shape, bool) {
	for _, sh := range shapes {
		if sh.tool == tool && tool != "" {
			return sh, true
		}
	}
	return shape{}, false
}

// toolDescriptions say what each tool answers, from stored snapshots.
var toolDescriptions = map[string]string{
	"simulate_policy":  "Simulate a flow along its path through the firewalls of the stored snapshots: the security rule each firewall matches, with routing and NAT on each hop. The answer is static analysis, not a live test.",
	"simulate_routing": "Trace the path a packet takes across the firewalls of the stored snapshots: each hop's route, NAT and policy-based forwarding.",
	"simulate_nat":     "Simulate NAT on one firewall: the NAT rule a packet matches and its translation.",
	"search":           "Search the stored configurations for an address, a prefix, a port or a name: the objects and rules that hold it.",
	"lookup":           "Show a rule or an object by name as the stored configurations define it, with its resolved members.",
	"snapshot_diff":    "Compare two snapshots of one device: the rules and objects added, removed and changed.",
}
