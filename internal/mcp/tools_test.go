package mcp

import (
	"context"
	"errors"
	"reflect"
	"strconv"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/simulate"
)

// The tools' arguments (spec 2026-10-09 §4.5). Each maps onto a query input.

type policyArgs struct {
	Source      string `json:"source" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked"`
	Destination string `json:"destination" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked"`
	Protocol    string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp or sctp; no default: a rule that needs it is held back and needs names it"`
	Port        int    `json:"port,omitempty" jsonschema:"the destination port"`
	SourcePort  int    `json:"source_port,omitempty" jsonschema:"the source port"`
	URL         string `json:"url,omitempty" jsonschema:"the URL; it decides URL categories"`
	Application string `json:"application,omitempty" jsonschema:"recorded, not evaluated; it does not change the answer"`
	User        string `json:"user,omitempty" jsonschema:"the source user, such as corp\\alice"`
	Device      string `json:"device,omitempty" jsonschema:"the firewall the path starts on; left out, the source places the start"`
	Router      string `json:"router,omitempty" jsonschema:"the start's logical router; needs device"`
	At          string `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; left out, the latest"`
	Detail      string `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return"`
}

type routingArgs struct {
	Source      string `json:"source,omitempty" jsonschema:"an address or a host name; left out, the path starts on device without a source"`
	Destination string `json:"destination" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is traced"`
	Protocol    string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp or sctp; tcp when left out"`
	Port        int    `json:"port,omitempty" jsonschema:"the destination port; it decides NAT and PBF rules that name a service"`
	Device      string `json:"device,omitempty" jsonschema:"the firewall the path starts on"`
	Router      string `json:"router,omitempty" jsonschema:"the start's logical router; needs device"`
	At          string `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; left out, the latest"`
	Detail      string `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return"`
}

type natArgs struct {
	Source      string `json:"source,omitempty" jsonschema:"an address or a host name; left out, any source"`
	Destination string `json:"destination" jsonschema:"an address or a host name; a host name is resolved with DNS and its first IPv4 address is checked"`
	Protocol    string `json:"protocol,omitempty" jsonschema:"tcp, udp, icmp or sctp; tcp when left out"`
	Port        int    `json:"port,omitempty" jsonschema:"the destination port"`
	Device      string `json:"device" jsonschema:"the firewall"`
	Router      string `json:"router,omitempty" jsonschema:"its logical router when it has several"`
	At          string `json:"at,omitempty" jsonschema:"read the newest snapshot at or before this time; left out, the latest"`
	Detail      string `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return"`
}

type searchArgs struct {
	Value  string   `json:"value" jsonschema:"the value or name to search for: an address, a prefix, a port or a name"`
	Kind   string   `json:"kind,omitempty" jsonschema:"an object kind to search; left out, every kind"`
	Device []string `json:"device,omitempty" jsonschema:"the devices to search; left out, every device"`
	Label  []string `json:"label,omitempty" jsonschema:"select devices by label, key=value"`
	Vsys   string   `json:"vsys,omitempty" jsonschema:"the vsys to search; left out, every vsys"`
	At     string   `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; left out, the latest"`
	Detail string   `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return"`
}

type lookupArgs struct {
	Name   string   `json:"name" jsonschema:"the rule or object name"`
	Kind   string   `json:"kind,omitempty" jsonschema:"pick one kind when several share the name: security-rule or an object kind"`
	Device []string `json:"device,omitempty" jsonschema:"the devices to read; left out, every device"`
	Vsys   string   `json:"vsys,omitempty" jsonschema:"the vsys to read; left out, every vsys"`
	At     string   `json:"at,omitempty" jsonschema:"read each device's newest snapshot at or before this time; left out, the latest"`
	Detail string   `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return"`
}

type diffArgs struct {
	Device string `json:"device" jsonschema:"the device to compare"`
	From   string `json:"from,omitempty" jsonschema:"the older point in time; left out, the snapshot before the newer one"`
	To     string `json:"to,omitempty" jsonschema:"the newer point in time; left out, the latest"`
	Detail string `json:"detail,omitempty" jsonschema:"summary or full: how much of each result to return"`
}

// inputSchema is a tool's input schema: the arguments' schema with the
// protocol, detail and port ranges, and the device names as an enum when
// devices is set, as the server adds them at start (spec §3.6).
func inputSchema(args reflect.Type, devices []string) (*jsonschema.Schema, error) {
	s, err := jsonschema.ForType(args, nil)
	if err != nil {
		return nil, err
	}
	enum := func(vs ...string) []any {
		out := make([]any, len(vs))
		for i, v := range vs {
			out[i] = v
		}
		return out
	}
	if p := s.Properties["protocol"]; p != nil {
		p.Enum = enum("tcp", "udp", "icmp", "sctp")
	}
	if p := s.Properties["detail"]; p != nil {
		p.Enum = enum(query.DetailSummary, query.DetailFull)
	}
	for _, key := range []string{"port", "source_port"} {
		if p := s.Properties[key]; p != nil {
			p.Minimum, p.Maximum = jsonschema.Ptr(1.0), jsonschema.Ptr(65535.0)
		}
	}
	if p := s.Properties["device"]; p != nil && devices != nil {
		if p.Items != nil {
			p.Items.Enum = enum(devices...)
		} else {
			p.Enum = enum(devices...)
		}
	}
	return s, nil
}

// toolError is a call that did not answer (spec §4.5).
type toolError struct {
	Code    string       `json:"code"`
	Text    string       `json:"text"`
	Options []string     `json:"options"`
	Needs   []query.Need `json:"needs"`
}

// output is a tool's structured output: the envelope, or an error.
type output struct {
	Envelope any        `json:"envelope"`
	Error    *toolError `json:"error"`
}

// port is a tool's port as the query reads it: "" for none.
func port(protocol string, p int) string {
	switch {
	case p == 0:
		return ""
	case protocol != "":
		return protocol + "/" + strconv.Itoa(p)
	}
	return strconv.Itoa(p)
}

// answer is a query's envelope as a tool's output: its JSON form in the
// detail asked (full when left out), or the error.
func answer[In query.Echoer[E], E, R, S any](e query.Envelope[In, R], err error, detail string, summary func(R) S) output {
	if err != nil {
		return output{Error: errorOf(err)}
	}
	if detail == query.DetailSummary {
		return output{Envelope: query.DocOf(query.Summarize(e, summary))}
	}
	return output{Envelope: query.DocOf(e)}
}

// errorOf is a query error as a tool error. The text and needs of a choice
// are the server's (Task 16); this proof needs only the shape.
func errorOf(err error) *toolError {
	if u, ok := errors.AsType[*query.UsageError](err); ok {
		return &toolError{Code: string(u.Code), Text: u.ToolText, Options: []string{}, Needs: []query.Need{}}
	}
	if c, ok := errors.AsType[*simulate.ChoiceError](err); ok {
		return &toolError{Code: "call.choice", Text: c.Error(), Options: []string{}, Needs: []query.Need{}}
	}
	return &toolError{Code: "call.internal", Text: err.Error(), Options: []string{}, Needs: []query.Need{}}
}

// result is a tool result: IsError with an error.
func result(o output) (*sdk.CallToolResult, output, error) {
	if o.Error != nil {
		return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: o.Error.Text}}}, o, nil
	}
	return nil, o, nil
}

// tools registers each question as a tool on s, answered by the query layer
// over env, with the generated schemas and the inventory's device enum.
func tools(s *sdk.Server, env query.Env, devices []string) error {
	byTool := map[string]shape{}
	for _, sh := range shapes {
		byTool[sh.tool] = sh
	}
	add := func(name string, register func(*sdk.Tool)) error {
		sh := byTool[name]
		in, err := inputSchema(sh.args, devices)
		if err != nil {
			return err
		}
		out, err := outputSchema(sh)
		if err != nil {
			return err
		}
		register(&sdk.Tool{Name: sh.tool, InputSchema: in, OutputSchema: out})
		return nil
	}
	var errs []error
	errs = append(errs, add("simulate_policy", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a policyArgs) (*sdk.CallToolResult, output, error) {
			e, err := query.Policy(ctx, env, query.PolicyInput{
				Flow: query.FlowInput{
					Source: a.Source, Destination: a.Destination, Protocol: a.Protocol, Port: port("", a.Port),
					SourcePort: a.SourcePort, Application: a.Application, User: a.User, URL: a.URL,
				},
				Device: a.Device, Router: a.Router, At: a.At,
			})
			return result(answer(e, err, a.Detail, query.PathResult.Summary))
		})
	}))
	errs = append(errs, add("simulate_routing", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a routingArgs) (*sdk.CallToolResult, output, error) {
			e, err := query.Routing(ctx, env, query.RoutingInput{
				Source: a.Source, Destination: a.Destination, Port: port(a.Protocol, a.Port), Device: a.Device, Router: a.Router, At: a.At,
			})
			return result(answer(e, err, a.Detail, query.RoutingResult.Summary))
		})
	}))
	errs = append(errs, add("simulate_nat", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a natArgs) (*sdk.CallToolResult, output, error) {
			proto := a.Protocol
			if proto == "" {
				proto = "tcp"
			}
			e, err := query.NAT(ctx, env, query.NATInput{
				Flow:   query.FlowInput{Source: a.Source, Destination: a.Destination, Protocol: proto, Port: port("", a.Port)},
				Device: a.Device, Router: a.Router, At: a.At,
			})
			return result(answer(e, err, a.Detail, query.NATResult.Summary))
		})
	}))
	errs = append(errs, add("search", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a searchArgs) (*sdk.CallToolResult, output, error) {
			in := query.SearchInput{Term: a.Value, Selection: query.Selection{Device: a.Device, Label: a.Label, At: a.At}}
			if a.Kind != "" {
				in.Kinds = []string{a.Kind}
			}
			if a.Vsys != "" {
				in.Selection.Vsys = []string{a.Vsys}
			}
			e, err := query.Search(ctx, env, in)
			return result(answer(e, err, a.Detail, query.Finding.Summary))
		})
	}))
	errs = append(errs, add("lookup", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a lookupArgs) (*sdk.CallToolResult, output, error) {
			in := query.LookupInput{Name: a.Name, Kind: a.Kind, Selection: query.Selection{Device: a.Device, At: a.At}}
			if a.Vsys != "" {
				in.Selection.Vsys = []string{a.Vsys}
			}
			e, err := query.Lookup(ctx, env, in)
			return result(answer(e, err, a.Detail, query.LookupResult.Summary))
		})
	}))
	errs = append(errs, add("snapshot_diff", func(t *sdk.Tool) {
		sdk.AddTool(s, t, func(ctx context.Context, _ *sdk.CallToolRequest, a diffArgs) (*sdk.CallToolResult, output, error) {
			e, err := query.SnapshotDiff(ctx, env, query.DiffInput{Selection: query.Selection{Device: []string{a.Device}}, From: a.From, To: a.To})
			return result(answer(e, err, a.Detail, query.DiffResult.Summary))
		})
	}))
	return errors.Join(errs...)
}
