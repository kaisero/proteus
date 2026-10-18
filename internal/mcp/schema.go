package mcp

import (
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/kaisero/proteus/internal/card"
	"github.com/kaisero/proteus/internal/query"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
	"github.com/kaisero/proteus/internal/simulate/securitypolicy"
)

// The schemas are generated from the query layer's types when the server
// starts, not embedded: a build cannot serve a schema its types do not match,
// and each tool gets its own tree (S2). The checked-in copies in schemas/out
// are the same generator's output; a test keeps them equal.

// shape is one question's JSON: its envelope in full and in summary, and the
// MCP tool that answers it with the arguments it takes. A question no tool
// answers (simulate policy on a file) has no tool.
type shape struct {
	name          string // file name of its schemas
	command       string // the envelope's command
	full, summary reflect.Type
	tool          string
	args          reflect.Type
}

var shapes = []shape{
	{
		"simulate-policy", "simulate policy",
		reflect.TypeFor[query.Doc[query.PathEcho, query.PathResult]](), reflect.TypeFor[query.Doc[query.PathEcho, query.PathSummary]](),
		"simulate_policy", reflect.TypeFor[policyArgs](),
	},
	{
		"simulate-policy-file", "simulate policy",
		reflect.TypeFor[query.Doc[query.FileEcho, query.SecurityResult]](), reflect.TypeFor[query.Doc[query.FileEcho, query.SecuritySummary]](),
		"", nil,
	},
	{
		"simulate-routing", "simulate routing",
		reflect.TypeFor[query.Doc[query.RoutingEcho, query.RoutingResult]](), reflect.TypeFor[query.Doc[query.RoutingEcho, query.RoutingSummary]](),
		"simulate_routing", reflect.TypeFor[routingArgs](),
	},
	{
		"simulate-nat", "simulate nat",
		reflect.TypeFor[query.Doc[query.NATEcho, query.NATResult]](), reflect.TypeFor[query.Doc[query.NATEcho, query.NATSummary]](),
		"simulate_nat", reflect.TypeFor[natArgs](),
	},
	{
		"search", "search",
		reflect.TypeFor[query.Doc[query.SearchEcho, query.Finding]](), reflect.TypeFor[query.Doc[query.SearchEcho, query.FindingSummary]](),
		"search", reflect.TypeFor[searchArgs](),
	},
	{
		"lookup", "lookup",
		reflect.TypeFor[query.Doc[query.LookupEcho, query.LookupResult]](), reflect.TypeFor[query.Doc[query.LookupEcho, query.LookupSummary]](),
		"lookup", reflect.TypeFor[lookupArgs](),
	},
	{
		"snapshot-diff", "snapshot diff",
		reflect.TypeFor[query.Doc[query.DiffEcho, query.DiffResult]](), reflect.TypeFor[query.Doc[query.DiffEcho, query.DiffSummary]](),
		"snapshot_diff", reflect.TypeFor[diffArgs](),
	},
}

// object is a closed object schema: these properties, all required unless
// optional names them.
func object(props map[string]*jsonschema.Schema, optional ...string) *jsonschema.Schema {
	s := &jsonschema.Schema{Type: "object", Properties: props, AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}}}
	for name := range props {
		if !slices.Contains(optional, name) {
			s.Required = append(s.Required, name)
		}
	}
	slices.Sort(s.Required)
	return s
}

func str(description string) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string", Description: description}
}

// reasonSchema is a reason: {code, text}.
func reasonSchema() *jsonschema.Schema {
	return object(map[string]*jsonschema.Schema{"code": str("the reason code"), "text": str("the reason in words")})
}

// typeSchemas are the schemas of the types that write their own JSON, which
// jsonschema-go cannot infer (spec §3.6). Each call builds a new tree; For
// clones each use, so no schema pointer is shared (S2).
func typeSchemas() (map[reflect.Type]*jsonschema.Schema, error) {
	levels := []any{"exact", "overmatch", "inferred", "undermatch", "undeclared"}
	out := map[reflect.Type]*jsonschema.Schema{
		reflect.TypeFor[netip.Addr]():   str("an IP address"),
		reflect.TypeFor[netip.Prefix](): str("an IP prefix, address/length"),
		reflect.TypeFor[time.Time]():    {Type: "string", Format: "date-time"},
		// simulate.Fidelity.MarshalJSON.
		reflect.TypeFor[simulate.Fidelity](): object(map[string]*jsonschema.Schema{
			"level": {
				Type: "string", Enum: levels,
				Description: "exact, overmatch (may hold more than the device matches), inferred (from data the device may not use) or undermatch (may miss matches)",
			},
			"reasons":       {Type: "array", Items: reasonSchema(), Description: "why the result is weaker than exact"},
			"not_evaluated": {Type: "array", Items: str(""), Description: "the dimensions not evaluated"},
		}, "reasons", "not_evaluated"),
		// securitypolicy.Relevance.MarshalJSON.
		reflect.TypeFor[securitypolicy.Relevance](): object(map[string]*jsonschema.Schema{
			"known":    {Type: "boolean", Description: "whether relevance could be read: the snapshot has a forwarding table"},
			"relevant": {Type: "boolean", Description: "whether the device routes either endpoint by more than a default route"},
			"code":     str("the reason code"),
			"text":     str("the reason in words"),
		}),
	}
	// encoding/json writes a nil map as null; jsonschema-go allows only an
	// object. A rule's fields and profiles are such maps.
	out[reflect.TypeFor[map[string][]string]()] = &jsonschema.Schema{
		Types: []string{"null", "object"}, AdditionalProperties: &jsonschema.Schema{Types: []string{"null", "array"}, Items: str("")},
	}
	// Recursive types: a card's nested group members and a NAT rule's
	// fallback translation. jsonschema-go refuses a cycle, and a $ref would
	// leave the tree (S2), so each is unrolled.
	for _, r := range []struct {
		t     reflect.Type
		depth int
	}{{reflect.TypeFor[card.Item](), 8}, {reflect.TypeFor[resolve.SourceTranslation](), 2}} {
		s, err := unrolled(r.t, r.depth, out)
		if err != nil {
			return nil, err
		}
		out[r.t] = s
	}
	// query.Checks.MarshalJSON writes each check's Security under its name.
	sec, err := jsonschema.ForType(reflect.TypeFor[query.Security](), &jsonschema.ForOptions{TypeSchemas: out})
	if err != nil {
		return nil, err
	}
	out[reflect.TypeFor[query.Checks]()] = &jsonschema.Schema{
		Type: "object", AdditionalProperties: sec, Description: "each check's answer under its name, such as security",
	}
	return out, nil
}

// anyTypes marks the terminal of an unrolled type while it is built: every
// JSON type, null included, so the generator keeps it as it is for a pointer.
var anyTypes = []string{"null", "boolean", "object", "array", "number", "string"}

// permissive replaces every terminal under s with the empty schema, true.
func permissive(s *jsonschema.Schema) {
	swap := func(c *jsonschema.Schema) *jsonschema.Schema {
		if slices.Equal(c.Types, anyTypes) {
			return &jsonschema.Schema{}
		}
		permissive(c)
		return c
	}
	v := reflect.ValueOf(s).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		switch f.Type() {
		case schemaPtr:
			if c := f.Interface().(*jsonschema.Schema); c != nil {
				f.Set(reflect.ValueOf(swap(c)))
			}
		case schemaSlice:
			for j, c := range f.Interface().([]*jsonschema.Schema) {
				f.Index(j).Set(reflect.ValueOf(swap(c)))
			}
		case schemaMap:
			m := f.Interface().(map[string]*jsonschema.Schema)
			for k, c := range m {
				m[k] = swap(c)
			}
		}
	}
}

// unrolled is a recursive struct type's schema, its recursion cut after depth
// levels: below them a value may be anything (true), so a deeper nesting
// still validates. The schema is built from a copy of the struct, so the
// override of t applies to its fields only.
func unrolled(t reflect.Type, depth int, base map[reflect.Type]*jsonschema.Schema) (*jsonschema.Schema, error) {
	fields := make([]reflect.StructField, t.NumField())
	for i := range fields {
		fields[i] = t.Field(i)
	}
	shell := reflect.StructOf(fields)
	m := maps.Clone(base)
	m[t] = &jsonschema.Schema{Types: anyTypes}
	for range depth {
		s, err := jsonschema.ForType(shell, &jsonschema.ForOptions{TypeSchemas: m})
		if err != nil {
			return nil, err
		}
		m[t] = s
	}
	permissive(m[t])
	return m[t], nil
}

// envelopeSchema is one envelope's schema: detail, format and command are
// constants, so a summary and a full envelope never both match (S1).
func envelopeSchema(sh shape, detail string) (*jsonschema.Schema, error) {
	ts, err := typeSchemas()
	if err != nil {
		return nil, err
	}
	t := sh.full
	if detail == query.DetailSummary {
		t = sh.summary
	}
	s, err := jsonschema.ForType(t, &jsonschema.ForOptions{TypeSchemas: ts})
	if err != nil {
		return nil, err
	}
	for key, v := range map[string]any{"detail": detail, "format": float64(query.FormatVersion), "command": sh.command} {
		c := v
		s.Properties[key].Const = &c
	}
	s.Description = fmt.Sprintf("the %s answer, detail %s", sh.command, detail)
	return s, nil
}

// errorSchema is a tool error, or null when the call answered.
func errorSchema() (*jsonschema.Schema, error) {
	need, err := jsonschema.For[query.Need](nil)
	if err != nil {
		return nil, err
	}
	s := object(map[string]*jsonschema.Schema{
		"code":    str("call.usage, call.choice, call.busy, call.timeout or call.internal"),
		"text":    str("what went wrong, and what to change"),
		"options": {Type: "array", Items: str(""), Description: "on call.choice: the values to pick from"},
		"needs":   {Type: "array", Items: need, Description: "on call.choice: the input to give with one of the options"},
	})
	s.Type, s.Types = "", []string{"null", "object"}
	s.Description = "null when the call answered; else why it did not"
	return s, nil
}

// outputSchema is a tool's output: {envelope, error}. The envelope is the
// summary or the full answer, each with its detail constant, or null with an
// error (S1). The root is an object.
func outputSchema(sh shape) (*jsonschema.Schema, error) {
	sum, err := envelopeSchema(sh, query.DetailSummary)
	if err != nil {
		return nil, err
	}
	full, err := envelopeSchema(sh, query.DetailFull)
	if err != nil {
		return nil, err
	}
	env := &jsonschema.Schema{
		OneOf:       []*jsonschema.Schema{sum, full, {Type: "null"}},
		Description: "the answer as the command line prints it with --output json; null with an error",
	}
	errs, err := errorSchema()
	if err != nil {
		return nil, err
	}
	return object(map[string]*jsonschema.Schema{"envelope": env, "error": errs}), nil
}

var (
	schemaPtr   = reflect.TypeFor[*jsonschema.Schema]()
	schemaSlice = reflect.TypeFor[[]*jsonschema.Schema]()
	schemaMap   = reflect.TypeFor[map[string]*jsonschema.Schema]()
)

// protocolPattern is simulate_policy's protocol: a name, or an IP protocol
// number from 0 to 255.
const protocolPattern = `^(tcp|udp|icmp|sctp|[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$`

// inputSchema is a tool's input schema: the arguments' schema with the
// protocol, detail, port and limit ranges, and the device names as an enum when
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
		if args == reflect.TypeFor[policyArgs]() {
			// simulate_policy also takes an IP protocol number, so an
			// application identified by its IP protocol, such as ospf on
			// 89, can be asked (spec 2026-10-16 §7, P4).
			p.Pattern = protocolPattern
		} else {
			p.Enum = enum("tcp", "udp", "icmp", "sctp")
		}
	}
	if p := s.Properties["detail"]; p != nil {
		p.Enum = enum(query.DetailSummary, query.DetailFull)
	}
	for _, key := range []string{"port", "source_port"} {
		if p := s.Properties[key]; p != nil {
			p.Minimum, p.Maximum = jsonschema.Ptr(1.0), jsonschema.Ptr(65535.0)
		}
	}
	if p := s.Properties["limit"]; p != nil {
		p.Minimum = jsonschema.Ptr(1.0)
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
