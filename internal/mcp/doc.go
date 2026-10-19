// Package mcp serves proteus's questions to MCP clients (spec 2026-10-09 §4):
// six tools answered by the query layer, with input and output schemas
// generated from its types at start, the device enum from the exported
// inventory, resources and instructions. A receiving middleware audits each
// call and turns a panic into call.internal. A cache keeps each snapshot's
// configuration, indexes, operational tables and identity data for every
// call, and bounds the loads that fill it (§4.7, §4.8). A limiter bounds the
// calls that run and wait, and answers call.busy and call.timeout. Serve runs
// it over any SDK transport; Streams, over standard input and output, is the
// one the command uses without --http. ServeHTTP runs it over Streamable HTTP
// behind a Host check and a bearer token (§4.4). AuditLog writes the audit
// lines (§4.9).
//
// R12: only this package imports the MCP Go SDK, jsonschema-go and x/sync.
// It imports testing for testing.Testing() alone: in a test binary a
// recovered panic goes on, so a bug fails the test instead of hiding as
// call.internal.
package mcp
