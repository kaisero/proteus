// Package mcp serves proteus's questions to MCP clients (spec 2026-10-09 §4):
// six tools answered by the query layer, with input and output schemas
// generated from its types at start, the device enum from the exported
// inventory, resources and instructions. A receiving middleware audits each
// call and turns a panic into call.internal. Serve runs it over any SDK
// transport; Stdio is the one the command uses without --http.
//
// R12: only this package imports the MCP Go SDK and jsonschema-go. It imports
// testing for testing.Testing() alone: in a test binary a recovered panic goes
// on, so a bug fails the test instead of hiding as call.internal.
package mcp
