// Package mcp will serve proteus's questions to MCP clients (spec 2026-10-09
// §4). It holds no code yet, only tests: they generate each question's JSON
// schemas from the query layer's types and prove that the MCP Go SDK accepts
// every answer against them (spec §3.6, D4).
//
// R12: only this package imports the MCP Go SDK and jsonschema-go.
package mcp
