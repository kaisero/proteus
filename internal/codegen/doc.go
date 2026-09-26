// Package codegen emits Go source from a parsed PAN-OS schema.
//
// The generator reads list shape, leaf type, defaults and documentation straight
// from the schema. It never guesses and never special-cases a field by name; see
// AGENTS.md R1 and R4.
//
// Generated output is committed to the repository so that a schema change
// appears as a reviewable diff (AGENTS.md R6).
package codegen
