// Package config loads a PAN-OS or Panorama configuration and reads it two ways.
//
// The generated types in the versioned subpackages give a caller typed access:
// unmarshal a file into a Config and walk the structs. Walk gives resolve and
// index a streaming, schema-driven view of the same file, which is how they read
// it. The digest records its own PAN-OS version, so neither needs a
// version-agnostic interface.
//
// Everything here is read-only, and resolution is always scoped. A name means
// different things in different scopes, so there is no global lookup. See
// AGENTS.md R2 and R5.
package config
