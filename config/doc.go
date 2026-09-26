// Package config loads a PAN-OS or Panorama configuration and answers questions
// about it.
//
// The model types in this package are generated from the PAN-OS schema by
// cmd/panos-schemagen. Do not edit them by hand; see AGENTS.md R1 and R6.
//
// Everything here is read-only. A loaded configuration is immutable, and
// resolution is always scoped: shared, a vsys, or a device group together with
// its ancestor chain. A name means different things in different scopes, so
// there is no global lookup. See AGENTS.md R2 and R5.
//
// The design of this package is not settled. See ARCHITECTURE.md.
package config
