// Package identity owns the identity file of a snapshot: the User-ID data of
// one firewall (spec 2026-10-17 §3, §4).
//
// The package holds the format in both directions. The parsers read the
// device answers of spec §3.2 (U1–U9, and user-ids match-user for the lab
// tool) in the layouts of fact X1. Assemble joins the parsed parts and the
// domains of the configuration into one File, and Classify gives each group
// its source by its form (§3.3). Encode writes the File as gzip JSON. Read
// and Load read it back into a Data, which is read-only (AGENTS.md R2).
//
// The format changes when a key changes its meaning or goes (§4.1); an added
// key keeps it. TestFormatGuardsTheFields pins the keys of each format.
//
// No error of this package quotes a value of a device answer: a user, a
// group, an address or a tag (§3.5). A *PartError names the part, the entry
// or the line, and a fixed reason.
//
// The package imports only the standard library and internal/reason
// (AGENTS.md R12). It keeps name lists, not bitmaps: it answers for one user
// or group at a time and holds no rule set (R11, spec SG11).
package identity
