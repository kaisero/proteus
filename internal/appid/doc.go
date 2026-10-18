// Package appid owns the App-ID content file: the predefined applications and
// application containers of one content version (spec 2026-10-16 §3).
//
// The package holds the format in both directions. Trim reads a device answer
// as a stream and keeps only the fields of the §3.2 table. Encode writes the
// trimmed applications and containers as one gzip file. Parse and Load read
// that file into a Data, which answers questions about one application at a
// time.
//
// A change to the kept fields increments TrimVersion. The file name carries
// TrimVersion, so a file of an older trim gives a miss and the next fetch
// writes a new one.
//
// The package imports only the standard library and internal/reason
// (AGENTS.md R12). It keeps name lists, not bitmaps: it answers for one
// application at a time and holds no rule or group sets (R11).
package appid
