// Package reason names every kind of reason an answer carries. A reason is a
// code from a closed registry plus the text a reader sees. The code lets a
// program act on a reason without parsing its text.
//
// The package imports only the standard library, so every package may import it.
package reason

import (
	"fmt"
	"slices"
	"testing"
)

// Code names one kind of reason, as "<class>.<name>" in lower case. The registry
// is closed: a code not in it is a bug.
type Code string

// Class groups codes for a reader.
type Class string

// The classes. A code starts with its class and a dot.
const (
	Doubt   Class = "doubt"   // a rule or stage the answer could not decide
	Gap     Class = "gap"     // data the answer needed and did not have
	Path    Class = "path"    // how a path ended or why it is uncertain
	Zone    Class = "zone"    // how a hop's zones were found
	Default Class = "default" // the default security rules
	DNS     Class = "dns"     // what name resolution adds to an answer
	Input   Class = "input"   // an input a second call can give
	Note    Class = "note"    // a fact the reader should know; not a doubt
	Call    Class = "call"    // why a call failed
	Verdict Class = "verdict" // why a verdict is what it is
)

// Reason is a reason as answers carry it.
type Reason struct {
	Code Code   `json:"code"`
	Text string `json:"text"`
}

// Entry describes a code.
type Entry struct {
	Code        Code
	Class       Class
	Description string
	ToolText    string // the text for MCP when the CLI text names a CLI flag
}

// strict makes New panic on an unregistered code. It is true only in a test
// binary, so a producer that uses a code missing from the registry fails every
// test that reaches it, in every package. A production binary keeps the code.
var strict = testing.Testing()

// New returns a reason with code c and text. In a test binary it panics when c
// is not registered.
func New(c Code, text string) Reason {
	if strict && !Known(c) {
		panic(fmt.Sprintf("reason: code %q is not in the registry", c))
	}
	return Reason{Code: c, Text: text}
}

// Known reports whether c is in the registry.
func Known(c Code) bool {
	_, ok := slices.BinarySearchFunc(registry, c, func(e Entry, c Code) int {
		switch {
		case e.Code < c:
			return -1
		case e.Code > c:
			return 1
		}
		return 0
	})
	return ok
}

// Registry returns every registered code, sorted by code. The caller owns the
// slice.
func Registry() []Entry {
	return slices.Clone(registry)
}
