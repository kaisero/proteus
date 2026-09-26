// Package schema parses the PAN-OS schema grammar into a traversable tree.
//
// The grammar uses sequence for containers, array for lists, element for leaves,
// and choice and union for alternatives. Two array shapes matter and must never
// be confused (see AGENTS.md R4):
//
//	<array><sequence name="entry">   an entry-keyed list, each item has a name
//	<array><element name="member">   a list of plain strings
//
// Nodes also carry validate and memberof children, which declare validator names
// and the objects a field may reference.
package schema
