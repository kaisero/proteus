// Package index builds scope-keyed lookup structures over a loaded
// configuration: address containment, group closure, reference edges and
// rule-field bitmaps.
//
// Every index belongs to one scope. A name means different things in different
// scopes, so a global index merges sibling device groups and returns answers that
// are wrong rather than incomplete. See AGENTS.md R5 and R10.
package index

// Interner maps names to dense uint32 ids, so every index works in integers.
type Interner struct {
	ids   map[string]uint32
	names []string
}

// NewInterner returns an empty interner.
func NewInterner() *Interner {
	return &Interner{ids: map[string]uint32{}}
}

// ID returns the id of a name, assigning one if it is new.
func (in *Interner) ID(name string) uint32 {
	if id, ok := in.ids[name]; ok {
		return id
	}
	// G115: the count cannot reach 2^32. Every interned name is an object name
	// read from a configuration file, and PAN-OS caps a name at 63 characters, so
	// four billion of them would be a file of hundreds of gigabytes. The largest
	// synthetic configuration measured for this project held 75,000.
	//nolint:gosec // see above
	id := uint32(len(in.names))
	in.ids[name] = id
	in.names = append(in.names, name)
	return id
}

// Lookup returns the id of a name without assigning one.
func (in *Interner) Lookup(name string) (uint32, bool) {
	id, ok := in.ids[name]
	return id, ok
}

// Name returns the name an id stands for, or the empty string.
func (in *Interner) Name(id uint32) string {
	if int(id) >= len(in.names) {
		return ""
	}
	return in.names[id]
}

// Len returns how many names are interned.
func (in *Interner) Len() int { return len(in.names) }
