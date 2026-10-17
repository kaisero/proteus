package appid

import "slices"

// Kept reports whether the trim keeps a child of an entry. It is unexported so
// that only the tests read the kept fields directly.
var Kept = kept

// KeptFields returns the kept fields of TrimVersion, in table order.
func KeptFields() []string { return slices.Clone(keptFields) }

// FilterOrder returns the filter fields in the order Via lists them.
func FilterOrder() []string {
	out := make([]string, len(filterFields))
	for i, f := range filterFields {
		out[i] = f.filter
	}
	return out
}
