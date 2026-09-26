package codegen

// ReservedUntyped is the escape-hatch field every generated struct carries, as
// AGENTS.md R3 requires.
//
// It is not called Unknown: cms-schema.xml declares a field literally named
// "unknown" in four places, which redeclares the field and breaks the build.
// Schema names are lowercase with dashes, so a name containing an uppercase run
// cannot be produced by a schema field.
const ReservedUntyped = "XMLUntyped"

// goLeafType maps a schema leaf type to a Go type. Pointers preserve the
// difference between absent and empty, which matters when a default applies.
//
// bool maps to *string because PAN-OS writes yes and no, and an absent value is
// distinct from either.
var goLeafType = map[string]string{
	"string":        "*string",
	"multiple":      "*string",
	"ipspec":        "*string",
	"rangelistspec": "*string",
	"iprangespec":   "*string",
	"ipdiscontmask": "*string",
	"bool":          "*string",
	"enum":          "*string",
	"rangedint":     "*int",
	"float":         "*float64",
}

// GoLeafType returns the Go type for a schema leaf type. An unrecognised type
// becomes *string rather than an error: a new PAN-OS release may add one, and a
// string always round-trips.
func GoLeafType(schemaType string) string {
	if g, ok := goLeafType[schemaType]; ok {
		return g
	}
	return "*string"
}
