package schema

// HandModel records a config node the schema does not describe, so it must be
// modelled by hand. See AGENTS.md R8.
type HandModel struct {
	Path   string // the config xpath
	Reason string // why the schema does not describe it
	Owner  string // the Go package that models it
}

// handModelled is the complete list. Adding an entry is a deliberate act: every
// other field in the library comes from the schema (R1).
var handModelled = []HandModel{
	{
		Path: "/config/readonly/devices/entry/device-group/entry/parent-dg",
		Reason: "The schema declares /config/readonly as an empty skip-validation " +
			"sequence and describes nothing inside it. parent-dg is the only " +
			"source of the device-group hierarchy, and it survives both " +
			"type=config&action=show and type=export&category=configuration. " +
			"Observed on Panorama 11.2.7-h1.",
		Owner: "resolve",
	},
}

// HandModelled returns the registered hand-modelled nodes.
func HandModelled() []HandModel {
	out := make([]HandModel, len(handModelled))
	copy(out, handModelled)
	return out
}
