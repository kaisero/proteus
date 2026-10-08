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
		Path: "/config/shared/post-rulebase/default-security-rules/rules/entry",
		Reason: "the firewall schema does not declare pushed default security rules; " +
			"Panorama keeps them at this path (cms-schema.xml), next to the other pushed post-rules",
		Owner: "internal/resolve",
	},
}

// HandModelled returns the registered hand-modelled nodes.
func HandModelled() []HandModel {
	out := make([]HandModel, len(handModelled))
	copy(out, handModelled)
	return out
}
