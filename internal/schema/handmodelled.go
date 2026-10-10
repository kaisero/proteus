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
		Path: "/config/devices/entry/vsys/entry/rulebase/default-security-rules/rules/entry/action",
		Reason: "the schema declares default allow for both default rules; the built-in action of " +
			"interzone-default is deny (PAN-OS admin guide, \"Default Security Policy Rules\"), " +
			"so an absent action takes the built-in action of its rule name",
		Owner: "internal/simulate/securitypolicy",
	},
	{
		Path: "/config/shared/post-rulebase/default-security-rules/rules/entry",
		Reason: "the firewall schema does not declare pushed default security rules; " +
			"Panorama keeps them at this path (cms-schema.xml), next to the other pushed post-rules",
		Owner: "internal/resolve",
	},
	{
		Path: "/config/devices/entry/vsys/entry/rulebase/security/rules/entry",
		Reason: "the schema says what each child of a security rule holds, not whether the device " +
			"matches a flow on it nor whether the security check evaluates it; the check classifies " +
			"every child, and a candidate that sets a matching field no stage evaluates has a doubt",
		Owner: "internal/simulate/securitypolicy",
	},
	{
		Path: "/config/predefined/service",
		Reason: "the firewall schema does not describe the device's predefined services; fetch reads " +
			"them with <show><predefined><xpath>/predefined/service</xpath></predefined></show>, and " +
			"each entry has the shape of a configured service (as observed on fw02, PAN-OS 12.2.3, L4)",
		Owner: "internal/resolve",
	},
}

// HandModelled returns the registered hand-modelled nodes.
func HandModelled() []HandModel {
	out := make([]HandModel, len(handModelled))
	copy(out, handModelled)
	return out
}
