package schema

// HandModel records a config node the schema does not describe, so it must be
// modelled by hand. See AGENTS.md R8.
type HandModel struct {
	Path   string // the config xpath
	Reason string // why the schema does not describe it
	Owner  string // the Go package that models it
	// Secret marks a node whose value is never shown, like one the schema marks
	// encrypt="yes" (Node.Encrypted). See IsSecret.
	Secret bool
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
		Path: "/config/shared/pre-rulebase",
		Reason: "the firewall schema does not declare the rules Panorama pushes before the firewall's own; " +
			"they sit here with the shape of a vsys rulebase (PAN-OS documentation, \"Device Group Policies\"), " +
			"and snapshot diff reads them with the schema node of /config/devices/entry/vsys/entry/rulebase",
		Owner: "internal/drift",
	},
	{
		Path: "/config/shared/post-rulebase",
		Reason: "the firewall schema does not declare the rules Panorama pushes after the firewall's own; " +
			"they sit here with the shape of a vsys rulebase (PAN-OS documentation, \"Device Group Policies\"), " +
			"and snapshot diff reads them with the schema node of /config/devices/entry/vsys/entry/rulebase",
		Owner: "internal/drift",
	},
	{
		Path: "/config/predefined/service",
		Reason: "the firewall schema does not describe the device's predefined services; fetch reads " +
			"them with <show><predefined><xpath>/predefined/service</xpath></predefined></show>, and " +
			"each entry has the shape of a configured service (as observed on fw02, PAN-OS 12.2.3, L4)",
		Owner: "internal/resolve",
	},
	// The password hashes of local users and of administrators. Their element
	// is phash in the schema, without encrypt="yes".
	{Path: "/config/shared/local-user-database/user/entry/phash", Reason: phashReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/local-user-database/user/entry/phash", Reason: phashReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/mgt-config/users/entry/phash", Reason: phashReason, Owner: "internal/drift", Secret: true},
}

// secretPaths are the hand-modelled secrets, by schema path.
var secretPaths = func() map[string]bool {
	out := map[string]bool{}
	for _, h := range handModelled {
		if h.Secret {
			out[h.Path] = true
		}
	}
	return out
}()

// IsSecret reports whether a node's value must never be shown: the schema
// marks it encrypt="yes", or it is registered above as a secret.
func IsSecret(n *Node) bool {
	return n != nil && (n.Encrypted || secretPaths[n.Path()])
}

// phashReason is why a phash node is registered as a secret.
const phashReason = "a password hash; the schema does not mark it encrypted"

// HandModelled returns the registered hand-modelled nodes.
func HandModelled() []HandModel {
	out := make([]HandModel, len(handModelled))
	copy(out, handModelled)
	return out
}
