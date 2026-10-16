package schema

import (
	"path"
	"strings"
	"sync"
)

// HandModel records a config node the schema does not describe, so it must be
// modelled by hand. See AGENTS.md R8.
type HandModel struct {
	Path   string // the config xpath; for a secret, a * may stand for one segment
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
			"every child, and a candidate that sets a matching field no stage evaluates has a doubt; " +
			"the application is evaluated with the device's App-ID content data, and without a flow " +
			"application or without that data a rule that names one has a doubt (spec 2026-10-16 §4)",
		Owner: "internal/simulate/securitypolicy",
	},
	{
		Path: "/config/shared/pre-rulebase",
		Reason: "the firewall schema does not declare the rules Panorama pushes before the firewall's own; " +
			"they sit here with the shape of a vsys rulebase (PAN-OS documentation, \"Device Group Policies\"), " +
			"and config reads them with the schema node of /config/devices/entry/vsys/entry/rulebase " +
			"(config.ChildNode), for snapshot diff and for the load's count of undescribed elements",
		Owner: "internal/config",
	},
	{
		Path: "/config/shared/post-rulebase",
		Reason: "the firewall schema does not declare the rules Panorama pushes after the firewall's own; " +
			"they sit here with the shape of a vsys rulebase (PAN-OS documentation, \"Device Group Policies\"), " +
			"and config reads them with the schema node of /config/devices/entry/vsys/entry/rulebase " +
			"(config.ChildNode), for snapshot diff and for the load's count of undescribed elements",
		Owner: "internal/config",
	},
	{
		Path: "/config/predefined/service",
		Reason: "the firewall schema does not describe the device's predefined services; fetch reads " +
			"them with <show><predefined><xpath>/predefined/service</xpath></predefined></show>, and " +
			"each entry has the shape of a configured service (as observed on fw02, PAN-OS 12.2.3, L4)",
		Owner: "internal/resolve",
	},
	// The App-ID content data. Fetch reads it with a show command, and the
	// trim of internal/appid keeps the fields of spec 2026-10-16 §3.2.
	{
		Path: "/config/predefined/application",
		Reason: "the digest has no such node; fetch reads the predefined applications with " +
			"<show><predefined><xpath>/predefined/application</xpath></predefined></show> " +
			"(spec 2026-10-16 F1), and appid keeps the fields of the spec's §3.2 table",
		Owner: "internal/appid",
	},
	{
		Path: "/config/predefined/application-container",
		Reason: "the digest has no such node; fetch reads the application containers with " +
			"<show><predefined><xpath>/predefined/application-container</xpath></predefined></show> " +
			"(spec 2026-10-16 F1), and appid keeps the fields of the spec's §3.2 table",
		Owner: "internal/appid",
	},
	{
		Path: "/config/devices/entry/vsys/entry/application-filter/entry",
		Reason: "the schema names the fields of an application filter, not the application fields " +
			"they select; appid.FilterField maps them by hand, as measured on the lab VM, PAN-OS 12.1.9 " +
			"(spec 2026-10-16 S10), and the map covers the shared filters too",
		Owner: "internal/appid",
	},
	// The password hashes of local users and of administrators. Their element
	// is phash in the schema, without encrypt="yes".
	{Path: "/config/shared/local-user-database/user/entry/phash", Reason: phashReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/local-user-database/user/entry/phash", Reason: phashReason, Owner: "internal/drift", Secret: true},
	// No package reads administrators today; IsSecret holds the mark so that a
	// future reader hides the hash too.
	{Path: "/config/mgt-config/users/entry/phash", Reason: phashReason + "; no package reads administrators yet, " +
		"and IsSecret marks it for any that will", Owner: "internal/schema", Secret: true},
	// Credentials the schema keeps in clear text, in shared and in a vsys: an
	// SNMP v2c trap community, a SCEP fixed challenge, the header and parameter
	// values of an HTTP log server profile, which carry API tokens, and the
	// values of an MFA server profile, which carry the vendor's keys. An HTTP
	// profile's URL and payload count too: a receiver can take its token in
	// either. A * stands for one segment: here the log type of an HTTP
	// profile's format.
	{Path: "/config/shared/log-settings/snmptrap/entry/version/v2c/server/entry/community", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/log-settings/snmptrap/entry/version/v2c/server/entry/community", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/shared/scep/entry/scep-challenge/fixed", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/scep/entry/scep-challenge/fixed", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/shared/log-settings/http/entry/format/*/headers/entry/value", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/log-settings/http/entry/format/*/headers/entry/value", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/shared/log-settings/http/entry/format/*/params/entry/value", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/log-settings/http/entry/format/*/params/entry/value", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/shared/log-settings/http/entry/format/*/url-format", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/log-settings/http/entry/format/*/url-format", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/shared/log-settings/http/entry/format/*/payload", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/log-settings/http/entry/format/*/payload", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/shared/server-profile/mfa-server-profile/entry/mfa-config/entry/value", Reason: clearReason, Owner: "internal/drift", Secret: true},
	{Path: "/config/devices/entry/vsys/entry/server-profile/mfa-server-profile/entry/mfa-config/entry/value", Reason: clearReason, Owner: "internal/drift", Secret: true},
}

// secretPaths are the hand-modelled secrets, by schema path, and
// secretNames the last segment of each, so a tree is searched without
// building the path of every node. A path's * stands for one segment
// (path.Match); a last segment is always a name.
var secretPaths, secretNames = func() ([]string, map[string]bool) {
	var paths []string
	names := map[string]bool{}
	for _, h := range handModelled {
		if h.Secret {
			paths = append(paths, h.Path)
			names[h.Path[strings.LastIndex(h.Path, "/")+1:]] = true
		}
	}
	return paths, names
}()

// handSecrets holds, per schema tree (keyed by its root), the nodes the
// hand-modelled secret paths name. It is built once per tree, on first use.
var handSecrets sync.Map // *Node -> map[*Node]bool

// IsSecret reports whether a node's value must never be shown: the schema
// marks it encrypt="yes", or it is registered above as a secret.
func IsSecret(n *Node) bool {
	if n == nil {
		return false
	}
	if n.Encrypted {
		return true
	}
	root := n
	for root.Parent != nil {
		root = root.Parent
	}
	set, ok := handSecrets.Load(root)
	if !ok {
		set, _ = handSecrets.LoadOrStore(root, secretNodes(root))
	}
	return set.(map[*Node]bool)[n]
}

// secretNodes finds the nodes of a tree that the hand-modelled secret paths
// name.
func secretNodes(root *Node) map[*Node]bool {
	out := map[*Node]bool{}
	root.Walk(func(n *Node) {
		if !secretNames[n.Name] {
			return
		}
		p := n.Path()
		for _, pattern := range secretPaths {
			if ok, _ := path.Match(pattern, p); ok {
				out[n] = true
				return
			}
		}
	})
	return out
}

// phashReason is why a phash node is registered as a secret.
const phashReason = "a password hash; the schema does not mark it encrypted"

// clearReason is why a credential the schema keeps in clear text is
// registered as a secret.
const clearReason = "holds a credential in clear text; the schema does not mark it encrypt"

// HandModelled returns the registered hand-modelled nodes.
func HandModelled() []HandModel {
	out := make([]HandModel, len(handModelled))
	copy(out, handModelled)
	return out
}
