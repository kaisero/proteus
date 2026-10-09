package mcp

import (
	"context"
	"encoding/json"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/okaiser/proteus/internal/query"
	"github.com/okaiser/proteus/internal/reason"
)

// The resources (spec §4.6): the reason registry, each tool's output schema
// per detail, and the limits.
const (
	reasonsURI = "proteus://reasons"
	limitsURI  = "proteus://limits"
)

// schemaURI is a tool's envelope schema in one detail.
func schemaURI(tool, detail string) string { return "proteus://schemas/" + tool + "/" + detail }

// limits sums up docs/limits.md for a model: what an answer cannot know.
const limits = `# What proteus cannot know

- Answers are static analysis of stored snapshots, not live tests. A note says when a snapshot is older than the freshness limit.
- Only PAN-OS 11.2 digests ship; another version reads with the nearest one, and the answer says so.
- Predefined applications, services, regions and PAN-DB URL categories live in content the firewall downloads. A rule that names one stays in doubt, and the answer can be undecided.
- Application, user, HIP, schedule, external dynamic lists and dynamic address groups are not evaluated. The application input is recorded only; it does not change the answer.
- Only the forward path is checked; asymmetric routing is not detected. IPv4 only.
- Policy-based forwarding is named, not followed. ECMP follows the lowest next hop. A path ends where it leaves the inventory.
- Firewalls in virtual wire or Layer 2 mode are not seen on a path; shared gateways are not verified.
- A DIPP port, a dynamic-IP pool address and a dynamic destination are chosen at runtime; NAT64 and NPTv6 are not simulated.
- A host name is resolved with this server's DNS and only its first IPv4 address is checked. A rule matched only through an FQDN object is in doubt (doubt.fqdn-resolution): the firewall resolves it itself.
- Fidelity: exact is what the device does; overmatch may hold more than the device matches; inferred comes from data the device may not use; undermatch may miss matches. Never report inferred or undermatch as a firm answer.
`

// addResources adds the resources to s.
func addResources(s *sdk.Server) error {
	text := func(uri, mime, body string) sdk.ResourceHandler {
		return func(context.Context, *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
			return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: uri, MIMEType: mime, Text: body}}}, nil
		}
	}
	type entry struct {
		Code        reason.Code  `json:"code"`
		Class       reason.Class `json:"class"`
		Description string       `json:"description"`
	}
	var reasons []entry
	for _, e := range reason.Registry() {
		reasons = append(reasons, entry{e.Code, e.Class, e.Description})
	}
	b, err := json.MarshalIndent(reasons, "", "  ")
	if err != nil {
		return err
	}
	s.AddResource(&sdk.Resource{
		URI: reasonsURI, Name: "reasons", MIMEType: "application/json",
		Description: "every reason code an answer can carry: its class and what it means",
	}, text(reasonsURI, "application/json", string(b)))
	for _, sh := range shapes {
		if sh.tool == "" {
			continue
		}
		for _, d := range []string{query.DetailSummary, query.DetailFull} {
			es, err := envelopeSchema(sh, d)
			if err != nil {
				return err
			}
			b, err := json.MarshalIndent(es, "", "  ")
			if err != nil {
				return err
			}
			uri := schemaURI(sh.tool, d)
			s.AddResource(&sdk.Resource{
				URI: uri, Name: sh.tool + "-" + d, MIMEType: "application/schema+json",
				Description: "the JSON schema of " + sh.tool + "'s envelope with detail " + d,
			}, text(uri, "application/schema+json", string(b)))
		}
	}
	s.AddResource(&sdk.Resource{
		URI: limitsURI, Name: "limits", MIMEType: "text/markdown",
		Description: "what proteus does not evaluate, and how to read fidelity",
	}, text(limitsURI, "text/markdown", limits))
	return nil
}
