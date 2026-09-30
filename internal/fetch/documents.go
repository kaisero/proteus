package fetch

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/okaiser/proteus/internal/runlog"
)

// A Document is one thing fetched from a device and stored as <Name>.xml.
//
// Adding a fetcher is adding a Document and listing it in Documents. The run, the
// store and the snapshot metadata take it from there; nothing else changes.
type Document struct {
	Name  string
	Fetch func(ctx context.Context, c *Client) ([]byte, error)
}

// OpDocument is a document read by show commands. The first command the device
// accepts wins, so a command that changed between releases lists its fallbacks. A
// transport failure stops the attempt: a device that is not answering will not
// answer the fallback either.
func OpDocument(name string, cmds ...string) Document {
	return Document{Name: name, Fetch: func(ctx context.Context, c *Client) ([]byte, error) {
		var errs []error
		for i, cmd := range cmds {
			b, err := c.Op(ctx, cmd)
			if err == nil {
				if i > 0 {
					c.log.Infof(runlog.TagAPI, "%s: %s: fell back to %s", c.name, name, cmd)
				}
				return b, nil
			}
			if _, ok := errors.AsType[*APIError](err); !ok {
				return nil, err
			}
			errs = append(errs, fmt.Errorf("%s: %w", cmd, err))
		}
		return nil, errors.Join(errs...)
	}}
}

// The documents every fetch collects.
var (
	// RunningConfig is the running configuration, exported.
	RunningConfig = Document{Name: "config", Fetch: func(ctx context.Context, c *Client) ([]byte, error) {
		return c.ExportConfig(ctx)
	}}

	// SystemInfo carries the serial and the software version.
	SystemInfo = OpDocument("system-info", "<show><system><info/></system></show>")

	// Interfaces is every interface with its zone, router and addresses.
	Interfaces = OpDocument("interfaces", "<show><interface>all</interface></show>")

	// RoutingFIB is the forwarding table. A firewall without Advanced Routing
	// refuses the first command, and the legacy one answers. Both declare the same
	// handler in the appliance's own opschema.xml, so the output shape is identical
	// and one parser reads both. afi=both asks for IPv6 routes too.
	RoutingFIB = OpDocument("fib",
		"<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>",
		"<show><routing><fib/></routing></show>")
)

// The routing and HA documents.
var (
	// RoutingRIB is the routing table, installed or not. Advanced Routing answers
	// with FRR JSON (verified on fw02, PAN-OS 12.2.2). On an Advanced Routing
	// device the legacy command reports success with a deprecation text, so the
	// Advanced Routing command must come first; the legacy one answers only where
	// the first is refused.
	RoutingRIB = OpDocument("rib", RoutingRIBCmd, "<show><routing><route/></routing></show>")

	// HAState is the device's high-availability state and its peer's.
	HAState = OpDocument("ha", haStateCmd)
)

// RoutingRIBCmd is the Advanced Routing form of the routing table command.
const RoutingRIBCmd = "<show><advanced-routing><route><afi>ipv4</afi></route></advanced-routing></show>"

const haStateCmd = "<show><high-availability><state/></high-availability></show>"

// Documents is what every fetch collects, in order. The configuration comes first
// because nothing can be analysed without it.
var Documents = []Document{RunningConfig, SystemInfo, Interfaces, RoutingFIB, RoutingRIB, HAState}

// System is what a snapshot records from show system info.
type System struct {
	Hostname  string `xml:"result>system>hostname" json:"hostname,omitempty"`
	Model     string `xml:"result>system>model" json:"model,omitempty"`
	Serial    string `xml:"result>system>serial" json:"serial,omitempty"`
	SWVersion string `xml:"result>system>sw-version" json:"sw_version,omitempty"`
	MultiVsys string `xml:"result>system>multi-vsys" json:"multi_vsys,omitempty"`
}

// ParseSystemInfo reads the response to show system info.
func ParseSystemInfo(b []byte) (System, error) {
	var s System
	if err := xml.Unmarshal(b, &s); err != nil {
		return System{}, fmt.Errorf("system info: %w", err)
	}
	return s, nil
}
