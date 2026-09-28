package fetch

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
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
		for _, cmd := range cmds {
			b, err := c.Op(ctx, cmd)
			if err == nil {
				return b, nil
			}
			var api *APIError
			if !errors.As(err, &api) {
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

// Documents is what every fetch collects, in order. The configuration comes first
// because nothing can be analysed without it.
var Documents = []Document{RunningConfig, SystemInfo, Interfaces, RoutingFIB}

// System is what a snapshot records from show system info.
type System struct {
	Hostname  string `xml:"result>system>hostname"`
	Model     string `xml:"result>system>model"`
	Serial    string `xml:"result>system>serial"`
	SWVersion string `xml:"result>system>sw-version"`
	MultiVsys string `xml:"result>system>multi-vsys"`
}

// ParseSystemInfo reads the response to show system info.
func ParseSystemInfo(b []byte) (System, error) {
	var s System
	if err := xml.Unmarshal(b, &s); err != nil {
		return System{}, fmt.Errorf("system info: %w", err)
	}
	return s, nil
}
