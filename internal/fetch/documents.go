package fetch

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/runlog"
)

// A Document is one thing fetched from a device and stored as <Name>.xml.
//
// Adding a fetcher is adding a Document and listing it in Documents. The run, the
// store and the snapshot metadata take it from there; nothing else changes.
type Document struct {
	Name  string
	Fetch func(ctx context.Context, c *Client) ([]byte, error)
	// Optional is set for a document a device may refuse, such as one an older
	// release does not know; nil makes the document required.
	Optional *Optional
	// Fallback runs when the device refuses Fetch: an *APIError, or an answer
	// without the document (errNoConfig). A transport failure takes no
	// fallback: a device that is not answering will not answer it either.
	Fallback *Fallback
}

// Fallback is a second way to read a document, and the note that says the
// snapshot holds what it read.
type Fallback struct {
	Fetch func(ctx context.Context, c *Client) ([]byte, error)
	Note  reason.Reason
}

// Optional says what a device's refusal of an optional document means.
//
// A refusal, or an answer that fails Check, adds the Refused note: nothing is
// stored and no outcome is recorded, so it is not a failed document. A transport
// failure still is.
type Optional struct {
	Refused reason.Reason
	// Check tests an answer the device accepted; nil accepts every answer. An
	// answer that fails it is not stored, so a reader never meets it.
	Check func([]byte) error
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
	// RunningConfig is the running configuration, from show config running: it
	// holds no uncommitted change, while the export holds the candidate (as
	// observed on fw01, PAN-OS 11.2.5, spec 2026-10-17 C12). The config element
	// of the answer is the document, byte for byte (PD2). A device that refuses
	// the command, or answers without the element, is exported instead, with a
	// note (PD1).
	RunningConfig = Document{
		Name: "config",
		Fetch: func(ctx context.Context, c *Client) ([]byte, error) {
			b, err := c.Op(ctx, runningConfigCmd)
			if err != nil {
				return nil, err
			}
			return unwrapConfig(b)
		},
		Fallback: &Fallback{
			Fetch: func(ctx context.Context, c *Client) ([]byte, error) { return c.ExportConfig(ctx) },
			Note:  configNotRunning,
		},
	}

	// PushedTemplate is the template that Panorama pushed to the device, which
	// the configuration does not hold (as observed on fw01, PAN-OS 11.2.5, spec
	// 2026-10-17 C1, C9). The template step merges it into the configuration
	// and keeps its config element as the document. A device that Panorama
	// does not manage answers that it has none, which is no refusal (C7).
	PushedTemplate = Document{
		Name:     "template",
		Fetch:    OpDocument("template", pushedTemplateCmd).Fetch,
		Optional: &Optional{Refused: configNoTemplate, Check: holdsTemplate},
	}

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

// Predefined is the device's predefined services, which no configuration holds.
// The device answers with service-http and service-https, each in the shape of a
// configured service (as observed on fw02, PAN-OS 12.2.3, L4). The command was
// checked on that release only, so a refusal is a note, not a failure. An answer
// without a <service> element, such as an empty result or a proxy's page, counts
// as a refusal.
var Predefined = Document{
	Name:  "predefined",
	Fetch: OpDocument("predefined", predefinedCmd).Fetch,
	Optional: &Optional{
		Refused: reason.New("note.fetch-predefined-missing",
			"the device did not return its predefined services; rules that use them stay in doubt"),
		Check: holdsService,
	},
}

const predefinedCmd = "<show><predefined><xpath>/predefined/service</xpath></predefined></show>"

// holdsService returns why an answer is not well-formed XML with a <service>
// element, or nil when it is.
func holdsService(b []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(b))
	found := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("the answer is not XML: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == "service" {
			found = true
		}
	}
	if !found {
		return errors.New("the answer holds no <service> element")
	}
	return nil
}

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
// because nothing can be analysed without it, and the pushed template right
// after it, because the template step merges the two (PD1).
var Documents = []Document{RunningConfig, PushedTemplate, SystemInfo, Interfaces, RoutingFIB, RoutingRIB, HAState, Predefined}

// The show commands of the configuration and of the pushed template (spec
// 2026-10-17 C9, C12).
const (
	runningConfigCmd  = "<show><config><running/></config></show>"
	pushedTemplateCmd = "<show><config><pushed-template/></config></show>"
)

// noTemplateText is the whole result of a device without a template: no
// template, and no note (as observed on fw02, PAN-OS 12.2.3, spec 2026-10-17
// C7).
const noTemplateText = "No template pushed to device"

// The notes of a configuration that is not the running configuration and the
// template (spec 2026-10-17 §2.1).
var (
	configNotRunning = reason.New("note.config-not-running",
		"the device refused show config running, so the snapshot holds the configuration export, which can hold uncommitted changes")
	configNoTemplate = reason.New("note.config-no-template",
		"the device did not return its pushed template, so the snapshot holds its base configuration without the template values")
)

var (
	errNoConfig   = errors.New("the answer holds no response/result/config element")
	errNoTemplate = errors.New("the answer holds no response/result/template/config element")
)

// unwrapConfig returns the config element of the answer to show config
// running, byte for byte: with its attributes version, detail-version and
// urldb, and with its indent (C12, PD2).
func unwrapConfig(b []byte) ([]byte, error) {
	return element(b, errNoConfig, "response", "result", "config")
}

// unwrapTemplate returns the config element of the answer to show config
// pushed-template, byte for byte. It sits in a template element, after the
// name of the template stack (C9, PD2).
func unwrapTemplate(b []byte) ([]byte, error) {
	return element(b, errNoTemplate, "response", "result", "template", "config")
}

// holdsTemplate returns why an answer is neither a template nor the answer of
// a device without one (C7), or nil.
func holdsTemplate(b []byte) error {
	_, err := unwrapTemplate(b)
	if err != nil && isNoTemplate(b) {
		return nil
	}
	return err
}

// isNoTemplate reports whether an answer is that of a device without a
// template: a response whose result is noTemplateText (C7).
func isNoTemplate(b []byte) bool {
	var r struct {
		XMLName xml.Name `xml:"response"`
		Result  string   `xml:"result"`
	}
	return xml.Unmarshal(b, &r) == nil && strings.TrimSpace(r.Result) == noTemplateText
}

// element returns the element at the path from the root, from its start tag
// to its end tag, as the answer holds it; missing, wrapped, when the answer
// holds no such element or is no XML.
func element(b []byte, missing error, path ...string) ([]byte, error) {
	dec := xml.NewDecoder(bytes.NewReader(b))
	var open []string
	start := int64(-1)
	for {
		off := dec.InputOffset()
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil, missing
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", missing, err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			open = append(open, t.Name.Local)
			if start < 0 && slices.Equal(open, path) {
				start = off
			}
		case xml.EndElement:
			if start >= 0 && len(open) == len(path) {
				return b[start:dec.InputOffset()], nil
			}
			open = open[:len(open)-1]
		}
	}
}

// System is what a snapshot records from show system info.
type System struct {
	Hostname  string `xml:"result>system>hostname" json:"hostname,omitempty"`
	Model     string `xml:"result>system>model" json:"model,omitempty"`
	Serial    string `xml:"result>system>serial" json:"serial,omitempty"`
	SWVersion string `xml:"result>system>sw-version" json:"sw_version,omitempty"`
	MultiVsys string `xml:"result>system>multi-vsys" json:"multi_vsys,omitempty"`
	// AppVersion is the App-ID content version; the application data belongs
	// to it (spec 2026-10-16 F2).
	AppVersion string `xml:"result>system>app-version" json:"app_version,omitempty"`
}

// ParseSystemInfo reads the response to show system info.
func ParseSystemInfo(b []byte) (System, error) {
	var s System
	if err := xml.Unmarshal(b, &s); err != nil {
		return System{}, fmt.Errorf("system info: %w", err)
	}
	return s, nil
}
