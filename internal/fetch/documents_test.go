package fetch

import (
	"context"
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/fakepanos"
	"github.com/kaisero/proteus/internal/task"
)

// Every document is stored as <name>.xml, so a name must be unique and file-safe.
func TestDocumentNamesAreUniqueAndFileSafe(t *testing.T) {
	t.Parallel()
	safe := regexp.MustCompile(`^[a-z0-9-]+$`)
	seen := map[string]bool{}
	for _, d := range Documents {
		if !safe.MatchString(d.Name) || seen[d.Name] {
			t.Errorf("document name %q is not unique and file-safe", d.Name)
		}
		seen[d.Name] = true
		if d.Fetch == nil {
			t.Errorf("%s has no Fetch", d.Name)
		}
		if d.Optional != nil && d.Optional.Refused.Code == "" {
			t.Errorf("%s is optional and has no note for a refusal", d.Name)
		}
		if d.Fallback != nil && (d.Fallback.Fetch == nil || d.Fallback.Note.Code == "") {
			t.Errorf("%s has a fallback without a fetch or a note", d.Name)
		}
	}
	if Documents[0].Name != "config" {
		t.Error("the configuration comes first: nothing can be analysed without it")
	}
	if Documents[1].Name != PushedTemplate.Name || PushedTemplate.Name != "template" {
		t.Error("the pushed template comes right after the configuration (PD1)")
	}
}

// configFetch fetches the documents of a device and returns the state and the
// documents step.
func configFetch(t *testing.T, d *fakepanos.Device) (State, task.Record) {
	t.Helper()
	s, steps := fetched(t, d)
	return s, steps["documents"]
}

// The configuration is show config running: it holds no uncommitted change,
// where the export holds the candidate (as observed on fw01, PAN-OS 11.2.5,
// spec 2026-10-17 C12). The device is not asked for the export. The config
// element is stored as the device sent it: the file's last newline is no byte
// of it (PD2).
func TestRunningConfigIsTheBase(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	s, docs := configFetch(t, d)
	if sent(d, fakepanos.RunningConfigCmd) != 1 || sent(d, "export") != 0 {
		t.Errorf("requests: %+v", d.Requests())
	}
	if string(s.Result.Docs["config"]) != strings.TrimSuffix(d.Config, "\n") {
		t.Errorf("config:\n%s", s.Result.Docs["config"])
	}
	if !strings.HasPrefix(s.Result.ConfigSource, "running") || docs.Status != task.OK || codes(s) != "" {
		t.Errorf("source %q, documents %+v, notes %s", s.Result.ConfigSource, docs, codes(s))
	}
	if runningConfigCmd != fakepanos.RunningConfigCmd || pushedTemplateCmd != fakepanos.PushedTemplateCmd {
		t.Error("fetch asks other commands than the fake device answers")
	}
}

// show config running returns response/result/config (C12). unwrapConfig
// returns that element byte for byte, an indented one too, with its
// attributes and entities. An answer without it gives errNoConfig.
func TestUnwrapConfigKeepsTheDeviceBytes(t *testing.T) {
	t.Parallel()
	for _, x := range []string{
		`<config version="11.2.0" urldb="paloaltonetworks" detail-version="11.2.5"><devices/></config>`,
		"<config detail-version=\"11.2.5\" urldb=\"paloaltonetworks\" version=\"11.2.0\">\n  <shared>\n" +
			"    <address>\n      <entry name=\"a&amp;b\">\n        <description>x &lt; y</description>\n" +
			"      </entry>\n    </address>\n  </shared>\n</config>",
		`<config/>`,
	} {
		got, err := unwrapConfig([]byte(fakepanos.Success(x)))
		if err != nil || string(got) != x {
			t.Errorf("got %q, %v; want %q", got, err, x)
		}
	}
	for _, a := range []string{
		`<response status="success"><result/></response>`,
		fakepanos.Success(`<template><config/></template>`),
		`<config version="11.2.0"/>`,
		`<response status="success"><result><config>`,
		`not xml`,
		``,
	} {
		if _, err := unwrapConfig([]byte(a)); !errors.Is(err, errNoConfig) {
			t.Errorf("%q: %v", a, err)
		}
	}
}

// A device that refuses show config running is exported, and the note says
// that the export can hold uncommitted changes (spec §2.1, C12).
func TestARefusedRunningConfigFallsBackToTheExport(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Ops[fakepanos.RunningConfigCmd] = fakepanos.Refusal("17", "show -> config is unexpected")
	s, docs := configFetch(t, d)
	if sent(d, "export") != 1 || string(s.Result.Docs["config"]) != d.Config {
		t.Errorf("requests %+v, config %s", d.Requests(), s.Result.Docs["config"])
	}
	if codes(s) != "note.config-not-running" || len(docs.Notes) != 1 || docs.Notes[0].Code != "note.config-not-running" ||
		docs.Status != task.OK || !strings.HasPrefix(s.Result.ConfigSource, "export") {
		t.Errorf("notes %s, documents %+v, source %q", codes(s), docs, s.Result.ConfigSource)
	}
	if !arrived(s.Result, "config") {
		t.Errorf("outcomes: %+v", s.Result.Outcomes)
	}
}

// An answer without response/result/config is no running configuration: the
// export and the note (spec §2.1).
func TestARunningAnswerWithoutConfigFallsBack(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Ops[fakepanos.RunningConfigCmd] = `<response status="success"><result/></response>`
	s, _ := configFetch(t, d)
	if sent(d, "export") != 1 || codes(s) != "note.config-not-running" || string(s.Result.Docs["config"]) != d.Config {
		t.Errorf("requests %+v, notes %s", d.Requests(), codes(s))
	}
}

// A transport error is no refusal: the configuration document fails, and the
// export is not tried against a device that is not answering (spec §2.1).
func TestATransportErrorFailsTheConfigDocument(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.DropCmd = map[string]int{fakepanos.RunningConfigCmd: 2}
	s, steps := fetched(t, d)
	if arrived(s.Result, "config") || !slices.ContainsFunc(s.Result.Outcomes, func(o Outcome) bool { return o.Name == "config" && o.Err != nil }) {
		t.Errorf("outcomes: %+v", s.Result.Outcomes)
	}
	if sent(d, "export") != 0 || s.Result.ConfigSource != "" || codes(s) != "" {
		t.Errorf("requests %+v, source %q, notes %s", d.Requests(), s.Result.ConfigSource, codes(s))
	}
	if steps["documents"].Status != task.Partial || steps["template"].Status != task.Skipped {
		t.Errorf("documents %+v, template %+v", steps["documents"], steps["template"])
	}
}

// A fallback that fails too fails the document, with both errors, and adds no
// note.
func TestAFailedFallbackFailsTheDocument(t *testing.T) {
	t.Parallel()
	doc := Document{
		Name:  "x",
		Fetch: func(context.Context, *Client) ([]byte, error) { return nil, &APIError{HTTPStatus: 200, Code: "17"} },
		Fallback: &Fallback{
			Fetch: func(context.Context, *Client) ([]byte, error) { return nil, errors.New("the other way failed") },
			Note:  configNotRunning,
		},
	}
	s := State{Docs: []Document{doc}, Result: Result{Docs: map[string][]byte{}}}
	r, err := documentsStep(context.Background(), &s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != task.Partial || len(r.Notes) != 0 || len(s.Result.Notes) != 0 || len(s.Result.Outcomes) != 1 {
		t.Fatalf("result %+v, outcomes %+v", r, s.Result.Outcomes)
	}
	if msg := s.Result.Outcomes[0].Err.Error(); !strings.Contains(msg, "code 17") || !strings.Contains(msg, "the other way failed") {
		t.Errorf("error %q", msg)
	}
}

// Advanced Routing off: the device refuses the new command and the legacy one
// answers with the same shape.
func TestRoutingFIBFallsBackToTheLegacyCommand(t *testing.T) {
	t.Parallel()
	d := device()
	d.Ops["<show><routing><fib/></routing></show>"] = fakepanos.Success("<fibs/>")
	c := loggedIn(t, d)
	b, err := RoutingFIB.Fetch(context.Background(), c)
	if err != nil || string(b) != fakepanos.Success("<fibs/>") {
		t.Fatalf("got %s, %v", b, err)
	}
	reqs := d.Requests()
	if reqs[1].Cmd != "<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>" ||
		reqs[2].Cmd != "<show><routing><fib/></routing></show>" {
		t.Errorf("commands sent: %q then %q", reqs[1].Cmd, reqs[2].Cmd)
	}
}

func TestOpDocumentReportsEveryRefusal(t *testing.T) {
	t.Parallel()
	c := loggedIn(t, device())
	_, err := OpDocument("x", "<show><a/></show>", "<show><b/></show>").Fetch(context.Background(), c)
	if err == nil {
		t.Fatal("two refusals must fail")
	}
}

// A device that stops answering is not asked the fallback.
func TestOpDocumentStopsOnATransportError(t *testing.T) {
	t.Parallel()
	d := device()
	c := loggedIn(t, d)
	d.DropFirst = 2
	_, err := OpDocument("x", "<show><a/></show>", "<show><b/></show>").Fetch(context.Background(), c)
	if err == nil {
		t.Fatal("a dead device must fail")
	}
	for _, r := range d.Requests() {
		if r.Cmd == "<show><b/></show>" {
			t.Error("the fallback was tried against a device that was not answering")
		}
	}
}

func TestParseSystemInfo(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile("../../testdata/opdata/fw01-system-info.xml")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSystemInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "lab-fw01-vm" || got.Serial != "007900000000001" || got.SWVersion != "11.2.5" ||
		got.Model != "PA-VM" || got.MultiVsys != "off" {
		t.Errorf("ParseSystemInfo = %+v", got)
	}
	if _, err := ParseSystemInfo([]byte("not xml")); err == nil {
		t.Error("garbage must be an error")
	}
}
