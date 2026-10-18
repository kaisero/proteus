package fetch

import (
	"context"
	"os"
	"regexp"
	"testing"

	"github.com/kaisero/proteus/internal/fakepanos"
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
	}
	if Documents[0].Name != "config" {
		t.Error("the configuration comes first: nothing can be analysed without it")
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
