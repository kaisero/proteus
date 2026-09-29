package fetch

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/internal/fakepanos"
	"github.com/okaiser/panos-analyst/runlog"
)

func fullDevice(t *testing.T) *fakepanos.Device {
	t.Helper()
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	d := device()
	d.Config = read("../testdata/config/firewall-lab.xml")
	d.Ops["<show><system><info/></system></show>"] = read("../testdata/opdata/fw01-system-info.xml")
	d.Ops["<show><interface>all</interface></show>"] = read("../testdata/opdata/fw01-interface-all.xml")
	d.Ops["<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>"] = read("../testdata/opdata/fw01-advanced-routing-fib.xml")
	d.Ops[RoutingRIBCmd] = read("../testdata/opdata/fw02-advanced-routing-route.xml")
	d.Ops[haStateCmd] = read("../testdata/opdata/fw02-ha-state.xml")
	return d
}

func TestRunFetchesEveryDocument(t *testing.T) {
	d := fullDevice(t)
	res, err := Run(context.Background(), target(d.Start(t)), Documents, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range Documents {
		if !res.OK(doc.Name) || len(res.Docs[doc.Name]) == 0 {
			t.Errorf("%s did not arrive: %+v", doc.Name, res.Outcomes)
		}
	}
	if res.System.Serial != "007900000000001" {
		t.Errorf("system info not parsed: %+v", res.System)
	}
	if res.OK("never-asked") {
		t.Error("a document never asked for is not OK")
	}
}

// Spec S10: a document that fails is recorded and the rest still arrive.
func TestRunContinuesPastAFailedDocument(t *testing.T) {
	d := fullDevice(t)
	delete(d.Ops, "<show><interface>all</interface></show>")
	res, err := Run(context.Background(), target(d.Start(t)), Documents, nil)
	if err != nil {
		t.Fatalf("one failed document must not fail the run: %v", err)
	}
	if res.OK("interfaces") {
		t.Error("interfaces must be recorded as failed")
	}
	if !res.OK("config") || !res.OK("fib") {
		t.Errorf("the other documents must still arrive: %+v", res.Outcomes)
	}
}

// Without a key nothing can be read, so a failed login fails the run.
func TestRunFailsWhenLoginFails(t *testing.T) {
	d := fullDevice(t)
	tg := target(d.Start(t))
	tg.Password = "wrong"
	_, err := Run(context.Background(), tg, Documents, nil)
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Errorf("want a login error that does not quote the password, got %v", err)
	}
}

// A debug log records every call and never a password or a key.
func TestRunLogsCallsWithoutSecrets(t *testing.T) {
	d := fullDevice(t)
	delete(d.Ops, "<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>")
	d.Ops["<show><routing><fib/></routing></show>"] = "<response status=\"success\"><result/></response>"
	l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "fetch", Level: runlog.Debug})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), target(d.Start(t)), Documents, l); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	b, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		"[DEBUG] [API] lab: keygen -> HTTP 200", "[INFO] [API] lab: logged in as reader",
		"[DEBUG] [API] lab: op <show><interface>all</interface></show> -> HTTP 200", "[INFO] [API] lab: fib: fell back to <show><routing><fib/></routing></show>",
		"[WARN] [API] lab: op <show><advanced-routing>", "[INFO] [API] lab: config: ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, testPass) || strings.Contains(got, testKey) {
		t.Errorf("a secret reached the log:\n%s", got)
	}
}
