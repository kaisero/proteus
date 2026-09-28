package fetch

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/okaiser/panos-analyst/internal/fakepanos"
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
	return d
}

func TestRunFetchesEveryDocument(t *testing.T) {
	d := fullDevice(t)
	res, err := Run(context.Background(), target(d.Start(t)), Documents)
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
	res, err := Run(context.Background(), target(d.Start(t)), Documents)
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
	_, err := Run(context.Background(), tg, Documents)
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Errorf("want a login error that does not quote the password, got %v", err)
	}
}
