package fetch

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/fakepanos"
	"github.com/okaiser/proteus/internal/inventory"
	"github.com/okaiser/proteus/internal/runlog"
	"github.com/okaiser/proteus/internal/task"
)

// run is a device's fetch the way the command line runs it: the fetch steps in
// order, with the device's name as the task's kind.
func run(ctx context.Context, t inventory.Target, docs []Document, opts ActiveOptions, log *runlog.Logger) (Result, error) {
	s := NewState(t, docs, opts, log)
	_, err := task.Run(ctx, t.Name, &s, Steps(), task.Options{Log: log})
	return s.Result, err
}

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
	d.Config = read("../../testdata/config/firewall-lab.xml")
	d.Ops["<show><system><info/></system></show>"] = read("../../testdata/opdata/fw01-system-info.xml")
	d.Ops["<show><interface>all</interface></show>"] = read("../../testdata/opdata/fw01-interface-all.xml")
	d.Ops["<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>"] = read("../../testdata/opdata/fw01-advanced-routing-fib.xml")
	d.Ops[RoutingRIBCmd] = read("../../testdata/opdata/fw02-advanced-routing-route.xml")
	d.Ops[haStateCmd] = read("../../testdata/opdata/fw02-ha-state.xml")
	return d
}

// arrived reports whether a document's outcome is recorded without an error.
func arrived(r Result, name string) bool {
	for _, o := range r.Outcomes {
		if o.Name == name {
			return o.Err == nil
		}
	}
	return false
}

func TestRunFetchesEveryDocument(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	res, err := run(context.Background(), target(d.Start(t)), Documents, ActiveOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, doc := range Documents {
		if !arrived(res, doc.Name) || len(res.Docs[doc.Name]) == 0 {
			t.Errorf("%s did not arrive: %+v", doc.Name, res.Outcomes)
		}
	}
	if res.System.Serial != "007900000000001" {
		t.Errorf("system info not parsed: %+v", res.System)
	}
	if arrived(res, "never-asked") {
		t.Error("a document never asked for is not OK")
	}
}

// Spec S10: a document that fails is recorded and the rest still arrive.
func TestRunContinuesPastAFailedDocument(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	delete(d.Ops, "<show><interface>all</interface></show>")
	res, err := run(context.Background(), target(d.Start(t)), Documents, ActiveOptions{}, nil)
	if err != nil {
		t.Fatalf("one failed document must not fail the run: %v", err)
	}
	if arrived(res, "interfaces") {
		t.Error("interfaces must be recorded as failed")
	}
	if !arrived(res, "config") || !arrived(res, "fib") {
		t.Errorf("the other documents must still arrive: %+v", res.Outcomes)
	}
}

// Without a key nothing can be read, so a failed login fails the run.
func TestRunFailsWhenLoginFails(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	tg := target(d.Start(t))
	tg.Password = "wrong"
	_, err := run(context.Background(), tg, Documents, ActiveOptions{}, nil)
	if err == nil || strings.Contains(err.Error(), "wrong") {
		t.Errorf("want a login error that does not quote the password, got %v", err)
	}
}

// A debug log records every call and never a password or a key.
func TestRunLogsCallsWithoutSecrets(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	delete(d.Ops, "<show><advanced-routing><fib><afi>both</afi></fib></advanced-routing></show>")
	d.Ops["<show><routing><fib/></routing></show>"] = "<response status=\"success\"><result/></response>"
	l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "fetch", Level: runlog.Debug})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run(context.Background(), target(d.Start(t)), Documents, ActiveOptions{}, l); err != nil {
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
		"[DEBUG] [API] lab: op <show><advanced-routing>", "[INFO] [API] lab: config: ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, testPass) || strings.Contains(got, testKey) {
		t.Errorf("a secret reached the log:\n%s", got)
	}
	// A refusal the fetcher recovers from by falling back is not a warning.
	if strings.Contains(got, "[WARN]") {
		t.Errorf("a handled refusal was logged as a warning:\n%s", got)
	}
}

// A document that fails for good is warned about once, by the caller that gives up
// on it, not again by the client that saw the refusal.
func TestAFailedDocumentIsWarnedAboutOnce(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	delete(d.Ops, "<show><interface>all</interface></show>")
	l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "fetch", Level: runlog.Debug})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run(context.Background(), target(d.Start(t)), Documents, ActiveOptions{}, l); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	b, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	var warns []string
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.Contains(line, "[WARN]") && strings.Contains(line, "interface") {
			warns = append(warns, line)
		}
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "interfaces failed") {
		t.Errorf("want one warning for the failed document, got:\n%s", strings.Join(warns, "\n"))
	}
}

// A run cancelled while the device hangs returns at once, and TestMain's leak check
// proves it leaves no goroutine behind.
func TestACancelledRunEndsPromptly(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Stall = "export"
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := run(ctx, target(d.Start(t)), Documents, ActiveOptions{}, nil)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the run took %s after its context ended", elapsed)
	}
	if err == nil && arrived(res, RunningConfig.Name) {
		t.Error("the stalled export cannot have succeeded")
	}
}

// The device name appears once in a login error: the task's kind adds it.
func TestALoginErrorNamesTheDeviceOnce(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	d.Password = "other"
	_, err := run(context.Background(), target(d.Start(t)), Documents, ActiveOptions{}, nil)
	if err == nil || strings.Count(err.Error(), target("").Name) != 1 || !strings.HasPrefix(err.Error(), target("").Name+"/login: ") {
		t.Errorf("err = %v", err)
	}
}

// The predefined services arrive as the device answers them (L4), and the fake
// device answers them as fw02 did.
func TestRunFetchesThePredefinedServices(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	res, err := run(context.Background(), target(d.Start(t)), Documents, ActiveOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../testdata/predefined/predefined.xml")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res.Docs[Predefined.Name]); got != strings.TrimSpace(string(want)) || got != fakepanos.PredefinedServices {
		t.Errorf("predefined = %s", got)
	}
	if len(res.Notes) != 0 {
		t.Errorf("notes: %v", res.Notes)
	}
	if predefinedCmd != fakepanos.PredefinedCmd {
		t.Errorf("fetch asks %q, the fake device answers %q", predefinedCmd, fakepanos.PredefinedCmd)
	}
}

// A device that refuses the predefined command, as an older release may, gives a
// note and a complete fetch: the document is optional. So does an accepted answer
// without a <service> element, such as an empty result or a proxy's HTML page:
// nothing is stored, so no reader meets it.
func TestARefusedPredefinedDocumentIsANote(t *testing.T) {
	t.Parallel()
	for name, answer := range map[string]string{
		"refused":      fakepanos.Refusal("17", "show -> predefined is unexpected"),
		"empty result": `<response status="success"><result/></response>`,
		"html page":    `<html><head><title>Sign in</title></head><body><p>Sign in first</p></body></html>`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := fullDevice(t)
			d.Ops[fakepanos.PredefinedCmd] = answer
			l, err := runlog.Open(runlog.Options{Dir: t.TempDir(), Command: "fetch", Level: runlog.Debug})
			if err != nil {
				t.Fatal(err)
			}
			s := NewState(target(d.Start(t)), Documents, ActiveOptions{}, l)
			recs, err := task.Run(context.Background(), "lab", &s, Steps(), task.Options{Log: l})
			if err != nil {
				t.Fatal(err)
			}
			_ = l.Close()
			docs := recs[len(recs)-1]
			if docs.Slug != "documents" || docs.Status != task.OK || docs.Detail != "6 of 7 documents" ||
				len(docs.Notes) != 1 || docs.Notes[0].Code != "note.fetch-predefined-missing" {
				t.Errorf("documents step = %+v", docs)
			}
			if len(s.Result.Notes) != 1 || s.Result.Notes[0].Text != "the device did not return its predefined services; rules that use them stay in doubt" {
				t.Errorf("notes = %v", s.Result.Notes)
			}
			for _, o := range s.Result.Outcomes {
				if o.Err != nil || o.Name == Predefined.Name {
					t.Errorf("outcome %+v: a refused optional document is not a document outcome", o)
				}
			}
			if _, ok := s.Result.Docs[Predefined.Name]; ok || arrived(s.Result, Predefined.Name) {
				t.Error("a refused document did not arrive")
			}
			b, err := os.ReadFile(l.Path())
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), "[WARN] [API] lab: predefined refused") {
				t.Errorf("the refusal is not warned about:\n%s", b)
			}
		})
	}
}

// The check reads the whole answer: it must parse and hold the element.
func TestHoldsService(t *testing.T) {
	t.Parallel()
	if err := holdsService([]byte(fakepanos.PredefinedServices)); err != nil {
		t.Errorf("the L4 answer: %v", err)
	}
	if err := holdsService([]byte(`<response><result><service><entry>`)); err == nil || !strings.Contains(err.Error(), "not XML") {
		t.Errorf("a cut answer: %v", err)
	}
	if err := holdsService([]byte(`<response status="success"><result/></response>`)); err == nil || !strings.Contains(err.Error(), "no <service>") {
		t.Errorf("an empty result: %v", err)
	}
}

// A transport failure of an optional document fails it as any other.
func TestAnOptionalDocumentFailsOnATransportError(t *testing.T) {
	t.Parallel()
	d := device()
	s := State{Docs: []Document{Predefined}, client: loggedIn(t, d), Result: Result{Docs: map[string][]byte{}}}
	d.DropFirst = 2
	r, err := documentsStep(context.Background(), &s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != task.Partial || len(r.Notes) != 0 || len(s.Result.Outcomes) != 1 || s.Result.Outcomes[0].Err == nil {
		t.Errorf("result %+v, outcomes %+v", r, s.Result.Outcomes)
	}
}
