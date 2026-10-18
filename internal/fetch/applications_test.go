package fetch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/fakepanos"
	"github.com/kaisero/proteus/internal/task"
)

const appVersion = "8000-1000"

// appState is a logged-in state after the documents step: it knows the
// device's content version.
func appState(t *testing.T, d *fakepanos.Device, version string) *State {
	t.Helper()
	c := quick(loggedIn(t, d))
	return &State{
		Target: target(""), client: c,
		Result: Result{Docs: map[string][]byte{}, System: System{AppVersion: version}},
	}
}

// appRequests are the App-ID commands the device received, in order.
func appRequests(d *fakepanos.Device) []string {
	var out []string
	for _, r := range d.Requests() {
		if r.Cmd == fakepanos.ApplicationsCmd || r.Cmd == fakepanos.ContainersCmd {
			out = append(out, r.Cmd)
		}
	}
	return out
}

// parse reads the content file of a result.
func parse(t *testing.T, a *AppData) *appid.Data {
	t.Helper()
	if a == nil || a.File == nil {
		t.Fatalf("no content file: %+v", a)
	}
	d, err := appid.Parse(bytes.NewReader(a.File))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The show system info answer names the content version (spec 2026-10-16 F2).
func TestParseSystemInfoReadsAppVersion(t *testing.T) {
	t.Parallel()
	b := []byte(fullDevice(t).Ops["<show><system><info/></system></show>"])
	got, err := ParseSystemInfo(b)
	if err != nil || got.AppVersion != appVersion {
		t.Errorf("ParseSystemInfo = %+v, %v", got, err)
	}
}

// On a miss the step asks the two F1 commands in sequence, after the
// documents, and hands over one content file with both parts (§2.1, §2.2).
func TestApplicationsStepMissFetchesBoth(t *testing.T) {
	t.Parallel()
	d := fullDevice(t)
	s := NewState(target(d.Start(t)), Documents, ActiveOptions{}, nil)
	s.HaveApps = func(string) bool { return false }
	recs, err := task.Run(context.Background(), "lab", &s, Steps(), task.Options{})
	if err != nil {
		t.Fatal(err)
	}
	last := recs[len(recs)-1]
	if last.Slug != "applications" || last.Status != task.OK || len(last.Notes) != 0 {
		t.Errorf("applications step = %+v", last)
	}
	reqs := d.Requests()
	if n := len(reqs); n < 2 || reqs[n-2].Cmd != fakepanos.ApplicationsCmd || reqs[n-1].Cmd != fakepanos.ContainersCmd {
		t.Errorf("the App-ID commands must come last, in order: %+v", reqs)
	}
	if applicationsCmd != fakepanos.ApplicationsCmd || containersCmd != fakepanos.ContainersCmd {
		t.Error("fetch and the fake device ask different commands")
	}
	a := s.Result.Apps
	data := parse(t, a)
	if a.Version != appVersion || a.ContainersMissing || data.Version() != appVersion || !data.HasContainers() {
		t.Errorf("apps = %+v, version %s, containers %v", a, data.Version(), data.HasContainers())
	}
	if _, ok := data.App("ssl"); !ok {
		t.Error("the applications are missing")
	}
	if c, ok := data.Container("office-suite"); !ok || len(c.Functions) != 2 {
		t.Errorf("container = %+v, %v", c, ok)
	}
	if len(s.Result.Notes) != 0 {
		t.Errorf("notes = %v", s.Result.Notes)
	}
}

// A stored file for the version is a hit: nothing reaches the device (§2.2).
func TestApplicationsStepHitSkipsTheDevice(t *testing.T) {
	t.Parallel()
	d := device()
	s := appState(t, d, appVersion)
	var asked []string
	s.HaveApps = func(v string) bool { asked = append(asked, v); return true }
	r, err := applicationsStep(context.Background(), s)
	if err != nil || r.Status != "" {
		t.Errorf("result %+v, err %v", r, err)
	}
	if got := appRequests(d); len(got) != 0 {
		t.Errorf("a hit asked the device: %v", got)
	}
	if a := s.Result.Apps; a == nil || a.Version != appVersion || a.File != nil {
		t.Errorf("apps = %+v", a)
	}
	if len(asked) != 1 || asked[0] != appVersion {
		t.Errorf("HaveApps asked %v", asked)
	}
}

// expectMissing checks that the step gave the refusal note, no data and a
// complete status.
func expectMissing(t *testing.T, s *State, r task.Result, err error) {
	t.Helper()
	if err != nil || r.Status != "" || len(r.Notes) != 1 || r.Notes[0].Code != "note.fetch-applications-missing" {
		t.Errorf("result %+v, err %v", r, err)
	}
	if len(s.Result.Notes) != 1 || s.Result.Notes[0].Text !=
		"the device did not return its application data, so rules that name an application stay in doubt" {
		t.Errorf("notes = %v", s.Result.Notes)
	}
	if s.Result.Apps != nil || len(s.Result.Outcomes) != 0 {
		t.Errorf("apps %+v, outcomes %+v", s.Result.Apps, s.Result.Outcomes)
	}
}

// A refused command gives the note, not a failure (§2.2).
func TestApplicationsStepRefusalIsANote(t *testing.T) {
	t.Parallel()
	for name, answer := range map[string]string{
		"status error": fakepanos.Refusal("17", "show -> application is unexpected"),
		"http error":   "",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := device()
			d.Ops[fakepanos.ApplicationsCmd] = answer
			s := appState(t, d, appVersion)
			if answer == "" {
				s.client.key = "not-the-key" // the fake device answers HTTP 403
			}
			r, err := applicationsStep(context.Background(), s)
			expectMissing(t, s, r, err)
			if got := appRequests(d); len(got) != 1 {
				t.Errorf("after a refusal the containers are not asked: %v", got)
			}
		})
	}
}

// A success answer without an entry, such as "No data found", is a refusal
// (§2.2, F16).
func TestApplicationsStepNoEntryIsANote(t *testing.T) {
	t.Parallel()
	d := device()
	d.Ops[fakepanos.ApplicationsCmd] = fakepanos.Success("<msg>No data found</msg>")
	s := appState(t, d, appVersion)
	r, err := applicationsStep(context.Background(), s)
	expectMissing(t, s, r, err)
}

// A content version that cannot name a file gives the note and asks nothing
// (§2.2).
func TestApplicationsStepBadVersionIsANote(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"x/../y", ""} {
		d := device()
		s := appState(t, d, v)
		s.HaveApps = func(string) bool { t.Error("HaveApps asked for a bad version"); return true }
		r, err := applicationsStep(context.Background(), s)
		expectMissing(t, s, r, err)
		if got := appRequests(d); len(got) != 0 {
			t.Errorf("%q: the device was asked: %v", v, got)
		}
	}
}

// A transport failure records an outcome and makes the step partial. The step
// returns no error, so the snapshot is still stored (§2.2).
func TestApplicationsStepTransportFailureIsPartial(t *testing.T) {
	t.Parallel()
	d := device()
	s := appState(t, d, appVersion)
	d.DropFirst = 2
	r, err := applicationsStep(context.Background(), s)
	if err != nil || r.Status != task.Partial || len(r.Notes) != 0 {
		t.Errorf("result %+v, err %v", r, err)
	}
	if o := s.Result.Outcomes; len(o) != 1 || o[0].Name != "applications" || o[0].Err == nil {
		t.Errorf("outcomes = %+v", o)
	}
	if s.Result.Apps != nil || len(s.Result.Notes) != 0 {
		t.Errorf("apps %+v, notes %v", s.Result.Apps, s.Result.Notes)
	}
}

// Containers that do not arrive leave the applications in the file, which
// records that the containers are missing (§2.2).
func TestApplicationsStepContainersMissingKeepsApps(t *testing.T) {
	t.Parallel()
	d := device()
	d.Ops[fakepanos.ContainersCmd] = fakepanos.Refusal("17", "show -> application-container is unexpected")
	s := appState(t, d, appVersion)
	r, err := applicationsStep(context.Background(), s)
	if err != nil || r.Status != task.Partial || !strings.Contains(r.Detail, "containers missing") {
		t.Errorf("result %+v, err %v", r, err)
	}
	a := s.Result.Apps
	data := parse(t, a)
	if !a.ContainersMissing || data.HasContainers() {
		t.Errorf("apps %+v, containers %v", a, data.HasContainers())
	}
	if _, ok := data.App("office-docs"); !ok {
		t.Error("the applications must stay")
	}
	if len(s.Result.Outcomes) != 0 || len(s.Result.Notes) != 0 {
		t.Errorf("outcomes %+v, notes %v", s.Result.Outcomes, s.Result.Notes)
	}
}

// A body cut off mid-read is retried, and read runs again on the new body
// (R2: one retry loop for every call).
func TestOpStreamRetriesATransportError(t *testing.T) {
	t.Parallel()
	d := device()
	c := quick(loggedIn(t, d))
	d.TruncateFirst = 1
	var buf bytes.Buffer
	calls := 0
	err := c.opStream(context.Background(), fakepanos.ApplicationsCmd, func(r io.Reader) error {
		calls++
		buf.Reset()
		_, err := io.Copy(&buf, r)
		return err
	})
	if err != nil || calls != 2 || buf.String() != fakepanos.Applications {
		t.Errorf("err %v, %d calls, body %q", err, calls, buf.String())
	}
}

// An error of the caller's read is no transport error: it is not retried and
// comes back unchanged.
func TestOpStreamKeepsItsReadError(t *testing.T) {
	t.Parallel()
	d := device()
	c := quick(loggedIn(t, d))
	mine := errors.New("dummy read error")
	calls := 0
	err := c.opStream(context.Background(), fakepanos.ApplicationsCmd, func(io.Reader) error {
		calls++
		return mine
	})
	if err != mine || calls != 1 { //nolint:errorlint // the very error, unwrapped
		t.Errorf("err %v, %d calls", err, calls)
	}
	if got := appRequests(d); len(got) != 1 {
		t.Errorf("requests %v", got)
	}
}

// An HTTP error status is a refusal; read never sees its body.
func TestOpStreamRefusesAnErrorStatus(t *testing.T) {
	t.Parallel()
	c := loggedIn(t, device())
	c.key = "not-the-key"
	err := c.opStream(context.Background(), fakepanos.ApplicationsCmd, func(io.Reader) error {
		t.Error("read ran on an error status")
		return nil
	})
	api, ok := errors.AsType[*APIError](err)
	if !ok || api.HTTPStatus != 403 || !strings.Contains(api.Message, "Invalid credentials") {
		t.Errorf("err = %v", err)
	}
}
