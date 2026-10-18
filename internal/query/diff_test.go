package query

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/drift"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
)

// diffLab is fw01 fetched twice, the second time changed and from another
// serial, and fw02 fetched once.
func diffLab(t *testing.T) Env {
	t.Helper()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01", Serial: "000000000001"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01", Serial: "000000000002"}, pathlab.Read(t, fixture("firewall-lab-changed.xml")))
	l.fetch("fw02", pathlab.ConfigFile("fw02"))
	return l.env()
}

// A diff per device and scope: fw01's changes with the serial note, fw02's one
// snapshot a hole.
func TestSnapshotDiff(t *testing.T) {
	t.Parallel()
	e, err := SnapshotDiff(context.Background(), diffLab(t), DiffInput{})
	if err != nil || e.Command != "snapshot diff" || len(e.Results) < 2 {
		t.Fatalf("%+v %v", e, err)
	}
	if r := e.Results[0]; r.Device != "fw01" || r.Scope != "shared" || r.From == r.To || r.Changes == nil {
		t.Errorf("first: %+v", r)
	}
	changed := 0
	for _, r := range e.Results {
		changed += len(r.Changes)
	}
	if changed == 0 {
		t.Error("no changes")
	}
	if len(e.Notes) != 1 || e.Notes[0].Code != "note.serial-changed" || len(e.Holes) != 1 || e.Holes[0].Device != "fw02" ||
		!strings.Contains(e.Holes[0].Reason, "only one snapshot") {
		t.Errorf("notes %+v, holes %+v", e.Notes, e.Holes)
	}
	e, err = SnapshotDiff(context.Background(), diffLab(t), DiffInput{Selection: Selection{Device: []string{"fw01"}, Vsys: []string{"vsys1"}}})
	if err != nil || len(e.Results) != 2 || e.Results[1].Scope != "vsys:vsys1" {
		t.Errorf("vsys1: %+v %v", e.Results, err)
	}
}

// A setting of the scope is a change like any other: the limit counts it.
func TestSnapshotDiffLimitCountsSettings(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	vsys := func(body string) []byte {
		return []byte(`<config version="11.2.0"><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">` +
			body + `</entry></vsys></entry></devices></config>`)
	}
	l.write(store.Meta{Device: "fw01"}, vsys(`<display-name>one</display-name>`))
	l.write(store.Meta{Device: "fw01"}, vsys(`<display-name>two</display-name><import><network><interface><member>ethernet1/3</member></interface></network></import>`))
	fw01 := Selection{Device: []string{"fw01"}, Vsys: []string{"vsys1"}}
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: fw01, ResultLimit: ResultLimit{Limit: 1}})
	if err != nil || e.Summary.Found != 2 || e.Summary.Omitted != 1 || len(e.Results) != 2 || len(e.Results[1].Changes) != 1 ||
		e.Results[1].Changes[0].Kind != "setting" || e.Results[1].Changes[0].Name != "display-name" {
		t.Errorf("%v %+v %+v", err, e.Summary, e.Results)
	}
}

// From and To pick the snapshots; one before any snapshot is a hole.
func TestSnapshotDiffFromAndTo(t *testing.T) {
	t.Parallel()
	env := diffLab(t)
	fw01 := Selection{Device: []string{"fw01"}}
	e, err := SnapshotDiff(context.Background(), env, DiffInput{Selection: fw01, From: "2026-09-28T10:00:00Z", To: "2026-09-28T10:00:30Z"})
	if err != nil || len(e.Results) == 0 || e.Results[0].From != e.Results[0].To {
		t.Errorf("same snapshot: %+v %v", e.Results, err)
	}
	if e, err := SnapshotDiff(context.Background(), env, DiffInput{Selection: fw01, To: "2020-01-01"}); err != nil || len(e.Holes) != 1 || e.Holes[0].Code != "gap.snapshot-missing" {
		t.Errorf("before any: %+v %v", e.Holes, err)
	}
}

// A configuration that does not parse is a hole of a failed load.
func TestSnapshotDiffOfAnUnreadableConfiguration(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01"}, []byte("<config"))
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
	if err != nil || len(e.Holes) != 1 || e.Holes[0].Code != "gap.load-failed" || !strings.Contains(e.Holes[0].Reason, "unreadable configuration") {
		t.Errorf("%+v %v", e.Holes, err)
	}
}

// Without From, a damaged snapshot before the newer one is passed over: the
// diff compares the next older one that can be read, and a note names the
// skipped one.
func TestSnapshotDiffPassesOverADamagedSnapshot(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab-changed.xml")))
	ids, err := l.st.List("fw01")
	if err != nil || len(ids) != 3 {
		t.Fatalf("ids %v, %v", ids, err)
	}
	sn, _ := l.st.Get("fw01", ids[1])
	if err := os.Remove(filepath.Join(sn.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
	if err != nil || len(e.Holes) != 0 || len(e.Results) == 0 {
		t.Fatalf("%+v %v", e, err)
	}
	if r := e.Results[0]; r.From != ids[2] || r.To != ids[0] {
		t.Errorf("compared %s with %s, want %s with %s", r.From, r.To, ids[2], ids[0])
	}
	if len(e.Notes) != 1 || e.Notes[0].Code != "note.snapshot-skipped" || e.Notes[0].Device != "fw01" ||
		!strings.Contains(e.Notes[0].Note, ids[1]) {
		t.Errorf("notes %+v", e.Notes)
	}
}

// With --from and --to on one snapshot past a damaged one, the note shows once.
// With every older snapshot damaged, the hole is a failed load that names them,
// not "only one snapshot".
func TestSnapshotDiffNamesDamagedSnapshotsOnce(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	for range 3 {
		l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	}
	ids, _ := l.st.List("fw01")
	sn, _ := l.st.Get("fw01", ids[0])
	if err := os.Remove(filepath.Join(sn.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	fw01 := Selection{Device: []string{"fw01"}}
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: fw01, From: "2026-09-28T10:02:30Z", To: "2026-09-28T10:02:30Z"})
	if err != nil || len(e.Notes) != 1 || e.Notes[0].Code != "note.snapshot-skipped" {
		t.Errorf("one snapshot on both sides: notes %+v, %v", e.Notes, err)
	}
	sn, _ = l.st.Get("fw01", ids[2])
	if err := os.Remove(filepath.Join(sn.Dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	e, err = SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: fw01, To: "2026-09-28T10:01:30Z"})
	if err != nil || len(e.Holes) != 1 || e.Holes[0].Code != "gap.load-failed" ||
		!strings.Contains(e.Holes[0].Reason, "damaged: "+ids[2]) || strings.Contains(e.Holes[0].Reason, "only one") {
		t.Errorf("every older one damaged: holes %+v, %v", e.Holes, err)
	}
}

// An older configuration that is there but cannot be read is a failed load, not
// "only one snapshot".
func TestSnapshotDiffOfAnUnreadableOlderSnapshot(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	l.write(store.Meta{Device: "fw01"}, pathlab.Read(t, fixture("firewall-lab.xml")))
	ids, _ := l.st.List("fw01")
	sn, _ := l.st.Get("fw01", ids[1])
	p := sn.Path(store.ConfigDoc)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(p), p); err != nil { // a link to itself cannot be read
		t.Fatal(err)
	}
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
	if err != nil || len(e.Holes) != 1 || e.Holes[0].Code != "gap.load-failed" || strings.Contains(e.Holes[0].Reason, "only one") {
		t.Errorf("%+v %v", e.Holes, err)
	}
}

// A diff reads the store: a file, a time or a fresh fetch is refused, as are an
// unknown device and an env without the estate.
func TestSnapshotDiffInputRules(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in   DiffInput
		want string
	}{
		{DiffInput{Selection: Selection{File: "x.xml"}}, "--file: snapshot diff compares stored snapshots"},
		{DiffInput{Selection: Selection{At: "2026-01-01"}}, "--at: snapshot diff"},
		{DiffInput{Selection: Selection{Fresh: true}}, "--fresh: snapshot diff"},
		{DiffInput{Selection: Selection{Device: []string{"fw09"}}}, `no device named "fw09"`},
		// From and To read as at does; a bad one names its own input.
		{DiffInput{To: "tuesday"}, `--to "tuesday": want a snapshot id, an RFC 3339 time, or a date`},
		{DiffInput{From: "tuesday", To: "2026-09-28"}, `--from "tuesday": want a snapshot id`},
	} {
		_, err := SnapshotDiff(context.Background(), diffLab(t), tc.in)
		usageOK(t, err, tc.want)
	}
	// The tool's words name the input without the dashes.
	u := DiffInput{From: "tuesday"}.Validate()
	if u == nil || u.ToolText != `from "tuesday": want a snapshot id, an RFC 3339 time, or a date like 2026-09-23` {
		t.Errorf("tool text: %+v", u)
	}
	if u := (DiffInput{From: "2026-09-27", To: "2026-09-28T10-00-00Z"}).Validate(); u != nil {
		t.Errorf("good times refused: %v", u)
	}
	if _, err := SnapshotDiff(context.Background(), Env{}, DiffInput{}); !errors.Is(err, errNoInventory) {
		t.Errorf("no inventory: %v", err)
	}
	env := diffLab(t)
	env.Store = nil
	if _, err := SnapshotDiff(context.Background(), env, DiffInput{}); !errors.Is(err, errNoStore) {
		t.Errorf("no store: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SnapshotDiff(ctx, diffLab(t), DiffInput{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// A diff of a snapshot without a configuration says so; one that cannot be read
// is a failed load.
func TestConfigGap(t *testing.T) {
	t.Parallel()
	with := store.Snapshot{Device: "fw01", ID: "a", Dir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(with.Dir, store.ConfigDoc+".xml"), []byte("<config"), 0o600); err != nil {
		t.Fatal(err)
	}
	without := store.Snapshot{Device: "fw01", ID: "b", Dir: t.TempDir()}
	if got := configGap(with, without); got != "gap.config-missing" {
		t.Errorf("without: %s", got)
	}
	if got := configGap(with, with); got != "gap.load-failed" {
		t.Errorf("with: %s", got)
	}
}

// Two snapshots of different content versions give a note; equal versions,
// or a snapshot without one, give none (spec 2026-10-16 §5.3). The newer
// version's file is built here: no binary fixture is committed (D15).
func TestDiffNotesTheContentVersion(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		older, newer string
		want         bool
	}{{"8000-1000", "8001-1001", true}, {"8000-1000", "8000-1000", false}, {"", "8001-1001", false}} {
		l := newLab(t)
		for _, v := range []string{tc.older, tc.newer} {
			if v == "" {
				continue
			}
			if err := l.st.WriteContent(v, contentOf(t, v)); err != nil {
				t.Fatal(err)
			}
		}
		l.write(store.Meta{Device: "fw01", AppVersion: tc.older}, pathlab.Read(t, fixture("firewall-lab.xml")))
		l.write(store.Meta{Device: "fw01", AppVersion: tc.newer}, pathlab.Read(t, fixture("firewall-lab-changed.xml")))
		e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
		if err != nil {
			t.Fatal(err)
		}
		n, ok := noteWith(e.Notes, "note.app-version-changed")
		if ok != tc.want || ok && (n.Note != "content version 8000-1000 → 8001-1001" || n.Device != "fw01") {
			t.Errorf("%s → %s: notes %+v", tc.older, tc.newer, e.Notes)
		}
	}
}

// Two snapshots whose configurations come from different sources give a note:
// across the switch from the export to the running configuration and its
// template, template values show as added once. A snapshot without the key
// exported its configuration (spec 2026-10-17 §2.4).
func TestDiffNotesTheConfigSourceChange(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		older, newer string
		want         string
	}{
		{"", "running+template", "configuration source export → running+template"},
		{"export", "running+template", "configuration source export → running+template"},
		{"running", "running+template", "configuration source running → running+template"},
		{"running+template", "running+template", ""},
		{"", "export", ""},
	} {
		l := newLab(t)
		l.write(store.Meta{Device: "fw01", ConfigSource: tc.older}, pathlab.Read(t, fixture("firewall-lab.xml")))
		l.write(store.Meta{Device: "fw01", ConfigSource: tc.newer}, pathlab.Read(t, fixture("firewall-lab-merged.xml")))
		e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
		if err != nil {
			t.Fatal(err)
		}
		n, ok := noteWith(e.Notes, "note.config-source-changed")
		if ok != (tc.want != "") || ok && (!strings.HasPrefix(n.Note, tc.want+": ") || n.Device != "fw01") {
			t.Errorf("%q → %q: notes %+v", tc.older, tc.newer, e.Notes)
		}
	}
}

// identityFixture is the identity fixture as a file whose lists the caller
// may change.
func identityFixture(t *testing.T) identity.File {
	t.Helper()
	d, err := identity.Read(bytes.NewReader(identityGzip(t)))
	if err != nil {
		t.Fatal(err)
	}
	f := d.File()
	f.Sources.LDAP = slices.Clone(f.Sources.LDAP)
	f.Users = slices.Clone(f.Users)
	for i := range f.Users {
		f.Users[i].Groups = slices.Clone(f.Users[i].Groups)
	}
	f.Mappings = slices.Clone(f.Mappings)
	f.PartsMissing = slices.Clone(f.PartsMissing)
	return f
}

// encodeIdentity is a file as a fetch stores it.
func encodeIdentity(t *testing.T, f identity.File) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := identity.Encode(&b, f); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// diffWithIdentity diffs two snapshots of fw01 with these identity files; nil is
// a snapshot without one.
func diffWithIdentity(t *testing.T, older, newer []byte) Envelope[DiffInput, DiffResult] {
	t.Helper()
	l := newLab(t)
	cfg := pathlab.Read(t, fixture("firewall-lab.xml"))
	l.writeWith(store.Meta{Device: "fw01"}, cfg, older)
	l.writeWith(store.Meta{Device: "fw01"}, cfg, newer)
	e, err := SnapshotDiff(context.Background(), l.env(), DiffInput{Selection: Selection{Device: []string{"fw01"}}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// identityResult is the result of the scope identity, if there is one.
func identityResult(e Envelope[DiffInput, DiffResult]) (DiffResult, bool) {
	i := slices.IndexFunc(e.Results, func(r DiffResult) bool { return r.Scope == "identity" })
	if i < 0 {
		return DiffResult{}, false
	}
	return e.Results[i], true
}

// With identity data in both snapshots, the diff has one result of the scope
// identity: a user that gained a group, and a source whose group count
// changed. The mappings changed too, and no mapping change shows (spec
// 2026-10-17 §6.3, D9).
func TestDiffUserGroupChanges(t *testing.T) {
	t.Parallel()
	before := identityFixture(t)
	after := identityFixture(t)
	after.Users[0].Groups = append(after.Users[0].Groups, "team-x") // example.com\alice
	after.Sources.LDAP[0].Groups = 4
	after.Mappings = append(after.Mappings[1:], identity.Mapping{IP: netip.MustParseAddr("198.51.100.20"), User: `example.com\bob`, Type: "XMLAPI", Timeout: 100})
	e := diffWithIdentity(t, encodeIdentity(t, before), encodeIdentity(t, after))
	r, ok := identityResult(e)
	if !ok {
		t.Fatalf("no identity result in %+v", e.Results)
	}
	want := []drift.Change{
		{Op: drift.Changed, Kind: "identity source", Name: "ldap:example.com", Fields: []drift.FieldChange{{Path: "groups", Old: "3", New: "4"}}},
		{Op: drift.Changed, Kind: "identity user", Name: `example.com\alice`, Fields: []drift.FieldChange{{Path: "group", New: "team-x"}}},
	}
	if !slices.EqualFunc(r.Changes, want, sameChange) {
		t.Errorf("changes %+v, want %+v", r.Changes, want)
	}
	if r.Device != "fw01" || r.Answer != "fw01/identity: 0 added, 0 removed, 2 changed" || e.Summary.Found < 2 || e.Summary.With != 1 {
		t.Errorf("result %+v, summary %+v", r, e.Summary)
	}
	same := diffWithIdentity(t, encodeIdentity(t, before), encodeIdentity(t, before))
	if r, ok := identityResult(same); !ok || r.Changes == nil || len(r.Changes) != 0 {
		t.Errorf("no change: %+v", r)
	}
}

func sameChange(a, b drift.Change) bool {
	return a.Op == b.Op && a.Kind == b.Kind && a.Name == b.Name && a.Old == b.Old && a.New == b.New && slices.Equal(a.Fields, b.Fields)
}

// identityChanges reads each change of identity.Diff as a drift change: a
// user that came or went with its groups, and a source with its line.
func TestIdentityChangesOfUsersAndSources(t *testing.T) {
	t.Parallel()
	before := identityFixture(t)
	after := identityFixture(t)
	after.Users = append(after.Users[1:], identity.User{Name: `example.com\eve`, Groups: []string{"team-x", "engineering"}})
	after.Users[0].Groups = after.Users[0].Groups[1:] // example.com\bob leaves domain users
	after.Sources.LDAP = append(after.Sources.LDAP, identity.LDAPSource{Name: "branch", Domain: "example.com", Base: "ou=branch,dc=example,dc=com", Groups: 1})
	got := identityChanges(identity.New(before), identity.New(after))
	want := []drift.Change{
		{Op: drift.Added, Kind: "identity source", Name: "ldap:branch", New: "domain=example.com base=ou=branch,dc=example,dc=com groups=1"},
		{Op: drift.Removed, Kind: "identity user", Name: `example.com\alice`, Old: "cn=domain users,cn=users,dc=example,dc=com; cn=payroll,ou=groups,dc=example,dc=com"},
		{Op: drift.Changed, Kind: "identity user", Name: `example.com\bob`, Fields: []drift.FieldChange{{Path: "group", Old: "cn=domain users,cn=users,dc=example,dc=com"}}},
		{Op: drift.Added, Kind: "identity user", Name: `example.com\eve`, New: "engineering; team-x"},
	}
	if !slices.EqualFunc(got, want, sameChange) {
		t.Errorf("changes:\n%+v\nwant:\n%+v", got, want)
	}
	if got := identityChanges(nil, identity.New(after)); got != nil {
		t.Errorf("one side: %+v", got)
	}
}

// With identity data in one snapshot only, the diff has no identity result
// and notes it (SG8). With none, there is neither. A part missing in either
// snapshot is not compared, and the note names the part (PD19).
func TestDiffWithOneIdentityFileNotes(t *testing.T) {
	t.Parallel()
	data := encodeIdentity(t, identityFixture(t))
	for _, tc := range []struct {
		name         string
		older, newer []byte
		note, result bool
		mentions     string
	}{
		{"older without", nil, data, true, false, "2026-"},
		{"newer without", data, nil, true, false, "2026-"},
		{"neither", nil, nil, false, false, ""},
	} {
		e := diffWithIdentity(t, tc.older, tc.newer)
		n, noted := noteWith(e.Notes, "note.identity-not-compared")
		_, result := identityResult(e)
		if noted != tc.note || result != tc.result || noted && (n.Device != "fw01" || !strings.Contains(n.Note, tc.mentions)) {
			t.Errorf("%s: notes %+v, results %+v", tc.name, e.Notes, e.Results)
		}
	}
	partial := identityFixture(t)
	partial.PartsMissing = []string{identity.PartUserGroups}
	e := diffWithIdentity(t, data, encodeIdentity(t, partial))
	n, noted := noteWith(e.Notes, "note.identity-not-compared")
	if _, result := identityResult(e); !noted || !result || !strings.Contains(n.Note, identity.PartUserGroups) {
		t.Errorf("a part missing: notes %+v, results %+v", e.Notes, e.Results)
	}
}
