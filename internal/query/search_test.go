package query

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/kaisero/proteus/internal/estate"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/search"
	"github.com/kaisero/proteus/internal/simulate"
)

// labStore is fw01 with the lab configuration, and fw02 with none.
func labStore(t *testing.T) Env {
	t.Helper()
	l := newLab(t)
	l.fetch("fw01", fixture("firewall-lab.xml"))
	return l.env()
}

// A search over the store: findings with their target, the targets read, and a
// summary that counts targets with and without findings and the holes.
func TestSearchTheStore(t *testing.T) {
	t.Parallel()
	e, err := Search(context.Background(), labStore(t), SearchInput{Term: "198.18.10.100"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Command != "search" || len(e.Results) == 0 || len(e.Targets) == 0 || e.Summary == nil ||
		e.Summary.Found != len(e.Results) || e.Summary.With != 1 || e.Summary.With+e.Summary.Without != len(e.Targets) {
		t.Fatalf("%+v %+v", e.Summary, e.Holes)
	}
	if len(e.Holes) != 1 || e.Holes[0].Device != "fw02" {
		t.Errorf("holes: %+v", e.Holes)
	}
	r := e.Results[0]
	if r.Device != "fw01" || r.Snapshot == "" || e.Targets[r.TargetIndex].Device != "fw01" || r.Scope == "" {
		t.Errorf("finding: %+v", r)
	}
	if e.Input.Matching() != "covers" {
		t.Errorf("matching %s", e.Input.Matching())
	}
}

// A file search with a mode, kinds and stages; a term within cannot read is a
// usage error.
func TestSearchAFile(t *testing.T) {
	t.Parallel()
	in := SearchInput{Term: "10.0.0.0/8", Mode: "within", Show: []string{"objects", "groups"}, Selection: Selection{File: fixture("firewall-lab.xml")}}
	e, err := Search(context.Background(), Env{}, in)
	if err != nil || e.Summary.With+e.Summary.Without != len(e.Targets) {
		t.Fatalf("%+v %v", e.Summary, err)
	}
	for _, r := range e.Results {
		if r.Stage != search.StageObject && r.Stage != search.StageGroup {
			t.Errorf("stage %s shown", r.Stage)
		}
	}
	in.Term = "web"
	_, err = Search(context.Background(), Env{}, in)
	usageOK(t, err, "--within: search: within mode needs")
	if !errors.Is(err, search.ErrWithinNeedsAddress) {
		t.Errorf("%v", err)
	}
	// Identity data that does not load is no error: the search is as
	// without it, with a note (spec 2026-10-17 §4.2, PD11).
	user := SearchInput{Term: `example.com\carol`, Selection: in.Selection}
	if e, err := Search(context.Background(), Env{Identity: failingIdentity{}}, user); err != nil || !hasNote(e.Notes, "gap.no-user-directory") {
		t.Errorf("identity: %v, notes %+v", err, e.Notes)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Search(ctx, Env{}, in); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

// Search refuses an unknown mode or stage and the store's selectors with a file.
func TestSearchInputRules(t *testing.T) {
	t.Parallel()
	file := Selection{File: fixture("firewall-lab.xml")}
	for _, tc := range []struct {
		in   SearchInput
		want string
	}{
		{SearchInput{Term: "x", Mode: "fuzzy"}, `mode "fuzzy": want exact, within or contains`},
		{SearchInput{Term: "x", Show: []string{"rules"}}, `--show "rules": want objects, identity, groups, refs or literals`},
		{SearchInput{Term: "x", Selection: Selection{File: file.File, Device: []string{"fw01"}}}, "--device selects from the store"},
		{SearchInput{Term: "x", Selection: Selection{File: file.File, Fresh: true}}, "--fresh selects from the store"},
	} {
		_, err := Search(context.Background(), Env{}, tc.in)
		usageOK(t, err, tc.want)
	}
}

// An unknown kind is one usage error before any target runs, with the kinds the
// configurations know, sorted; a kind any selected configuration knows passes.
func TestSearchRefusesAnUnknownKind(t *testing.T) {
	t.Parallel()
	file := Selection{File: fixture("firewall-lab.xml")}
	_, err := Search(context.Background(), Env{}, SearchInput{Term: "web", Kinds: []string{"addr", "servce", "zz-none"}, Selection: file})
	usageOK(t, err, `--kind "addr": did you mean address, address-group?`)
	u, _ := errors.AsType[*UsageError](err)
	lines := strings.Split(u.Text, "\n")
	if len(lines) != 4 || lines[1] != `--kind "servce": did you mean service?` ||
		lines[2] != `--kind "zz-none": no kind is close` || !strings.HasPrefix(lines[3], "known kinds: ") {
		t.Fatalf("text %q", u.Text)
	}
	kinds := strings.Split(strings.TrimPrefix(lines[3], "known kinds: "), ", ")
	if !slices.IsSorted(kinds) || !slices.Contains(kinds, "address") || !slices.Contains(kinds, "service") {
		t.Errorf("kinds %q", lines[3])
	}
	if want := strings.ReplaceAll(u.Text, "--kind", "kind"); u.ToolText != want {
		t.Errorf("tool text %q, want %q", u.ToolText, want)
	}
	// The store has two targets on fw01 and a hole on fw02: still one error.
	_, err = Search(context.Background(), labStore(t), SearchInput{Term: "web", Kinds: []string{"address", "addr"}})
	usageOK(t, err, `--kind "addr"`)
	e, err := Search(context.Background(), labStore(t), SearchInput{Term: "198.18.10.100", Kinds: []string{"address"}})
	if err != nil || len(e.Results) == 0 {
		t.Fatalf("a known kind: %v %+v", err, e.Summary)
	}
}

// The closest kinds come first, at most five; a case slip is no edit.
func TestNearKinds(t *testing.T) {
	t.Parallel()
	known := map[string]bool{"address": true, "address-group": true, "service": true, "tag": true, "zone": true}
	for in, want := range map[string]string{
		"Service": "service", "tags": "tag", "addr": "address, address-group", "xyz": "", "zon": "zone", "tg": "tag",
	} {
		if got := strings.Join(nearKinds(in, known), ", "); got != want {
			t.Errorf("nearKinds(%q) = %q, want %q", in, got, want)
		}
	}
	many := map[string]bool{"a1": true, "a2": true, "a3": true, "a4": true, "a5": true, "a6": true}
	if got := nearKinds("a", many); len(got) != 5 || got[0] != "a1" {
		t.Errorf("nearKinds(a) = %v, want five", got)
	}
}

// A reference from the device's own configuration prints with scope config.
func TestSearchShowsDeviceLevelReferences(t *testing.T) {
	t.Parallel()
	e, err := Search(context.Background(), Env{}, SearchInput{Term: "10.88.5.1", Selection: Selection{File: fixture("firewall-device-refs.xml")}})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range e.Results {
		if r.Kind == "static-route" && r.Name == "to-remote" {
			found = r.Scope == "config" && r.Field == "destination"
		}
	}
	if !found {
		t.Errorf("no static-route reference with scope config: %+v", e.Results)
	}
}

// How a term is matched: the mode asked, or what its type sets.
func TestMatching(t *testing.T) {
	t.Parallel()
	for term, want := range map[string]string{"10.0.0.1": "covers", "tcp/443": "covers", "443": "covers", "10.0.0.0/8": "overlaps", "web": "matches"} {
		if got := (SearchInput{Term: term}).Matching(); got != want {
			t.Errorf("%s: %s, want %s", term, got, want)
		}
	}
	if got := (SearchInput{Term: "web", Mode: "contains"}).Matching(); got != "contains" {
		t.Errorf("mode: %s", got)
	}
}

// A finding's detail says where it was found.
func TestDetail(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		f    search.Finding
		want string
	}{
		{search.Finding{Stage: search.StageReference, Field: "source", Via: "g"}, "source -> g"},
		{search.Finding{Stage: search.StageLiteral, Field: "source", Via: "10.0.0.1"}, "source 10.0.0.1"},
		{search.Finding{Stage: search.StageObject, Via: "value"}, "value"},
	} {
		if got := Detail(tc.f); got != tc.want {
			t.Errorf("%s, want %s", got, tc.want)
		}
	}
}

// Every target note stays a note, with its device and vsys.
func TestTargetNotesKeepEveryNote(t *testing.T) {
	t.Parallel()
	tg := estate.Target{Device: "fw01", Vsys: "vsys1", Notes: simulate.Reasons{
		reason.New("note.snapshot-stale", "old"), reason.New("note.ha-peer", "peer"),
	}}
	notes := TargetNotes([]estate.Target{tg})
	if len(notes) != 2 || notes[0].Device != "fw01" || notes[1].Code != "note.ha-peer" {
		t.Errorf("notes %+v", notes)
	}
}

// The store's selection: by label, at a time, none matching, with a fresh fetch
// whose notes land on its device, and without what it needs.
func TestTargets(t *testing.T) {
	t.Parallel()
	env := labStore(t)
	ctx := context.Background()
	if ts, _, err := Targets(ctx, env, Selection{Label: []string{"site=s1"}}); err != nil || len(ts) == 0 || ts[0].Device != "fw01" {
		t.Errorf("label: %v %v", ts, err)
	}
	if ts, holes, err := Targets(ctx, env, Selection{Device: []string{"fw01"}, At: "2026-01-01"}); err != nil || len(ts) != 0 || len(holes) != 1 {
		t.Errorf("at: %v %v %v", ts, holes, err)
	}
	_, _, err := Targets(ctx, env, Selection{Label: []string{"site=nowhere"}})
	usageOK(t, err, "the selection matches no device")
	_, _, err = Targets(ctx, env, Selection{Label: []string{"bad"}})
	usageOK(t, err, `label "bad" must be key=value`)
	_, _, err = Targets(ctx, env, Selection{At: "tuesday"})
	usageOK(t, err, `--at "tuesday"`)
	_, _, err = Targets(ctx, env, Selection{Fresh: true})
	usageOK(t, err, "--fresh: this front end does not fetch")

	tls := reason.New("note.tls-off", "TLS certificate verification is off (insecure_tls)")
	env.Fresh = func(_ context.Context, names []string) (map[string][]reason.Reason, error) {
		return map[string][]reason.Reason{names[0]: {tls}}, nil
	}
	ts, _, err := Targets(ctx, env, Selection{Device: []string{"fw01"}, Fresh: true})
	if err != nil || len(ts) == 0 || ts[0].Notes[len(ts[0].Notes)-1] != tls {
		t.Errorf("fresh: %+v %v", ts, err)
	}
	env.Fresh = func(context.Context, []string) (map[string][]reason.Reason, error) {
		return nil, errors.New("fetch broke")
	}
	if _, _, err := Targets(ctx, env, Selection{Fresh: true}); err == nil || err.Error() != "fetch broke" {
		t.Errorf("fresh error: %v", err)
	}
	if _, _, err := Targets(ctx, Env{}, Selection{}); !errors.Is(err, errNoInventory) {
		t.Errorf("no inventory: %v", err)
	}
	env.Store = nil
	if _, _, err := Targets(ctx, env, Selection{}); !errors.Is(err, errNoStore) {
		t.Errorf("no store: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := Targets(cancelled, env, Selection{}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
	if _, _, err := Targets(ctx, Env{}, Selection{File: fixture("absent.xml")}); err == nil || !strings.Contains(err.Error(), "absent.xml") {
		t.Errorf("absent file: %v", err)
	}
}

// A prefix search cannot decide a wildcard object; the envelope lists it as
// unresolved for the target it came from (decision C1).
func TestSearchListsAWildcardAsUnresolved(t *testing.T) {
	t.Parallel()
	e, err := Search(context.Background(), Env{}, SearchInput{Term: "10.88.0.0/16", Selection: Selection{File: fixture("firewall-wildcard.xml")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Unresolved) != 1 || e.Unresolved[0].Value != "wc" || e.Unresolved[0].Code != "gap.address-wildcard" ||
		e.Unresolved[0].Vsys != "vsys1" {
		t.Errorf("unresolved: %+v", e.Unresolved)
	}
}

// A term in any case finds the application: the search runs on the canonical
// name, and the findings name it (spec 2026-10-16 P14, D17). The answer names
// the content file it used.
func TestSearchFindsAnApplicationInAnyCase(t *testing.T) {
	t.Parallel()
	path := appFile(t, true)
	e, err := Search(context.Background(), Env{}, SearchInput{Term: "SSL", Selection: Selection{File: path}})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range e.Results {
		lines = append(lines, string(r.Stage)+" "+r.Kind+" "+r.Name+" "+r.Via)
	}
	got := strings.Join(lines, "\n")
	for _, want := range []string{
		"object application ssl predefined",
		"group application-group outer holds outer > inner > ssl",
		"reference security rule allow-outer outer",
		"reference security rule allow-remote implicit use by app-remote",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if n, ok := noteWith(e.Notes, "note.app-data-file"); !ok || !strings.Contains(n.Note, "8000-1000") {
		t.Errorf("notes %+v", e.Notes)
	}
	// A custom application takes its name as configured.
	e, err = Search(context.Background(), Env{}, SearchInput{Term: "erp-mixed", Selection: Selection{File: path}})
	if err != nil || !slices.ContainsFunc(e.Results, func(f Finding) bool { return f.Name == "Erp-Mixed" && f.Via == "name" }) {
		t.Errorf("erp-mixed: %+v %v", e.Results, err)
	}
}

// Only a term with the shape of a name loads the data (D11): an address or a
// port does not, so its answer carries no note. A name without the file says
// the data is missing.
func TestSearchLoadsDataForANameOnly(t *testing.T) {
	t.Parallel()
	for _, term := range []string{"10.1.0.5", "443", "tcp/443", "10.1.0.0/24"} {
		e, err := Search(context.Background(), Env{}, SearchInput{Term: term, Selection: Selection{File: appFile(t, true)}})
		if err != nil || len(e.Notes) != 0 {
			t.Errorf("%s: notes %+v %v", term, e.Notes, err)
		}
	}
	e, err := Search(context.Background(), Env{}, SearchInput{Term: "ssl", Selection: Selection{File: appFile(t, false)}})
	if n, ok := noteWith(e.Notes, "note.app-data-missing"); err != nil || !ok || !strings.Contains(n.Note, "does not exist") || len(e.Results) != 0 {
		t.Errorf("without the file: %+v %+v %v", e.Results, e.Notes, err)
	}
}

func TestNameShaped(t *testing.T) {
	t.Parallel()
	for term, want := range map[string]bool{
		"ssl": true, "Erp-Mixed": true, "f-media": true, "10.1.0.5": false, "10.0.0.0/8": false,
		"443": false, "udp/53": false, "a b": false, "x/y": false, "10.1.0.1-10.1.0.9": false,
	} {
		if got := nameShaped(term); got != want {
			t.Errorf("%q: %v, want %v", term, got, want)
		}
	}
}

// A UPN term finds the user by its primary name, its two groups with their
// source, its mapped address, and every rule that names the user or a group,
// in any form (spec 2026-10-17 §6.1, N2, M11, M12). A group shows once: the
// object stage shows each group that a rule names, so the identity stage
// adds none of them again.
func TestSearchAUserByUPN(t *testing.T) {
	t.Parallel()
	e := searchFile(t, Env{}, identityConfig(t, "firewall-identity.xml", identityGzip(t)), "alice@example.com")
	got := answers(e)
	for _, want := range []string{
		`file/vsys1: user example.com\alice | example.com\alice`,
		"file/vsys1: user-group cn=domain users,cn=users,dc=example,dc=com | ldap:example.com, 3 members",
		"file/vsys1: user-group cn=payroll,ou=groups,dc=example,dc=com | ldap:example.com, 1 member",
		`file/vsys1: mapping 198.51.100.11 | user example.com\alice, XMLAPI, timeout 14400 s`,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, strings.Join(got, "\n"))
		}
	}
	rules := ruleFindings(e)
	for _, want := range []string{"u-user", "u-upn", "u-ldap-group", "u-multi", "u-dn-case", "u-short"} {
		if !rules[want] {
			t.Errorf("no rule %s in %v", want, rules)
		}
	}
	for _, f := range e.Results {
		if f.Stage == search.StageIdentity && f.Kind != search.KindMapping {
			t.Errorf("the object stage shows alice and her groups; the identity stage shows %s %s again", f.Kind, f.Name)
		}
	}
	if slices.Contains(got, `file/vsys1: mapping 198.51.100.10 | user example\alice, XMLAPI, timeout 14400 s`) {
		t.Error("a mapping stored as example\\alice is no mapping of example.com\\alice (M2)")
	}
}

// A group DN with spaces and commas is a user term once the data knows it
// (Review focus 5): search finds the group with its 3 members and the rule
// u-ldap-group, and the rules that name it in another form.
func TestSearchFindsAGroupDNWithSpaces(t *testing.T) {
	t.Parallel()
	e := searchFile(t, Env{}, identityConfig(t, "firewall-identity.xml", identityGzip(t)), "cn=domain users,cn=users,dc=example,dc=com")
	if got := answers(e); !slices.Contains(got, "file/vsys1: user-group cn=domain users,cn=users,dc=example,dc=com | ldap:example.com, 3 members") {
		t.Errorf("no group with 3 members in:\n%s", strings.Join(got, "\n"))
	}
	rules := ruleFindings(e)
	for _, want := range []string{"u-ldap-group", "u-dn-case", "u-short"} {
		if !rules[want] {
			t.Errorf("no rule %s in %v", want, rules)
		}
	}
}

// One address finds its mapped user; --show identity keeps that stage only;
// --kind takes the kinds of the stage identity (spec 2026-10-17 §6.1).
func TestSearchShowsTheIdentityStage(t *testing.T) {
	t.Parallel()
	path := identityConfig(t, "firewall-identity.xml", identityGzip(t))
	e := searchFile(t, Env{}, path, "198.51.100.10")
	if got := answers(e); !slices.Equal(got, []string{`file/vsys1: mapping 198.51.100.10 | user example\alice, XMLAPI, timeout 14400 s`}) {
		t.Errorf("198.51.100.10:\n%s", strings.Join(got, "\n"))
	}
	e, err := Search(context.Background(), Env{}, SearchInput{Term: `example.com\carol`, Show: []string{"identity"}, Selection: Selection{File: path}})
	if err != nil || len(e.Results) == 0 {
		t.Fatalf("--show identity: %v, %+v", err, e.Results)
	}
	for _, f := range e.Results {
		if f.Stage != search.StageIdentity {
			t.Errorf("--show identity: %s %s", f.Stage, f.Name)
		}
	}
	e, err = Search(context.Background(), Env{}, SearchInput{
		Term: `example.com\carol`, Kinds: []string{"identity-user", "identity-group", "mapping"}, Selection: Selection{File: path},
	})
	if err != nil || !slices.Contains(answers(e), `file/vsys1: identity-user example.com\carol | directory user`) {
		t.Errorf("--kind of the identity stage: %v, %+v", err, e.Results)
	}
	for _, f := range e.Results {
		if f.Stage != search.StageIdentity {
			t.Errorf("--kind of the identity stage: %s %s %s", f.Stage, f.Kind, f.Name)
		}
	}
}
