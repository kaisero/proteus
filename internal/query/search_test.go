package query

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/index"
	"github.com/okaiser/proteus/internal/reason"
	"github.com/okaiser/proteus/internal/search"
	"github.com/okaiser/proteus/internal/simulate"
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
	env := Env{Users: func() (index.UserDirectory, error) { return nil, errors.New("PROTEUS_USERS: unreadable") }}
	if _, err := Search(context.Background(), env, in); err == nil || err.Error() != "PROTEUS_USERS: unreadable" {
		t.Errorf("users: %v", err)
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
		{SearchInput{Term: "x", Show: []string{"rules"}}, `--show "rules": want objects, groups, refs or literals`},
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
	_, err := Search(context.Background(), Env{}, SearchInput{Term: "web", Kinds: []string{"addr"}, Selection: file})
	usageOK(t, err, `--kind "addr": want one of `)
	u, _ := errors.AsType[*UsageError](err)
	list := strings.TrimPrefix(u.Text, `--kind "addr": want one of `)
	kinds := strings.Split(list, ", ")
	if !slices.IsSorted(kinds) || !slices.Contains(kinds, "address") || !slices.Contains(kinds, "service") {
		t.Errorf("kinds %q", list)
	}
	if u.ToolText != `kind "addr": want one of `+list {
		t.Errorf("tool text %q", u.ToolText)
	}
	// The store has two targets on fw01 and a hole on fw02: still one error.
	_, err = Search(context.Background(), labStore(t), SearchInput{Term: "web", Kinds: []string{"address", "addr"}})
	usageOK(t, err, `--kind "addr"`)
	e, err := Search(context.Background(), labStore(t), SearchInput{Term: "198.18.10.100", Kinds: []string{"address"}})
	if err != nil || len(e.Results) == 0 {
		t.Fatalf("a known kind: %v %+v", err, e.Summary)
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

// A version gap is unresolved by its code, not by its text: a note that reads
// the same with another code stays a note.
func TestTargetQualifiersUseTheCode(t *testing.T) {
	t.Parallel()
	gap := "the configuration is PAN-OS 12.2.0"
	tg := estate.Target{Device: "fw01", Vsys: "vsys1", Notes: simulate.Reasons{
		reason.New("gap.version", gap), reason.New("note.ha-peer", gap),
	}}
	un, notes := TargetQualifiers([]estate.Target{tg})
	if len(un) != 1 || un[0].Code != "gap.version" || len(notes) != 1 || notes[0].Code != "note.ha-peer" {
		t.Errorf("unresolved %+v, notes %+v", un, notes)
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
