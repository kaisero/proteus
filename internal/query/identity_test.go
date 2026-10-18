package query

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/okaiser/proteus/internal/estate"
	"github.com/okaiser/proteus/internal/identity"
	"github.com/okaiser/proteus/internal/resolve"
	"github.com/okaiser/proteus/internal/search"
	"github.com/okaiser/proteus/internal/simulate/pathlab"
	"github.com/okaiser/proteus/internal/store"
	"github.com/okaiser/proteus/internal/testconfig"
)

// identityTakenAt is the taken_at of the identity fixture.
var identityTakenAt = time.Date(2026, 10, 17, 20, 0, 0, 0, time.UTC)

// identityGzip is the identity fixture as a fetch stores it: gzip JSON.
func identityGzip(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), identity.FileName)
	testconfig.Identity(t, p)
	return pathlab.Read(t, p)
}

// gzipped is raw as a gzip file.
func gzipped(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// identityConfig copies a configuration fixture into a new directory and
// returns its path; with data, data is the identity file beside it.
func identityConfig(t *testing.T, config string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.xml")
	if err := os.WriteFile(path, pathlab.Read(t, fixture(config)), 0o600); err != nil {
		t.Fatal(err)
	}
	if data != nil {
		if err := os.WriteFile(filepath.Join(dir, estate.IdentityFile), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// countingIdentity loads from disk and counts the loads of each path.
type countingIdentity struct {
	mu    sync.Mutex
	loads map[string]int
}

func newCountingIdentity() *countingIdentity { return &countingIdentity{loads: map[string]int{}} }

func (c *countingIdentity) Identity(path string) (*identity.Data, error) {
	c.mu.Lock()
	c.loads[path]++
	c.mu.Unlock()
	return estate.DiskIdentity{}.Identity(path)
}

// failingIdentity is a source whose every load fails.
type failingIdentity struct{}

func (failingIdentity) Identity(string) (*identity.Data, error) {
	return nil, errors.New("identity: unreadable")
}

// total is the number of loads, of every path.
func (c *countingIdentity) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, l := range c.loads {
		n += l
	}
	return n
}

// searchFile searches one configuration file.
func searchFile(t *testing.T, env Env, path, term string) Envelope[SearchInput, Finding] {
	t.Helper()
	e, err := Search(context.Background(), env, SearchInput{Term: term, Selection: Selection{File: path}})
	if err != nil {
		t.Fatalf("search %s: %v", term, err)
	}
	return e
}

// ruleFindings names the rules the references of a search found.
func ruleFindings(e Envelope[SearchInput, Finding]) map[string]bool {
	out := map[string]bool{}
	for _, f := range e.Results {
		if f.Stage == search.StageReference && f.Kind == "security rule" {
			out[f.Name] = true
		}
	}
	return out
}

// hasNote says whether the notes hold one of a code.
func hasNote(ns []Note, code string) bool {
	_, ok := noteWith(ns, code)
	return ok
}

// answers are the findings of a search as lines, to compare two answers.
func answers(e Envelope[SearchInput, Finding]) []string {
	out := make([]string, 0, len(e.Results))
	for _, f := range e.Results {
		out = append(out, f.Answer+" | "+Detail(f.Finding))
	}
	return out
}

// A --file question reads identity.json.gz beside the configuration, and
// note.identity-file names it: nothing checks that the file belongs to the
// configuration (spec 2026-10-17 §7). A file older than max_snapshot_age adds
// gap.user-directory-stale (§5.7).
func TestFileIdentityNotes(t *testing.T) {
	t.Parallel()
	path := identityConfig(t, "firewall-identity.xml", identityGzip(t))
	file := filepath.Join(filepath.Dir(path), estate.IdentityFile)
	env := func(age, maxAge time.Duration) Env {
		return Env{Now: func() time.Time { return identityTakenAt.Add(age) }, MaxAge: maxAge}
	}
	e := searchFile(t, env(time.Hour, 24*time.Hour), path, `example.com\carol`)
	n, ok := noteWith(e.Notes, "note.identity-file")
	if !ok || !strings.Contains(n.Note, file) || !strings.Contains(n.Note, "2026-10-17T20:00:00Z") {
		t.Errorf("notes %+v", e.Notes)
	}
	if _, ok := noteWith(e.Notes, "gap.user-directory-stale"); ok {
		t.Errorf("a file of an hour is fresh: %+v", e.Notes)
	}
	e = searchFile(t, env(48*time.Hour, 24*time.Hour), path, `example.com\carol`)
	if n, ok := noteWith(e.Notes, "gap.user-directory-stale"); !ok || !strings.Contains(n.Note, file) {
		t.Errorf("notes %+v", e.Notes)
	}
	if e := searchFile(t, env(48*time.Hour, 0), path, `example.com\carol`); hasNote(e.Notes, "gap.user-directory-stale") {
		t.Errorf("no age limit, no stale note: %+v", e.Notes)
	}
	// simulate policy reads the file beside too.
	p, err := PolicyFile(context.Background(), env(time.Hour, 24*time.Hour), PolicyFileInput{
		Flow:      FlowInput{Source: "198.51.100.11", Destination: "192.0.2.11", Port: "443", User: `example.com\alice`},
		Selection: Selection{File: path},
	})
	if n, ok := noteWith(p.Notes, "note.identity-file"); err != nil || !ok || !strings.Contains(n.Note, file) {
		t.Errorf("%v: notes %+v", err, p.Notes)
	}
}

// A file that does not load is as no file: the answer is the answer without
// data, a note gap.no-user-directory names the cause, and nothing fails
// (spec 2026-10-17 §4.2, PD11, Review focus 1).
func TestADamagedIdentityFileIsNoDirectory(t *testing.T) {
	t.Parallel()
	good := identityGzip(t)
	raw := pathlab.Read(t, "../../testdata/identity/identity.json")
	none := searchFile(t, Env{}, identityConfig(t, "firewall-identity.xml", nil), `example.com\carol`)
	for _, code := range []string{"gap.no-user-directory", "note.identity-file"} {
		if hasNote(none.Notes, code) {
			t.Fatalf("a file without identity.json.gz beside it has no identity note: %+v", none.Notes)
		}
	}
	for _, tc := range []struct {
		name string
		data []byte
		says string
	}{
		{"truncated", good[:len(good)/2], "damaged"},
		{"bad JSON", gzipped(t, []byte("{")), "JSON"},
		{"format 2", gzipped(t, bytes.Replace(raw, []byte(`"format": 1`), []byte(`"format": 2`), 1)), "format 2"},
	} {
		path := identityConfig(t, "firewall-identity.xml", tc.data)
		file := filepath.Join(filepath.Dir(path), estate.IdentityFile)
		e := searchFile(t, Env{}, path, `example.com\carol`)
		if !slices.Equal(answers(e), answers(none)) {
			t.Errorf("%s: findings %v, want %v", tc.name, answers(e), answers(none))
		}
		if n, ok := noteWith(e.Notes, "gap.no-user-directory"); !ok || !strings.Contains(n.Note, file) || !strings.Contains(n.Note, tc.says) {
			t.Errorf("%s: notes %+v", tc.name, e.Notes)
		}
		p, err := PolicyFile(context.Background(), Env{}, PolicyFileInput{
			Flow:      FlowInput{Source: "198.51.100.11", Destination: "192.0.2.11", Port: "443", User: `example.com\alice`},
			Selection: Selection{File: path},
		})
		if _, ok := noteWith(p.Notes, "gap.no-user-directory"); err != nil || !ok || len(p.Results) != 1 {
			t.Errorf("%s: simulate: %v, notes %+v", tc.name, err, p.Notes)
		}
	}
}

// simulate policy loads the identity data only for a flow with --user or a
// vsys whose rules name a source-user other than any (spec 2026-10-17 §4.2,
// PD10). A mapped source is no reason: before the load nothing knows the
// mapping, and without a rule that names a user it decides nothing (SG9).
func TestSimulateLoadsIdentityOnlyWhenNeeded(t *testing.T) {
	t.Parallel()
	t.Run("file", func(t *testing.T) {
		t.Parallel()
		src := newCountingIdentity()
		env := Env{Identity: src}
		ask := func(config, source, destination, user string) {
			t.Helper()
			path := identityConfig(t, config, identityGzip(t))
			_, err := PolicyFile(context.Background(), env, PolicyFileInput{
				Flow: FlowInput{
					Source: source, Destination: destination, Port: "443", User: user,
					FromZone: "inside", ToZone: "outside",
				},
				Selection: Selection{File: path},
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		// firewall-appid.xml names no source-user. The data maps
		// 198.51.100.11 to alice.
		ask("firewall-appid.xml", "198.51.100.11", "10.2.0.5", "")
		if src.total() != 0 {
			t.Errorf("a mapped source, no user and no rule that names one: loads %v", src.loads)
		}
		ask("firewall-appid.xml", "198.51.100.11", "10.2.0.5", `example.com\alice`)
		if src.total() != 1 {
			t.Errorf("with --user: loads %v", src.loads)
		}
		ask("firewall-identity.xml", "198.51.100.11", "192.0.2.11", "")
		if src.total() != 2 {
			t.Errorf("rules that name users: loads %v", src.loads)
		}
	})
	t.Run("path", func(t *testing.T) {
		t.Parallel()
		l := newLab(t)
		l.writeWith(store.Meta{Device: "fw01", Host: "fw01.example.test"}, pathlab.Read(t, fixture("firewall-appid.xml")), identityGzip(t))
		l.writeWith(store.Meta{Device: "fw02", Host: "fw02.example.test"}, pathlab.Read(t, fixture("firewall-identity.xml")), identityGzip(t))
		for _, tc := range []struct {
			device   string
			withUser bool
			loads    int
		}{{"fw01", false, 0}, {"fw01", true, 1}, {"fw02", false, 1}} {
			src := newCountingIdentity()
			when := estate.When{Identity: src}
			load := storeLoader(l.st, when, estate.NewNetwork(l.st, nil, when), false, tc.withUser)
			tg, err := load(tc.device, "vsys1")
			if err != nil || src.total() != tc.loads || (tg.Providers.Users != nil) != (tc.loads == 1) {
				t.Errorf("%s, user %v: %v, loads %v, data %v", tc.device, tc.withUser, err, src.loads, tg.Providers.Users != nil)
			}
		}
		// simulate routing and nat judge no user: their loader reads no
		// identity file, also where a rule names a user.
		src := newCountingIdentity()
		when := estate.When{Identity: src}
		es := fetchedEstate{st: l.st, when: when, network: estate.NewNetwork(l.st, nil, when)}
		if tg, err := es.simEnv(Env{}).Load("fw02", "vsys1"); err != nil || src.total() != 0 || tg.Providers.Users != nil {
			t.Errorf("routing and nat: %v, loads %v", err, src.loads)
		}
	})
}

// search loads the identity data for a term that can name a user or a mapped
// address, or that a rule names as its source-user, and for any term the first
// search finds nothing for; a term that finds an object loads nothing (spec
// 2026-10-17 §4.2, PD10).
func TestSearchLoadsIdentityOnlyWhenNeeded(t *testing.T) {
	t.Parallel()
	path := identityConfig(t, "firewall-identity.xml", identityGzip(t))
	for _, tc := range []struct {
		term  string
		loads int
	}{
		{"web-server", 0},                                 // an address object
		{"198.51.100.10", 1},                              // one address
		{`example.com\carol`, 1},                          // a backslash
		{"alice@example.com", 1},                          // an at sign
		{"cn=domain users,cn=users,dc=example,dc=com", 1}, // a DN
		{"engineering", 1},                                // a source-user member of a rule
		{"ENGINEERING", 1},                                // in any case
		{"team-x", 1},                                     // no rule names it, and the first search finds nothing
	} {
		src := newCountingIdentity()
		searchFile(t, Env{Identity: src}, path, tc.term)
		if src.total() != tc.loads {
			t.Errorf("%s: loads %v, want %d", tc.term, src.loads, tc.loads)
		}
	}
}

// One question loads each identity file once, however many of its targets
// read it: the vsys of one snapshot, the vsys of one file. A second question
// loads it again: the memo is the question's (spec 2026-10-17 §4.2).
func TestIdentityLoadsOncePerQuestion(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.writeWith(store.Meta{Device: "fw01", Host: "fw01.example.test"}, pathlab.Read(t, fixture("firewall-multivsys.xml")), identityGzip(t))
	src := newCountingIdentity()
	env := l.env()
	env.Identity = src
	in := SearchInput{Term: `example.com\carol`, Selection: Selection{Device: []string{"fw01"}}}
	for want := 1; want <= 2; want++ {
		e, err := Search(context.Background(), env, in)
		if err != nil || len(e.Targets) < 2 || src.total() != want || len(src.loads) != 1 {
			t.Fatalf("question %d: %v, %d targets, loads %v", want, err, len(e.Targets), src.loads)
		}
		if _, ok := noteWith(e.Notes, "note.identity-file"); ok {
			t.Errorf("a snapshot's own file gets no file note: %+v", e.Notes)
		}
	}
	src = newCountingIdentity()
	e := searchFile(t, Env{Identity: src}, identityConfig(t, "firewall-multivsys.xml", identityGzip(t)), `example.com\carol`)
	if len(e.Targets) < 2 || src.total() != 1 {
		t.Errorf("a file: %d targets, loads %v", len(e.Targets), src.loads)
	}
}

// The load triggers of search, term by term: one address, a backslash, an at
// sign or an equals sign, or a source-user member of a rule in any case
// (PD10). namesUser holds for a rule that names a source-user other than any.
func TestTheIdentityLoadTriggers(t *testing.T) {
	t.Parallel()
	ts, _, err := estate.OpenFile(fixture("firewall-identity.xml"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := indexesOf(ts[0]).Index(ts[0].Scope, resolve.Security)
	if err != nil {
		t.Fatal(err)
	}
	rules := idx.Rules()
	for term, want := range map[string]bool{
		"198.51.100.10": true, "2001:db8::11": true, "198.51.100.0/24": false, "443": false,
		`other\ghost`: true, "bob@example.com": true, "cn=x": true,
		"dug-a": true, "DUG-AB": true, "local-admins": true, "known-user": true,
		"any": false, "web-server": false, "team-x": false,
	} {
		if got := searchNeedsIdentity(term, rules); got != want {
			t.Errorf("searchNeedsIdentity(%q) = %v", term, got)
		}
	}
	if !namesUser(rules) {
		t.Error("the fixture's rules name users")
	}
	apps, _, err := estate.OpenFile(fixture("firewall-appid.xml"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	idx, err = indexesOf(apps[0]).Index(apps[0].Scope, resolve.Security)
	if err != nil || namesUser(idx.Rules()) {
		t.Errorf("%v: firewall-appid.xml names no user", err)
	}
}

// A search term that names a user reads as its primary name, as --user does
// (spec 2026-10-17 §5.2, PD18): the UPN finds the rules of alice, not only the
// rule that names the UPN. A term that names an application stays the
// application.
func TestSearchReadsAUserTermAsItsPrimaryName(t *testing.T) {
	t.Parallel()
	path := identityConfig(t, "firewall-identity.xml", identityGzip(t))
	got := ruleFindings(searchFile(t, Env{}, path, "alice@example.com"))
	for _, want := range []string{"u-user", "u-upn", "u-ldap-group", "u-multi", "u-dn-case", "u-short"} {
		if !got[want] {
			t.Errorf("alice@example.com finds %v, not %s", got, want)
		}
	}
	ts, _, err := estate.OpenFile(fixture("firewall-appid.xml"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := identity.New(identity.File{Format: identity.Format, Users: []identity.User{{Name: `example.com\dave`, Alt: []string{"erp-custom", "dave@example.com"}}}})
	for term, want := range map[string]string{
		"erp-custom": "erp-custom", "ERP-MIXED": "ERP-MIXED", "DAVE@example.com": `example.com\dave`, "nobody": "nobody",
	} {
		if got := userTerm(ts[0], d, nil, term); got != want {
			t.Errorf("userTerm(%q) = %q, want %q", term, got, want)
		}
	}
	if got := userTerm(ts[0], nil, nil, "dave@example.com"); got != "dave@example.com" {
		t.Errorf("without data: %q", got)
	}
}

// A snapshot whose meta names an identity file that is gone has no identity
// data, and the note names the cause (spec 2026-10-17 §4.2, PD11).
func TestASnapshotWithoutItsIdentityFileNotesIt(t *testing.T) {
	t.Parallel()
	l := newLab(t)
	l.writeWith(store.Meta{Device: "fw01", Host: "fw01.example.test"}, pathlab.Read(t, fixture("firewall-identity.xml")), identityGzip(t))
	sn, err := l.st.Latest("fw01")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(sn.IdentityPath()); err != nil {
		t.Fatal(err)
	}
	e, err := Search(context.Background(), l.env(), SearchInput{Term: `example.com\carol`, Selection: Selection{Device: []string{"fw01"}}})
	if n, ok := noteWith(e.Notes, "gap.no-user-directory"); err != nil || !ok || !strings.Contains(n.Note, sn.IdentityPath()) {
		t.Errorf("%v: notes %+v", err, e.Notes)
	}
}
