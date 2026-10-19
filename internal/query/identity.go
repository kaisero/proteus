package query

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/kaisero/proteus/internal/appid"
	"github.com/kaisero/proteus/internal/estate"
	"github.com/kaisero/proteus/internal/identity"
	"github.com/kaisero/proteus/internal/index"
	"github.com/kaisero/proteus/internal/reason"
	"github.com/kaisero/proteus/internal/resolve"
	"github.com/kaisero/proteus/internal/simulate"
)

// identityMemo loads each identity file once per question, through the env's
// source: the vsys of one snapshot or of one file share its file (spec
// 2026-10-17 §4.2). A failed load is kept too, so the targets give one cause.
type identityMemo struct {
	src estate.IdentitySource
	mu  sync.Mutex
	got map[string]identityLoad
}

type identityLoad struct {
	data *identity.Data
	err  error
}

// Identity implements estate.IdentitySource.
func (m *identityMemo) Identity(path string) (*identity.Data, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if l, ok := m.got[path]; ok {
		return l.data, l.err
	}
	d, err := m.src.Identity(path)
	m.got[path] = identityLoad{d, err}
	return d, err
}

// identitySource is a new memo for one question over the env's source of
// identity files, or over the disk when it has none (PD10).
func (e Env) identitySource() estate.IdentitySource {
	src := e.Identity
	if src == nil {
		src = estate.DiskIdentity{}
	}
	return &identityMemo{src: src, got: map[string]identityLoad{}}
}

// identityThrough has each target load its identity file through src.
func identityThrough(ts []estate.Target, src estate.IdentitySource) {
	for i := range ts {
		if path := ts[i].IdentityPath; path != "" {
			ts[i].Identity = func() (*identity.Data, error) { return src.Identity(path) }
		}
	}
}

// identityFor is a target's identity data and the notes that qualify it (spec
// 2026-10-17 §4.2, §7, PD11):
//
//   - a snapshot without an identity file, and a --file configuration without
//     one beside it, have none and no note: the answer is as before the data;
//   - a file that does not load gives none, and gap.no-user-directory names
//     the cause: the answer is as without data;
//   - the data of a --file question comes with note.identity-file, which names
//     the file, because nothing checks that the file belongs to the
//     configuration; and with gap.user-directory-stale when the file is older
//     than maxAge.
func identityFor(t estate.Target, maxAge time.Duration, now time.Time) (*identity.Data, simulate.Reasons) {
	if t.Identity == nil {
		return nil, nil
	}
	d, err := t.Identity()
	switch {
	case err != nil && t.Snapshot == nil && errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, simulate.Reasons{reason.New("gap.no-user-directory", "no identity data: "+err.Error())}
	case t.Snapshot != nil:
		return d, nil
	}
	notes := simulate.Reasons{reason.New("note.identity-file",
		fmt.Sprintf("identity data taken %s from %s", d.TakenAt().UTC().Format(time.RFC3339), t.IdentityPath))}
	if age := now.Sub(d.TakenAt()); maxAge > 0 && age > maxAge {
		notes = append(notes, reason.New("gap.user-directory-stale", fmt.Sprintf(
			"the identity file %s is %s old, past the %s limit", t.IdentityPath, age.Round(time.Minute), maxAge)))
	}
	return d, notes
}

// namesUser reports whether a rule names a source-user other than any. Only
// then can the identity data change the answer to a flow without --user: a
// mapped source address is no reason to load the data, as no answer knows the
// mapping before the load (spec 2026-10-17 §4.2, SG9).
//
// Three walks read the source-user members of the rules, each with its own
// filter, because each asks another question. namesUser keeps known-user,
// unknown and pre-logon: with no user they make the answer inferred, so the
// data must load (§5.4). searchNeedsIdentity keeps every member but any, as
// a term of that text can name a user or a group of the data. The user value
// space (index.newUserResolver) drops the four keywords and the local users
// and groups: the security check judges the keywords, and the local user
// database judges the local names, so only the other members are matched
// against the data (§5.3).
func namesUser(rules []resolve.Rule) bool {
	for _, r := range rules {
		for _, m := range r.Fields[index.SourceUser.String()] {
			if m != "any" {
				return true
			}
		}
	}
	return false
}

// searchNeedsIdentity reports whether search loads the identity data before
// the first search of a target (spec 2026-10-17 §4.2, PD10): for one address,
// whose mapped user the data holds; for a term with \, @ or =, as a user
// name, a UPN and a group DN hold; and for a source-user member of a rule
// other than any, in any case. Any other term loads the data only when the
// first search finds nothing, as lookup loads the App-ID data (needsApps).
func searchNeedsIdentity(term string, rules []resolve.Rule) bool {
	if ps := index.PrefixesOf(term); len(ps) == 1 && ps[0].IsSingleIP() {
		return true
	}
	if strings.ContainsAny(term, `\@=`) {
		return true
	}
	for _, r := range rules {
		for _, m := range r.Fields[index.SourceUser.String()] {
			if m != "any" && strings.EqualFold(m, term) {
				return true
			}
		}
	}
	return false
}

// userTerm is a search term as the user value space reads it: the primary
// name of the user that the term names, when the identity data resolves it
// and the term names no application (spec 2026-10-17 §5.2, §6.1, PD8). It
// resolves as --user does, through Resolve (PD18).
func userTerm(t estate.Target, d *identity.Data, apps *appid.Data, term string) string {
	if d == nil {
		return term
	}
	if _, app := canonicalApp(t, apps, term); app {
		return term
	}
	if p, ok := d.Resolve(term); ok {
		return p
	}
	return term
}
