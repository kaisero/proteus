# reporting

Validated against 86fd84f on 2026-09-27 · Purpose: how an answer carries its reasoning, and how incompleteness is made impossible to miss.

## Purpose & responsibilities

Every lookup returns rules **and** a `Report`. The report exists because the
failures that hurt in this domain are not crashes. They are plausible wrong
answers: a rule list that looks complete and is missing the only rule that matters.

## How it works

```go
type Report struct {
	Value      string
	Hits       []Hit          // what matched, and via which value
	Groups     []string       // groups reached through those hits
	ViaAny     bool           // some rules joined only because the field is "any"
	Unresolved []Unresolved   // what could not be evaluated, and why
}

type Hit struct{ Name, Kind string; Scope config.Scope; Via string }
type Unresolved struct{ Value, Kind, Reason string }
```

`Hit.Via` is the value that matched, not the object that held it. A wildcard hit
reports `*.wildcard-example.com` rather than only naming the category, so a reader
can check the reasoning instead of trusting it.

### Recognised is not matched

A resolver returns a third result: whether it recognised the **form** of the value.

- recognised and matched → hits, no unresolved
- recognised and unmatched → no hits, no unresolved. **A complete answer.** A URL
  in no category really does reach only the any-rules.
- not recognised by any value space, and not a known name → one `Unresolved`
  explaining that only the any-rules are reported

Getting this wrong in either direction is harmful. Reporting the second case as
incomplete trains a caller to ignore the warning; reporting the third as complete is
the original defect.

### What is always reported

These cannot be answered by reading a file, so they are attached to every relevant
answer rather than discovered later:

| Reported | Why |
|---|---|
| `Category Match` URL category | members are predefined PAN-DB categories, held in the cloud |
| URL or IP external list | contents are fetched at runtime |
| dynamic address group members | registered at runtime by User-ID or VM monitoring |
| dynamic user group | filled in at runtime by User-ID |
| application filter, application container | selects by content-database metadata |
| unreadable tag filter, unreadable URL member | the parser refuses rather than guesses |
| zone with no interface, interface in no zone | nothing can be placed there |
| virtual router running BGP or OSPF | routes learned at runtime are not in the file |
| address no route covers | the arriving zone is unknown |
| no user directory supplied | only the local database was searched |
| stale user snapshot | membership may have changed since it was taken |

### Deduplication

Two value spaces can find the same thing. A user in a local group that a directory
also reports is one membership, and a report listing it twice invites the opposite
reading. `Candidates` deduplicates hits, groups and unresolved entries before
returning.

## Build / run pointers

- `go test ./internal/index/ -run 'Unresolved|Report'`
- `./bin/proteus search <term> --file <cfg>` — prints unresolved entries and exits 3,
  because the result on its own looks complete.

## Public API

<!-- GENERATED:api ./internal/index -->
```go
type Field int
type Hit struct{ ... }
type Index struct{ ... }
type Interner struct{ ... }
type Match struct{ ... }
type ProfileUse struct{ ... }
type Providers struct{ ... }
type Ref struct{ ... }
type Report struct{ ... }
type StaleReporter interface{ ... }
type UnparsedFilter struct{ ... }
type Unresolved struct{ ... }
type UserDirectory interface{ ... }
type UserSnapshot struct{ ... }
type View struct{ ... }
type ZoneLocator interface{ ... }
type ZonePlacement struct{ ... }
type ZoneSnapshot struct{ ... }

func (f Field) String() string
func (i *Index) Candidates(f Field, value string) (*roaring.Bitmap, Report)
func (i *Index) CandidatesFor(f Field, addr netip.Addr) *roaring.Bitmap
func (i *Index) CandidatesForName(f Field, name string) *roaring.Bitmap
func (i *Index) CandidatesForPrefix(f Field, p netip.Prefix) *roaring.Bitmap
func (i *Index) Containing(addr netip.Addr) []Match
func (i *Index) DirectGroupsOf(name string) []string
func (i *Index) Disabled() *roaring.Bitmap
func (i *Index) GroupsOf(name string) []string
func (i *Index) Interner() *Interner
func (i *Index) MembersOf(group string) []string
func (i *Index) Overlapping(p netip.Prefix) []Match
func (i *Index) ProfileUses(value string) []ProfileUse
func (i *Index) Refs(name string) []Ref
func (i *Index) Rules() []resolve.Rule
func (i *Index) RulesWith(f Field, ids ...uint32) *roaring.Bitmap
func (i *Index) RulesWithAddr(f Field, addr netip.Addr) *roaring.Bitmap
func (i *Index) RulesWithAny(f Field) *roaring.Bitmap
func (i *Index) RulesWithPrefix(f Field, p netip.Prefix) *roaring.Bitmap
func (i *Index) Scope() config.Scope
func (i *Index) SearchValues(substr string) []Hit
func (i *Index) UnparsedFilters() []UnparsedFilter
func (i *Index) VersionGap() string
func (i *Index) With(p Providers) *View
func (in *Interner) ID(name string) uint32
func (in *Interner) Len() int
func (in *Interner) Lookup(name string) (uint32, bool)
func (in *Interner) Name(id uint32) string
func (s *UserSnapshot) GroupsOf(user string) []string
func (s *UserSnapshot) Stale() (string, bool)
func (s *ZoneSnapshot) Describe() string
func (s *ZoneSnapshot) Routers() []string
func (s *ZoneSnapshot) UnroutedInterfaces() []string
func (s *ZoneSnapshot) ZonesOf(addr netip.Addr) []ZonePlacement
func (u Unresolved) String() string
func (v *View) Candidates(f Field, value string) (*roaring.Bitmap, Report)
func (v *View) Opaque(f Field) (*roaring.Bitmap, map[uint32]string)
func For(cfg *config.Config, sc config.Scope) (*Index, error)
func ForRulebase(cfg *config.Config, sc config.Scope, rb resolve.Rulebase) (*Index, error)
func LoadUserSnapshot(r io.Reader) (*UserSnapshot, error)
func LoadZoneSnapshot(r io.Reader) (*ZoneSnapshot, error)
func NewInterner() *Interner
func NewZoneSnapshot(takenAt time.Time, source string, interfaces, fib io.Reader) (*ZoneSnapshot, error)
func PrefixesOf(value string) []netip.Prefix
```
<!-- /GENERATED:api -->

## Reason codes (`internal/reason`)

A reason is a code plus a text: `reason.Reason{Code, Text}`, JSON `{code, text}`.
The code is `<class>.<name>` in lower case and comes from a closed registry
(`internal/reason/registry.go`). The classes: doubt, gap, path, zone, default,
dns, input, note, call, verdict. A program acts on the code; a reader reads the
text. Each not-evaluated dimension has its own code (`doubt.not-evaluated.user`);
there is no wildcard.

`reason.New` builds a reason. In a test binary (`testing.Testing()`) it panics on
a code the registry does not hold, so any package's tests fail when a producer
uses one. A production binary keeps the code. Add a code to the registry, with a
one-line description, before a producer uses it.

`reason` imports only the standard library, so every package may import it; the
archtest allows it in every R12 rule.

<!-- GENERATED:api ./internal/reason -->
```go
type Class string
type Code string
type Entry struct{ ... }
type Reason struct{ ... }

func Known(c Code) bool
func New(c Code, text string) Reason
func Registry() []Entry
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **A non-empty `Unresolved` means the caller must say so to its own user.**
  Passing the rule list on without it is the defect this type exists to prevent.
- **`ViaAny` is not a warning.** An `any` field genuinely matches every value. It
  is context, so a reader knows which rules are specific.
- **Build-time limits ride along on query answers.** A `Category Match` category
  found while building is reported on every URL query, because it could have matched.

## See also

- `internal/index/unresolved.go`, `internal/index/candidates.go`, `internal/index/resolver.go`
- [value-spaces](value-spaces.md) — the recognised flag
- [providers](providers.md) — staleness and the missing-directory report
