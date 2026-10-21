# providers

Validated against 4c57e88 on 2026-10-19 · Purpose: how facts a configuration does not hold reach a lookup, without the read-only core fetching anything.

## Purpose & responsibilities

Some questions cannot be answered from a file. Which groups a user belongs to comes
from User-ID, which learns it from a directory. `internal/identity` defines the
shape of that data and reads it. **The caller fetches it**: `fetch` stores it with
each snapshot, and `query` loads it. The core performs no network
access at all; `store.Snapshot.Zones()` builds a zone snapshot from a fetched one.

## How it works

```go
type Providers struct {
	Users *identity.Data // the device's User-ID data, or nil
	Zones ZoneLocator
	Apps  *appid.Data    // the device's App-ID content data, or nil
}

type ZoneLocator interface{ ZonesOf(addr netip.Addr) []ZonePlacement }

func (i *Index) With(p Providers) *View
func (v *View) Candidates(f Field, value string) (*roaring.Bitmap, Report)
```

### Why a View and not the Index

An `Index` is cached per `(file, scope)` and is immutable so concurrent readers
need no lock. A User-ID mapping changes orders of magnitude faster than a
configuration file. Attaching it to the index would either poison the cache or
force a rebuild per query. So providers attach to a `View`, which is a cheap pairing
of the shared index with the facts for one question.

`Index.Candidates` is sugar for `With(Providers{}).Candidates`.

### The identity data

`Providers.Users` is the identity file of the snapshot, parsed (`*identity.Data`,
spec 2026-10-17). It is a value, not an interface: one file is immutable and
belongs to one snapshot. `UserDirectory`, `StaleReporter`, `UserSnapshot`,
`LoadUserSnapshot` and `PROTEUS_USERS` are gone (PD6, §7). `query` loads the file
(`estate.Target.Identity`, through `Env.Identity`, an `estate.IdentitySource`; the
MCP cache keeps one LRU item per snapshot) once per question per file
(`identityMemo`), only when the question needs it (PD10). The caller resolves
`--user` and a search term to a primary name first (`Resolve`, PD8, PD18).

With the data, the user value space returns the `source-user` members of the
rules that the user satisfies, and a member the data cannot judge as an
unresolved entry (`doubt.user-cie-group`, `doubt.user-data-missing`). Without it,
the answer still works and says what it missed: only the local user database was
searched, so a rule naming a directory group carries `gap.no-user-directory`, and
a dynamic user group `gap.dynamic-user-group`. A `--file` identity file older than
`max_snapshot_age` adds `gap.user-directory-stale` (in `query`, not in the index).
See [identity](identity.md).

### ZoneLocator

Real. `ZoneSnapshot` carries two op-command responses verbatim —
`show interface all` and `show advanced-routing fib` — and answers from the device's
own forwarding table.

```
address -> longest matching route in each router -> interface -> zone
```

`ZonesOf` returns `[]ZonePlacement{Zone, Interface, Router, Route, Vsys}`, not
`[]string`. A placement carries the reasoning, like every other answer here.

Three things separate it from the identity data:

- **No staleness.** An upstream tool supplies a forwarding table fresh enough for the
  question. `TakenAt` is provenance, unenforced, and no answer reports the age of a
  zone snapshot.
- **It is authoritative.** Where a snapshot places nothing, the configuration is not
  consulted instead. Falling back would hide a disagreement, and the two disagree
  routinely: a lab firewall's configuration held one static route where its device held
  25, and they named different default routes.
- **It returns a set, not an answer.** Several logical routers can cover one address,
  and which applies depends on the interface the packet arrived on — the thing being
  worked out. Measured: `198.19.11.5` is in `lte`'s `198.19.11.0/24` reaching
  `int-link-b`, and in `default`'s `0.0.0.0/0` reaching `transport`. Both are reported
  and the ambiguity is named.

A zone is visible only inside its vsys, so placements from another vsys are dropped
and counted when the scope is a vsys. The shared scope keeps everything: a snapshot
comes from one firewall, and shared belongs to none of its vsys.

The format contract is `docs/zone-snapshot-format.md` and the `ZoneSnapshot` doc
comment. `scripts/capture-zones.sh` captures one.

### App-ID content data

`Providers.Apps` is the parsed content file of the device's content version
(`appid.Data`, spec 2026-10-16). It is a value, not an interface: one file is
immutable and shared by every device and snapshot with that version. `query`
loads it (`estate.Target.Apps`, through `Env.Apps`, an `estate.AppSource`; the MCP
server's cache keeps one LRU item per content version) once per question per
file (`appMemo`), only when the question needs it (plan D11): `--application`, a
search term with the shape of a name, or a lookup that needs application kinds.
With it, the application resolver answers predefined applications, filters and
containers; without it, it reports `gap.application-filter` and
`gap.application-container`, and the answer carries `note.app-data-missing`. PBF
builds its view with empty providers, so it never sees the data (D5). See
[app-id](app-id.md).

## Build / run pointers

- `go test ./internal/index/ -run 'User|Snapshot'`
- `./bin/proteus search 'example.com\carol' --file <dir>/config.xml`, with
  `testdata/config/firewall-identity.xml` as the configuration and
  `testdata/identity/identity.json`, gzipped, as `<dir>/identity.json.gz`

## Public API

<!-- GENERATED:api ./internal/index -->
```go
type Edges struct{ ... }
type Field int
type Group struct{ ... }
type Hit struct{ ... }
type Index struct{ ... }
type Interner struct{ ... }
type Match struct{ ... }
type ProfileUse struct{ ... }
type Providers struct{ ... }
type Ref struct{ ... }
type Report struct{ ... }
type Set struct{ ... }
type UnparsedFilter struct{ ... }
type Unresolved struct{ ... }
type View struct{ ... }
type ZoneLocator interface{ ... }
type ZonePlacement struct{ ... }
type ZoneSnapshot struct{ ... }

func (f Field) String() string
func (i *Index) Candidates(f Field, value string) (*roaring.Bitmap, Report)
func (i *Index) Containing(addr netip.Addr) []Match
func (i *Index) Disabled() *roaring.Bitmap
func (i *Index) GroupPath(kind, group, name string) []string
func (i *Index) GroupsHolding(kind, name string, direct bool) []Group
func (i *Index) Interner() *Interner
func (i *Index) MatchWildcards(prefixes []netip.Prefix, single bool) ([]Hit, []Unresolved)
func (i *Index) Overlapping(p netip.Prefix) []Match
func (i *Index) ProfileUses(value string) []ProfileUse
func (i *Index) Refs(name string) []Ref
func (i *Index) Rules() []resolve.Rule
func (i *Index) RulesReaching(f Field, name string) *roaring.Bitmap
func (i *Index) RulesWith(f Field, ids ...uint32) *roaring.Bitmap
func (i *Index) RulesWithAddr(f Field, addr netip.Addr) *roaring.Bitmap
func (i *Index) RulesWithAny(f Field) *roaring.Bitmap
func (i *Index) RulesWithPrefix(f Field, p netip.Prefix) *roaring.Bitmap
func (i *Index) Scope() config.Scope
func (i *Index) SearchValues(substr string) []Hit
func (i *Index) UnparsedFilters() []UnparsedFilter
func (i *Index) With(p Providers) *View
func (in *Interner) ID(name string) uint32
func (in *Interner) Len() int
func (in *Interner) Lookup(name string) (uint32, bool)
func (in *Interner) Name(id uint32) string
func (s *Set) Config() *config.Config
func (s *Set) Index(sc config.Scope, rb resolve.Rulebase) (*Index, error)
func (s *Set) Provider(sc config.Scope) func(resolve.Rulebase) (*Index, error)
func (s *ZoneSnapshot) Describe() string
func (s *ZoneSnapshot) Routers() []string
func (s *ZoneSnapshot) UnroutedInterfaces() []string
func (s *ZoneSnapshot) ZonesOf(addr netip.Addr) []ZonePlacement
func (u Unresolved) String() string
func (u Unresolved) Why() reason.Reason
func (v *View) Candidates(f Field, value string) (*roaring.Bitmap, Report)
func (v *View) Opaque(f Field) (*roaring.Bitmap, map[uint32][]reason.Reason)
func Build(cfg *config.Config, edges *Edges, sc config.Scope, rb resolve.Rulebase) (*Index, error)
func LoadZoneSnapshot(r io.Reader) (*ZoneSnapshot, error)
func New(cfg *config.Config, sc config.Scope, rb resolve.Rulebase) (*Index, error)
func NewInterner() *Interner
func NewSet(cfg *config.Config) *Set
func NewUnresolved(value, kind string, r reason.Reason) Unresolved
func NewZoneSnapshot(takenAt time.Time, source string, interfaces, fib io.Reader) (*ZoneSnapshot, error)
func PrefixesOf(value string) []netip.Prefix
func ReadEdges(cfg *config.Config) (*Edges, error)
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **Never add I/O to the read-only core.** A provider is an interface. Fetching belongs to
  the caller, which keeps the core offline, deterministic and testable.
- **Never bake a provider into a cached index.** That is the whole reason `View`
  exists.
- **A missing provider is reported, not silently skipped.** Otherwise a user query
  returns the local-only answer and looks complete.

## See also

- `internal/index/zonesnapshot.go`, `internal/index/resolver_user.go`, `internal/index/resolver.go`
- [identity](identity.md) — the identity file and its queries
- [reporting](reporting.md) — where the gap reasons surface
- [value-spaces](value-spaces.md) — the user and zone spaces
