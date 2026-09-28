# providers

Validated against 86fd84f on 2026-09-27 · Purpose: how facts a configuration does not hold reach a lookup, without the library fetching anything.

## Purpose & responsibilities

Some questions cannot be answered from a file. Which groups a user belongs to comes
from User-ID, which learns it from a directory. The library defines the shape of
that data and reads it. **The caller fetches it.** The core performs no network
access at all; `store.Snapshot.Zones()` builds a zone snapshot from a fetched one.

## How it works

```go
type Providers struct {
	Users UserDirectory
	Zones ZoneLocator
}

type UserDirectory interface{ GroupsOf(user string) []string }
type ZoneLocator    interface{ ZonesOf(addr netip.Addr) []string }

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

### The user snapshot

```json
{
  "taken_at": "2026-09-27T12:00:00Z",
  "source": "User-ID on fw01",
  "groups": { "alice": ["local-admins", "engineering"] },
  "max_age": 86400000000000
}
```

`LoadUserSnapshot(r)` reads it. `taken_at` is **required**: a snapshot that cannot
be reported stale is worse than none, because a mapping read days ago can place a
user in a group they have since left. Lookups are case-insensitive, since a
directory and a firewall rule rarely agree on case.

### Staleness

```go
type StaleReporter interface{ Stale() (reason string, stale bool) }
```

A provider may implement this; `UserSnapshot` does. The user resolver type-asserts
for it and passes the reason into `Report.Unresolved`. Default tolerance is one
day.

Without any directory the answer still works and says what it missed: only the
local user database was searched, so a rule naming a directory group is absent.

### ZoneLocator

Real. `ZoneSnapshot` carries two op-command responses verbatim —
`show interface all` and `show advanced-routing fib` — and answers from the device's
own forwarding table.

```
address -> longest matching route in each router -> interface -> zone
```

`ZonesOf` returns `[]ZonePlacement{Zone, Interface, Router, Route, Vsys}`, not
`[]string`. A placement carries the reasoning, like every other answer here.

Three things separate it from `UserSnapshot`:

- **No staleness.** An upstream tool supplies a forwarding table fresh enough for the
  question. `TakenAt` is provenance, unenforced, and `ZoneSnapshot` deliberately does
  not implement `StaleReporter`.
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

## Build / run pointers

- `go test ./index/ -run 'User|Snapshot'`
- `PANOS_USERS=testdata/users-snapshot.json ./bin/panos-analyst search 'ACME\carol' --file testdata/config/firewall-users.xml`

## Public API

<!-- GENERATED:api ./index -->
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
func For(cfg *config.Config, sc config.Scope) (*Index, error)
func LoadUserSnapshot(r io.Reader) (*UserSnapshot, error)
func LoadZoneSnapshot(r io.Reader) (*ZoneSnapshot, error)
func NewInterner() *Interner
func NewZoneSnapshot(takenAt time.Time, source string, interfaces, fib io.Reader) (*ZoneSnapshot, error)
func PrefixesOf(value string) []netip.Prefix
```
<!-- /GENERATED:api -->

## Gotchas / invariants

- **Never add I/O to the library.** A provider is an interface. Fetching belongs to
  the caller, which keeps the library offline, deterministic and testable.
- **Never bake a provider into a cached index.** That is the whole reason `View`
  exists.
- **A missing provider is reported, not silently skipped.** Otherwise a user query
  returns the local-only answer and looks complete.

## See also

- `index/snapshot.go`, `index/resolver_user.go`, `index/resolver.go`
- [reporting](reporting.md) — where the staleness reason surfaces
- [value-spaces](value-spaces.md) — the user and zone spaces
