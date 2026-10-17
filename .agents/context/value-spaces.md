# value-spaces

Validated against 86fd84f on 2026-09-27 · Purpose: how a query value becomes a set of rules, and how a new kind of value is added.

## Purpose & responsibilities

A rule field is matched by the object kinds the schema says it accepts. A security
rule's `source` accepts `address`, `address-group`, `region`, `external-list` and
`ip-block-list-v2` — five value spaces, not one. A **resolver** owns one value
space and answers the only question that depends on it: which object names does
this value match.

Everything after that step is identical for every value space. Matched names
expand through the group closure, become interned ids, and index into the
rule-field bitmaps. So the resolver interface is deliberately narrow.

## How it works

### The interface

Resolvers are internal and the set is closed. A new value space is implemented
here rather than registered from outside, so every resolver can be held to the
same obligation: when it recognises a value but cannot evaluate it, it says so.

```go
type resolver interface {
	kinds() []string
	resolve(value string, p Providers) ([]Hit, []Unresolved, bool)
	literalRules(f Field, value string) *roaring.Bitmap
	search(substr string) []Hit
}
```

The third result of `resolve` is **recognised**, which is not the same as matched.
A URL that belongs to no category is recognised and matches nothing, and that is a
complete answer. A value nothing recognises is an incomplete one. See
[reporting](reporting.md).

### Wiring comes from the schema

`wireResolvers` in `internal/index/resolver.go` maps each `Field` to the resolvers covering
the kinds `config.FieldKinds("rulebase/security/rules")` reports. Nothing here
lists fields by hand.

This cannot be derived from the configuration instead. `any` is a keyword and
yields no walk event, so a rulebase whose every rule says `source any` would look
as though `source` names nothing.

### The four paths

`View.Candidates` in `internal/index/candidates.go` is the driver. A rule field reaches a
value by four paths, and forgetting one gives a wrong answer rather than an
incomplete one:

1. the field names an object whose value matches — the resolvers
2. the field names a group holding such an object, at any depth, static membership
   or tag filter alike — the closure. Each group kind (address, service,
   application group) has its own closure, and a field asks only the group kinds
   the schema lets it name: an address group and a service group may share a name.
   The closure is built in one pass: groups that hold each other (a cycle) are
   joined into one component first, and the components are built in the order
   they hold each other (`settle`, `components` in `closure.go`)
3. the field holds a matching value directly — `literalRules`
4. the field is `any` — `RulesWithAny`

The fourth is the one that bites. Checked against a firewall: for 198.18.0.5 to
198.18.1.5 the device reports rule 3, whose source is `any`, while matching on
objects alone reports rule 8. An any-rule usually sits earlier in a rulebase than
a specific one.

## The implemented value spaces

| File | Kinds | Matches by |
|---|---|---|
| `resolver_address.go` | address, address-group | `bart` prefix trie for prefixes and ranges; a map for FQDN values |
| `resolver_url.go` | custom-url-category | exact member map plus parsed wildcard patterns |
| `resolver_service.go` | service, service-group | protocol plus port-range interval containment |
| `resolver_user.go` | user, user-group, dynamic-user-group | local database, then the caller's directory |
| `resolver_zone.go` | zone | interface addresses and static routes as a routing table, longest prefix wins |
| `resolver_app.go` | application, application-group, application-filter, application-container | custom applications only; the rest is content-database data |

`tag` has no resolver and needs none: a tag is a name, and the generic name path
already answers it.

### Notes that are easy to get wrong

- **The prefix trie is not the index's.** It belongs to the address resolver. Its
  position was the original design fault: while it sat on `Index`, every
  reachability question was address-shaped.
- **URL matching is by token, never by substring.** The host matches in full and
  the path as a prefix, so `wildcard-example.com` does not cover
  `wildcard-example.com.evil.net`. Syntax rules in `internal/resolve/urlpattern.go` are
  verified against a firewall's validator; the matching rules are
  documentation-derived and labelled as such.
- **A service group spells its membership `members`**, an address group `static`,
  a local user group `user`. All three are read in `resolve.objectValue`.
- **Zone placement has two sources.** With a `ZoneSnapshot` in `Providers` it reads
  the device's own forwarding table and is authoritative. Without one it infers from
  the configuration, reports that it did, and reports every limit: a zone with no
  interface, an interface in no zone, a virtual router learning routes at runtime, and
  an address no route covers. See [providers](providers.md).

## Adding a value space

1. Write `internal/index/resolver_<name>.go` implementing the four methods.
2. Read whatever it needs in `resolve`, not in `index`.
3. Register it in `build()` in `internal/index/index.go`; the kinds it declares do the wiring.
4. If a kind name is ambiguous in the schema, use `resolve.ObjectsAt` with an
   explicit container path rather than `ObjectsInScope`. See [config-loading](config-loading.md).
5. Report what it cannot evaluate. Never guess membership.

## Build / run pointers

- `go test ./internal/index/ -run 'Resolver|Candidates'` — the value-space tests.
- `./bin/proteus search <value> --file <cfg>` — every value space at once.
- `scripts/device-probe.sh` — compares the first match against a real firewall.

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
func (i *Index) Containing(addr netip.Addr) []Match
func (i *Index) Disabled() *roaring.Bitmap
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
func (s *UserSnapshot) GroupsOf(user string) []string
func (s *UserSnapshot) Stale() (string, bool)
func (s *ZoneSnapshot) Describe() string
func (s *ZoneSnapshot) Routers() []string
func (s *ZoneSnapshot) UnroutedInterfaces() []string
func (s *ZoneSnapshot) ZonesOf(addr netip.Addr) []ZonePlacement
func (u Unresolved) String() string
func (u Unresolved) Why() reason.Reason
func (v *View) Candidates(f Field, value string) (*roaring.Bitmap, Report)
func (v *View) Opaque(f Field) (*roaring.Bitmap, map[uint32][]reason.Reason)
func Build(cfg *config.Config, edges *Edges, sc config.Scope, rb resolve.Rulebase) (*Index, error)
func LoadUserSnapshot(r io.Reader) (*UserSnapshot, error)
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

- **A query never interns.** `Interner.ID` writes an unlocked map on an index that
  is cached and shared. Use `Lookup`. The race detector reported seven races on the
  version that got this wrong.
- **`literalRules` is value-space-specific.** Whether a literal in a rule field
  matches is as domain-dependent as whether an object does. Only the address
  resolver returns anything; a category, service, user or zone field names things.
- **`search` is not `resolve`.** Searching is a case-insensitive substring over
  object values and must never be used for matching.
- **A resolver may own several kinds**, and `byKind` maps each kind to it, so
  `distinctResolvers` deduplicates before a whole-index sweep such as `SearchValues`.

## See also

- `internal/index/candidates.go` — the driver and the four paths
- `internal/index/resolver.go` — the interface, `Providers`, `View`, `Report`, `SearchValues`
- [reporting](reporting.md) — what a resolver must report when it cannot answer
- [providers](providers.md) — value spaces that need data a file does not hold
- `ARCHITECTURE.md` — the reachability-versus-verdict seam
